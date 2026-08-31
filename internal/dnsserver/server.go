package dnsserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

// shutdownTimeout bounds how long the listeners are given to drain in-flight
// queries. ShutdownContext closes the listener first and only then waits, so
// this caps the wait rather than the close: a query still in a handler when
// the deadline passes is abandoned, and the process is not held open by one
// slow upstream. DNS queries are answered in milliseconds, so five seconds is
// generous.
const shutdownTimeout = 5 * time.Second

// shutdownContext derives the context the listeners are torn down with.
//
// The parent is usually already cancelled — its cancellation is what triggers
// the shutdown — so inheriting it directly would mean every Shutdown ran
// against a dead context and skipped the drain entirely. WithoutCancel keeps
// the parent's values while dropping that cancellation, and the timeout puts a
// finite bound back on in place of the unbounded context.Background this
// replaced. The caller must call cancel.
func shutdownContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), shutdownTimeout)
}

// Server owns the UDP, TCP, and DNS-over-TLS listeners.
type Server struct {
	handler *Handler
	log     *slog.Logger
	servers []*dns.Server
	mu      sync.Mutex
}

// NewServer builds the listeners described by cfg. Listeners are created but
// not started; call Start.
func NewServer(cfg config.DNS, h *Handler, log *slog.Logger) (*Server, error) {
	s := &Server{handler: h, log: log}

	mux := dns.NewServeMux()
	mux.Handle(".", h)

	if cfg.ListenUDP != "" {
		s.servers = append(s.servers, &dns.Server{
			Addr:    cfg.ListenUDP,
			Net:     "udp",
			Handler: mux,
			// Accept larger EDNS payloads so DNSSEC-signed answers do not get
			// needlessly truncated into a TCP retry.
			UDPSize: 1232,
		})
	}
	if cfg.ListenTCP != "" {
		s.servers = append(s.servers, &dns.Server{
			Addr:    cfg.ListenTCP,
			Net:     "tcp",
			Handler: mux,
		})
	}
	if cfg.ListenDoT != "" {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, fmt.Errorf("dns-over-tls requires tls_cert_file and tls_key_file")
		}
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load DoT certificate: %w", err)
		}
		s.servers = append(s.servers, &dns.Server{
			Addr:    cfg.ListenDoT,
			Net:     "tcp-tls",
			Handler: mux,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		})
	}

	if len(s.servers) == 0 {
		return nil, fmt.Errorf("no DNS listeners configured")
	}
	return s, nil
}

// Start begins serving. It returns once every listener is bound, and reports
// the first bind error. Serving continues in the background until Shutdown.
func (s *Server) Start(ctx context.Context) error {
	ready := make(chan error, len(s.servers))
	errs := make(chan error, len(s.servers))

	s.mu.Lock()
	servers := append([]*dns.Server(nil), s.servers...)
	s.mu.Unlock()

	for _, srv := range servers {
		srv := srv
		var once sync.Once
		srv.NotifyStartedFunc = func() {
			once.Do(func() { ready <- nil })
		}
		go func() {
			err := srv.ListenAndServe()
			if err != nil {
				// Surface a bind failure as readiness so Start does not hang.
				once.Do(func() { ready <- fmt.Errorf("%s %s: %w", srv.Net, srv.Addr, err) })
				errs <- err
				return
			}
			errs <- nil
		}()
	}

	// Wait for every listener to report, even once one has already failed.
	// Returning on the first error would unwind while a sibling goroutine is
	// still on its way to bind: ShutdownContext refuses a server whose started
	// flag is not yet set, so that listener would come up *after* the unwind,
	// on a port the caller has just been told could not be opened, and with
	// s.servers already cleared there would be nothing left holding a
	// reference to stop it. Draining every readiness signal first means each
	// server has either bound or failed by the time Shutdown runs.
	var firstErr error
	for range servers {
		if err := <-ready; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		// The same bounded context is used, so a failed start cannot hang
		// either.
		shutdownCtx, cancel := shutdownContext(ctx)
		s.Shutdown(shutdownCtx)
		cancel()
		return firstErr
	}

	for _, srv := range servers {
		s.log.Info("dns listener started", "net", srv.Net, "addr", srv.Addr)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := shutdownContext(ctx)
		defer cancel()
		s.Shutdown(shutdownCtx)
	}()

	return nil
}

// Shutdown stops all listeners.
func (s *Server) Shutdown(ctx context.Context) {
	s.mu.Lock()
	servers := append([]*dns.Server(nil), s.servers...)
	s.servers = nil
	s.mu.Unlock()

	for _, srv := range servers {
		if err := srv.ShutdownContext(ctx); err != nil {
			s.log.Debug("dns listener shutdown", "addr", srv.Addr, "error", err)
		}
	}
}
