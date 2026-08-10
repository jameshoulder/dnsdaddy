package dnsserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

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

	for range servers {
		if err := <-ready; err != nil {
			s.Shutdown(context.Background())
			return err
		}
	}

	for _, srv := range servers {
		s.log.Info("dns listener started", "net", srv.Net, "addr", srv.Addr)
	}

	go func() {
		<-ctx.Done()
		s.Shutdown(context.Background())
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
