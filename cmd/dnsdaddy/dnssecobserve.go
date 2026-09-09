package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jameshoulder/dnsdaddy/internal/api"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/trustanchors"
	"github.com/jameshoulder/dnsdaddy/internal/dnssecobs"
	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// dnssecObservation is everything observe mode owns, so main can start and
// stop it as one thing.
type dnssecObservation struct {
	observer *observe.Observer
	writer   *dnssecobs.Writer
	source   *observe.Source

	// stopWriter cancels the writer, and is deliberately not the process
	// context. See Wait.
	stopWriter context.CancelFunc
}

// startDNSSECObserver builds and starts local DNSSEC observation, or returns
// nil when the mode is off.
//
// Nil is the normal case and every caller tolerates it. In off mode nothing
// here runs: no validator is constructed, no worker starts, no trust anchor is
// parsed and no supporting query is ever sent, so an instance that did not ask
// for the feature is indistinguishable from one built before it existed.
//
// A failure to start is a startup error rather than a warning. An operator who
// configured observe mode and got a silently disabled validator would draw
// conclusions from an empty dataset, which is worse than not starting.
func startDNSSECObserver(
	ctx context.Context,
	cfg config.Config,
	res *resolver.Resolver,
	st *store.Store,
	log *slog.Logger,
) (*dnssecObservation, error) {
	if !cfg.DNS.ObserveDNSSEC() {
		return nil, nil
	}

	anchors, err := loadTrustAnchors(cfg.DNS.LocalDNSSECTrustAnchorFile)
	if err != nil {
		return nil, fmt.Errorf("local DNSSEC validation: %w", err)
	}

	// The operator's own upstreams, so switching validation on does not send
	// DNSSEC traffic somewhere they did not choose — and in particular does
	// not fall back to plaintext for an instance configured with DoT.
	ups := res.Upstreams()
	exchangers := make([]observe.Exchanger, 0, len(ups))
	for _, u := range ups {
		exchangers = append(exchangers, u)
	}
	if len(exchangers) == 0 {
		return nil, fmt.Errorf("local DNSSEC validation: no upstreams to validate against")
	}

	source := observe.NewSource(exchangers, observe.SourceOptions{})
	validator := dnssec.New(source, dnssec.Config{
		Anchors:  anchors,
		Policy:   dnssec.DefaultPolicy(),
		Clock:    dnssec.SystemClock{},
		Verifier: dnssec.StdVerifier(),
		Limits:   dnssec.DefaultLimits(),
	})

	writer := dnssecobs.New(st, dnssecobs.Options{Log: log})
	// The writer outlives the observer on purpose. Given the same context
	// both stop on the same cancellation, and the writer can drain its queue
	// and return while a worker is still unwinding a validation in flight —
	// the row that worker then records is queued with no consumer left, so it
	// is neither stored nor counted as dropped. Silently losing evidence is
	// the one failure this package exists to make impossible, so the writer
	// gets its own cancellation and Wait triggers it only once every producer
	// has gone.
	wctx, stopWriter := context.WithCancel(context.WithoutCancel(ctx))
	go writer.Run(wctx)

	observer := observe.New(validator, writer, observe.Options{
		Workers: cfg.DNS.LocalDNSSECWorkers,
		Queue:   cfg.DNS.LocalDNSSECQueue,
		Timeout: cfg.DNS.LocalDNSSECTimeout.D(),
		Log:     log,
	})
	go observer.Run(ctx)

	// The process context still has to reach the writer, or a shutdown that
	// never called Wait would leave it running. Same ordering as Wait, for
	// the same reason. Wait is deferred in main and is the ordinary path;
	// this is the backstop, and cancelling twice is harmless.
	go func() {
		<-ctx.Done()
		observer.Wait()
		stopWriter()
	}()

	log.Info("local DNSSEC validation is observing",
		"mode", cfg.DNS.LocalDNSSECMode(),
		"workers", cfg.DNS.LocalDNSSECWorkers,
		"queue", cfg.DNS.LocalDNSSECQueue,
		"timeout", cfg.DNS.LocalDNSSECTimeout.D(),
		"enforcing", false)

	return &dnssecObservation{
		observer:   observer,
		writer:     writer,
		source:     source,
		stopWriter: stopWriter,
	}, nil
}

func loadTrustAnchors(path string) (dnssec.TrustAnchors, error) {
	if path == "" {
		return trustanchors.Root()
	}
	return trustanchors.FromFile(path)
}

// Wait blocks until both goroutines have drained.
//
// The order is the point. Waiting for the observer first means every worker
// that could still record an observation has exited before the writer is told
// to drain, so the last verdicts of a run reach the database instead of being
// queued into a channel nothing is reading any more.
func (d *dnssecObservation) Wait() {
	if d == nil {
		return
	}
	d.observer.Wait()
	d.stopWriter()
	d.writer.Wait()
}

// observerOrNil converts a possibly-nil observation into the handler's
// interface without handing it a non-nil interface wrapping a nil pointer,
// which would defeat every `if h.dnssec == nil` in the handler.
func observerOrNil(d *dnssecObservation) dnsserver.DNSSECObserver {
	if d == nil || d.observer == nil {
		return nil
	}
	return d.observer
}

// dnssecStatsOrNil exposes the observer's counters to the API without handing
// it a non-nil interface wrapping a nil pointer.
func dnssecStatsOrNil(d *dnssecObservation) api.DNSSECObserverStats {
	if d == nil || d.observer == nil {
		return nil
	}
	return d.observer
}

// dnssecWriterOrNil exposes the writer's counters to the API, so an
// observation that completed and was then lost before storage is visible
// rather than only implied by a smaller dataset.
func dnssecWriterOrNil(d *dnssecObservation) api.DNSSECWriterStats {
	if d == nil || d.writer == nil {
		return nil
	}
	return d.writer
}
