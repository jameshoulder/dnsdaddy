package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/dnssecobs"
	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// TestOffModeConstructsNothing is Phase 3 of the observe-mode brief.
//
// "off" must be indistinguishable from a build without the feature. Not
// "cheap" — absent: no validator, no worker, no trust anchor parsed, no
// upstream touched. The check is that nothing is constructed at all, because a
// validator that exists but is not called still holds memory, still needs its
// anchors to parse at startup, and still gives a future edit somewhere to
// accidentally start using it.
func TestOffModeConstructsNothing(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, mode := range []string{config.LocalDNSSECOff, ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			cfg := config.Default()
			cfg.DNS.LocalDNSSECValidation = mode
			// A trust anchor file that does not exist. In off mode nothing
			// may read it, so this passing is itself evidence that no anchor
			// loading happened.
			cfg.DNS.LocalDNSSECTrustAnchorFile = "/nonexistent/anchors"

			got, err := startDNSSECObserver(context.Background(), cfg, nil, nil, log)
			if err != nil {
				t.Fatalf("off mode returned an error: %v", err)
			}
			if got != nil {
				t.Fatal("off mode constructed an observer")
			}
		})
	}
}

// TestOffModeHandsTheHandlerATrueNil is a Go trap worth a test of its own.
//
// A nil *dnssecObservation assigned straight into the interface field would
// make the handler's `if h.dnssec == nil` false, and every query would call
// through a nil pointer. The bug would appear only in off mode, which is the
// default, and only at runtime.
func TestOffModeHandsTheHandlerATrueNil(t *testing.T) {
	var d *dnssecObservation
	if got := observerOrNil(d); got != nil {
		t.Fatal("a nil observation became a non-nil interface; the handler's nil check would not fire")
	}

	var iface dnsserver.DNSSECObserver = observerOrNil(nil)
	if iface != nil {
		t.Fatal("observerOrNil(nil) is not nil")
	}
}

// TestObserveModeRefusesToStartWithoutUsableAnchors.
//
// An operator who configured observe mode and got a silently disabled
// validator would draw conclusions from an empty dataset. Failing startup is
// the honest outcome, and it is the same reasoning as refusing "enforce".
func TestObserveModeRefusesToStartWithoutUsableAnchors(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Default()
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECObserve
	cfg.DNS.LocalDNSSECTrustAnchorFile = "/nonexistent/anchors"

	if _, err := startDNSSECObserver(context.Background(), cfg, nil, nil, log); err == nil {
		t.Fatal("observe mode started with an unreadable trust anchor file")
	}
}

// blockingValidator stalls until its context is cancelled, then takes a
// moment to unwind. It exists to open the window that
// TestTheLastVerdictsOfARunAreStored closes.
type blockingValidator struct {
	entered chan struct{}
	once    sync.Once
}

func (b *blockingValidator) Validate(ctx context.Context, qname string, rrtype uint16) dnssec.ValidationResult {
	b.once.Do(func() { close(b.entered) })
	<-ctx.Done()
	// The unwind a real validator would do: abandoning a chain walk, closing
	// out a trace. Long enough that a writer racing us on the same
	// cancellation has certainly finished draining and returned.
	time.Sleep(50 * time.Millisecond)
	return dnssec.ValidationResult{Status: dnssec.StatusIndeterminate, Reason: dnssec.ReasonCancelled}
}

// TestTheLastVerdictsOfARunAreStored.
//
// The observer and the writer used to stop on the same cancellation. The
// writer would drain an empty queue and return while a worker was still
// unwinding a validation in flight; the row that worker then recorded was
// queued with nothing left to read it, so it was neither written nor counted
// as dropped. Observations vanishing without a trace is the one failure this
// package exists to prevent — it has already happened once, for a different
// reason — so the shutdown order is now part of the design and this pins it.
func TestTheLastVerdictsOfARunAreStored(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	writer := dnssecobs.New(st, dnssecobs.Options{Log: log, FlushInterval: time.Hour})
	wctx, stopWriter := context.WithCancel(context.Background())
	go writer.Run(wctx)

	v := &blockingValidator{entered: make(chan struct{})}
	observer := observe.New(v, writer, observe.Options{
		Workers: 1, Queue: 4, Timeout: time.Minute, Log: log,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go observer.Run(ctx)

	d := &dnssecObservation{observer: observer, writer: writer, stopWriter: stopWriter}

	if !observer.Observe(observe.Request{
		ID: "obs-1", Domain: "example.test", QName: "example.test.",
		QType: dns.TypeA, Store: true,
	}) {
		t.Fatal("the observation was dropped before it could start")
	}

	// Cancel only once the worker is inside the validator, so shutdown really
	// does overlap an observation in flight.
	<-v.entered
	cancel()
	d.Wait()

	rows, err := st.ListDNSSECObservations(context.Background(), store.DNSSECObservationFilter{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d stored observations, want 1: a verdict reached during shutdown was lost", len(rows))
	}
	if s := writer.Stats(); s.Dropped != 0 {
		t.Fatalf("the writer dropped %d rows; a lost row must at least be counted", s.Dropped)
	}
}
