package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
)

// captureDetector records the events the engine enriched, so the handler's
// side of the contract can be asserted end to end.
type captureDetector struct{ events []detect.Event }

func (d *captureDetector) Name() string                        { return "capture" }
func (d *captureDetector) Info() detect.DetectorInfo           { return detect.DetectorInfo{Name: "capture"} }
func (d *captureDetector) Observe(e *detect.Event)             { d.events = append(d.events, *e) }
func (d *captureDetector) Evaluate(time.Time) []detect.Finding { return nil }
func (d *captureDetector) Sweep(time.Time)                     {}
func (d *captureDetector) Tracked() int                        { return 0 }

// newDetectingHarness wires a real detection engine into the handler and
// returns both, along with a function that drains the engine's queue.
func newDetectingHarness(t *testing.T, lists map[string]string) (*testHarness, *captureDetector, func()) {
	t.Helper()

	cap := &captureDetector{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := detect.New([]detect.Detector{cap}, nil, detect.NewExclusions(nil, false),
		detect.Options{BufferSize: 256, EvalInterval: time.Hour}, log)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		engine.Run(ctx)
		close(done)
	}()

	h := newHarnessWithQueryLog(t, lists, true, func(o *HandlerOptions) {
		o.Detector = engine
	})

	// drain stops the engine and waits for it to finish, which flushes every
	// queued observation through the detectors. Doing it this way rather than
	// sleeping keeps the test deterministic.
	drain := func() {
		cancel()
		<-done
	}
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			cancel()
			<-done
		}
	})

	return h, cap, drain
}

func TestHandlerObservesResolvedQueries(t *testing.T) {
	h, cap, drain := newDetectingHarness(t, nil)

	h.handler.Handle(context.Background(), query("www.example.com.", dns.TypeA),
		requestMeta{proto: "udp", clientAddr: mustAddr("192.168.1.42")})
	drain()

	if len(cap.events) != 1 {
		t.Fatalf("observed %d events, want 1", len(cap.events))
	}
	e := cap.events[0]

	if e.QName != "www.example.com" {
		t.Errorf("qname = %q, want www.example.com (normalised, no trailing dot)", e.QName)
	}
	if e.QType != "A" {
		t.Errorf("qtype = %q", e.QType)
	}
	if e.ClientIP != "192.168.1.42" {
		t.Errorf("client = %q", e.ClientIP)
	}
	if e.Rcode != "NOERROR" {
		t.Errorf("rcode = %q, want NOERROR", e.Rcode)
	}
	if e.Blocked {
		t.Error("a resolved query was marked as blocked")
	}
	if e.Parent != "example.com" {
		t.Errorf("parent = %q, want example.com", e.Parent)
	}
	// The test upstream answers with a 60-second TTL; the beaconing detector
	// needs that to tell a poll from a cache refresh.
	if e.AnswerTTL != 60 {
		t.Errorf("answer TTL = %d, want 60", e.AnswerTTL)
	}
}

// The Blocked flag is what stops effective filtering from looking like an
// NXDOMAIN incident, so it is asserted at the handler boundary rather than
// only inside the engine.
func TestHandlerMarksBlockedQueries(t *testing.T) {
	h, cap, drain := newDetectingHarness(t, map[string]string{"evil.com": "malware"})

	resp := h.handler.Handle(context.Background(), query("evil.com.", dns.TypeA),
		requestMeta{proto: "udp", clientAddr: mustAddr("192.168.1.42")})
	drain()

	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked query returned rcode %d, want NXDOMAIN", resp.Rcode)
	}
	if len(cap.events) != 1 {
		t.Fatalf("observed %d events, want 1", len(cap.events))
	}
	e := cap.events[0]

	if !e.Blocked {
		t.Error("blocked query was not marked as blocked")
	}
	// The rcode really is NXDOMAIN — the flag is what stops it being counted
	// as an upstream failure.
	if e.Rcode != "NXDOMAIN" {
		t.Errorf("rcode = %q, want NXDOMAIN", e.Rcode)
	}
	if e.NXDomain {
		t.Error("a policy block was enriched as an upstream NXDOMAIN")
	}
}

// Device attribution is a privacy switch. With it off, findings must still be
// produced but must not carry an IP.
func TestHandlerRespectsClientIPPrivacySwitch(t *testing.T) {
	cap := &captureDetector{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := detect.New([]detect.Detector{cap}, nil, detect.NewExclusions(nil, false),
		detect.Options{BufferSize: 64, EvalInterval: time.Hour}, log)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { engine.Run(ctx); close(done) }()

	h := newHarnessWithQueryLog(t, nil, true, func(o *HandlerOptions) {
		o.Detector = engine
		o.LogClientIP = false
	})

	h.handler.Handle(context.Background(), query("www.example.com.", dns.TypeA),
		requestMeta{proto: "udp", clientAddr: mustAddr("192.168.1.42")})
	cancel()
	<-done

	if len(cap.events) != 1 {
		t.Fatalf("observed %d events, want 1", len(cap.events))
	}
	if ip := cap.events[0].ClientIP; ip != "" {
		t.Errorf("client IP %q reached the detection engine with log_client_ip off", ip)
	}
}

// Detection must never be able to change an answer, and must never be able to
// stall one. A detector that panics is the harshest version of that test.
func TestDetectionFailureCannotAffectResolution(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := detect.New([]detect.Detector{&panicDetector{}}, nil,
		detect.NewExclusions(nil, false), detect.Options{BufferSize: 1}, log)

	// Deliberately never Run: the queue fills after one observation and every
	// subsequent Observe must return immediately rather than block.
	h := newHarnessWithQueryLog(t, nil, true, func(o *HandlerOptions) {
		o.Detector = engine
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			resp := h.handler.Handle(context.Background(), query("www.example.com.", dns.TypeA),
				requestMeta{proto: "udp", clientAddr: mustAddr("192.168.1.42")})
			if resp == nil || resp.Rcode != dns.RcodeSuccess {
				t.Errorf("resolution failed while the detection queue was full")
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("resolution blocked on a full detection queue")
	}

	if got := engine.Stats().Dropped; got == 0 {
		t.Error("expected observations to be dropped and counted")
	}
}

// panicDetector would take the process down if it were ever driven; the test
// above relies on it never being reached, which is the point.
type panicDetector struct{}

func (panicDetector) Name() string              { return "panic" }
func (panicDetector) Info() detect.DetectorInfo { return detect.DetectorInfo{Name: "panic"} }
func (panicDetector) Observe(*detect.Event)     { panic("detector should not have run") }
func (panicDetector) Evaluate(time.Time) []detect.Finding {
	panic("detector should not have run")
}
func (panicDetector) Sweep(time.Time) {}
func (panicDetector) Tracked() int    { return 0 }

// mustAddr parses a test client address.
func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}
