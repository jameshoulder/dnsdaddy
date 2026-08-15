package detect

import (
	"context"
	"sync"
	"testing"
	"time"
)

// The detection engine is driven by one goroutine, but the API reads from it
// while that goroutine is running: /metrics calls Stats and Counts, and
// /api/v1/detectors calls Catalogue. Those are the only cross-goroutine reads
// that exist, and if any of them touched detector state directly it would be a
// data race in production that no single-threaded test would ever show.
//
// Run this package with -race for it to mean anything.
func TestAPIReadersAreSafeWhileEngineRuns(t *testing.T) {
	sink := &recordingSink{}
	e := New(defaultDetectorsForTest(), sink, NewExclusions(nil, false), Options{
		BufferSize:   1024,
		EvalInterval: time.Millisecond,
		Cooldown:     time.Millisecond,
	}, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)
	go func() { defer wg.Done(); e.Run(ctx) }()

	// Feed it continuously, so the engine goroutine is inside Observe and
	// Evaluate while the readers below run.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20000; i++ {
			e.Observe(Observation{
				Time:     time.Now(),
				ClientIP: "10.0.0.1",
				QName:    randomLabel(newTestRand(int64(i)), base32Alphabet, 40) + ".tunnel.example",
				QType:    "TXT",
				Rcode:    "NOERROR",
			})
		}
	}()

	// The API surface, hammered concurrently.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				_ = e.Stats()
				_ = e.Counts()
				_ = e.Catalogue()
			}
		}()
	}

	// Give the engine a moment of real overlap before shutting down.
	time.Sleep(150 * time.Millisecond)
	cancel()
	wg.Wait()
	e.Wait()
}

// Cooldown state is keyed on subject and event type, and it is the one map in
// the engine that grows with the number of distinct subjects rather than with
// tracked detector state. Without a sweep it would grow for the lifetime of the
// process on a network with many clients.
func TestCooldownStateIsSwept(t *testing.T) {
	d := &keyedStubDetector{}
	e := New([]Detector{d}, &recordingSink{}, NewExclusions(nil, false), Options{
		Cooldown: time.Minute,
	}, testLogger())

	now := time.Now()

	// 500 distinct subjects, each emitting once.
	for i := 0; i < 500; i++ {
		d.client = randomLabel(newTestRand(int64(i)), lowerAlphabet, 8)
		e.evaluate(context.Background(), now)
	}
	if got := len(e.lastEmit); got != 500 {
		t.Fatalf("cooldown map holds %d entries, want 500", got)
	}

	// Well past two cooldowns, every entry is dead weight and must be dropped.
	e.sweepCooldowns(now.Add(3 * time.Minute))
	if got := len(e.lastEmit); got != 0 {
		t.Errorf("cooldown map still holds %d entries after a sweep", got)
	}
}

// A detector whose state is bounded must stay bounded under a flood of unique
// keys — that is the whole reason for the cap, and it is the difference between
// a detection gap and an out-of-memory kill.
func TestDetectorStateStaysBoundedUnderUniqueNameFlood(t *testing.T) {
	cfg := DefaultTunnelConfig()
	cfg.MaxTracked = 64
	d := NewTunnelDetector(cfg)

	ex := NewExclusions(nil, false)
	now := time.Now()

	// 10,000 distinct client/domain pairs against a cap of 64.
	for i := 0; i < 10000; i++ {
		r := newTestRand(int64(i))
		ev := Event{Observation: Observation{
			Time:     now,
			ClientIP: randomLabel(r, lowerAlphabet, 6),
			QName:    "a." + randomLabel(r, lowerAlphabet, 10) + ".example",
			QType:    "A",
		}}
		ev.Parent, ev.Sub, ev.HasParent = split(ev.QName)
		ev.Excluded = ex.Excluded(ev.QName)
		d.Observe(&ev)
	}

	if got := d.Tracked(); got > cfg.MaxTracked {
		t.Errorf("tracked %d keys, cap is %d — eviction is not bounding the state", got, cfg.MaxTracked)
	}
}

// keyedStubDetector emits one finding for a settable client, so the engine's
// cooldown keying can be exercised across many distinct subjects.
type keyedStubDetector struct{ client string }

func (d *keyedStubDetector) Name() string { return "keyed_stub" }
func (d *keyedStubDetector) Info() DetectorInfo {
	return DetectorInfo{Name: "keyed_stub", EventType: "stub_event", Maturity: MaturityExperimental}
}
func (d *keyedStubDetector) Observe(*Event) {}
func (d *keyedStubDetector) Evaluate(now time.Time) []Finding {
	return []Finding{{
		EventType: "stub_event",
		Severity:  SeverityHigh,
		Client:    Client{IP: d.client},
		Time:      now,
	}}
}
func (d *keyedStubDetector) Sweep(time.Time) {}
func (d *keyedStubDetector) Tracked() int    { return 0 }
