package resolution_test

import (
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/resolution"
)

// A moving clock, so a test can drive five minutes of resolver history without
// waiting five minutes.
type testClock struct{ at time.Time }

func (c *testClock) now() time.Time      { return c.at }
func (c *testClock) add(d time.Duration) { c.at = c.at.Add(d) }

// The window forgets.
//
// This is the defect the whole type exists to fix. The dashboard divided an
// error counter accumulated since process start by a query count over a
// different period; on a resolver that had been up for a month the result was
// dominated by failures nobody remembered, and it could not go down, so a
// deployment that had recovered still read as broken.
func TestTheWindowForgetsWhatIsOlderThanTheWindow(t *testing.T) {
	c := &testClock{at: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	w := resolution.NewWindow(c.now)

	// A bad five minutes: everything failed.
	for i := 0; i < 100; i++ {
		w.Record(resolution.Sample{Err: true, Servfail: true, Elapsed: time.Second})
	}
	if got := w.Snapshot(); got.Errors != 100 {
		t.Fatalf("errors = %d, want 100", got.Errors)
	}

	// An hour later, all of it healthy.
	c.add(time.Hour)
	for i := 0; i < 100; i++ {
		w.Record(resolution.Sample{Elapsed: 5 * time.Millisecond})
	}

	got := w.Snapshot()
	if got.Errors != 0 {
		t.Errorf("errors = %d an hour after the failures stopped; the window is not rolling",
			got.Errors)
	}
	if got.Queries != 100 {
		t.Errorf("queries = %d, want the 100 in the window", got.Queries)
	}
	// The lifetime figure is still there, kept apart so nothing can divide one
	// by the other by accident.
	if total := w.Total(); total != 200 {
		t.Errorf("Total() = %d, want every sample ever recorded (200)", total)
	}
}

// Refusing a forged answer is the resolver working, not the resolver ill.
//
// A deployment whose users happen to visit one misconfigured signed domain
// must not read as unhealthy. That is the whole of Part 8's second half, and
// it has to be decided in one place or it will be decided differently in two.
func TestABogusAnswerDoesNotMakeTheResolverUnhealthy(t *testing.T) {
	c := &testClock{at: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	w := resolution.NewWindow(c.now)

	for i := 0; i < 50; i++ {
		w.Record(resolution.Sample{Elapsed: 5 * time.Millisecond})
	}
	// Every one of these is a security decision: the resolver validated, found
	// the answer forged, and refused it. SERVFAIL went to the client.
	for i := 0; i < 50; i++ {
		w.Record(resolution.Sample{Elapsed: 8 * time.Millisecond, Bogus: true, Servfail: true})
	}

	got := w.Snapshot()
	if got.Bogus != 50 {
		t.Errorf("bogus = %d, want 50", got.Bogus)
	}
	if got.Errors != 0 {
		t.Errorf("errors = %d; refusing a forged answer is not an error", got.Errors)
	}
	if got.Servfail != 50 {
		t.Errorf("servfail = %d, want 50 — the client did receive SERVFAIL", got.Servfail)
	}
}

// An unmeasured rate is not a rate of zero.
//
// A cache that answered none of the lookups it saw and a cache that has seen no
// lookups are different facts. This deployment has already shown the second as
// the first once, on the settings page.
func TestAnUnmeasuredCacheRateIsReportedAsUnmeasured(t *testing.T) {
	c := &testClock{at: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	w := resolution.NewWindow(c.now)

	if got := w.Snapshot(); got.CacheHitRate >= 0 {
		t.Errorf("an empty window reports a cache hit rate of %v; "+
			"nothing has been measured and it must say so", got.CacheHitRate)
	}

	w.Record(resolution.Sample{Elapsed: time.Millisecond})
	if got := w.Snapshot(); got.CacheHitRate != 0 {
		t.Errorf("one miss gives a hit rate of %v, want 0", got.CacheHitRate)
	}
	w.Record(resolution.Sample{Elapsed: time.Millisecond, Cached: true})
	if got := w.Snapshot(); got.CacheHitRate != 0.5 {
		t.Errorf("one hit and one miss gives %v, want 0.5", got.CacheHitRate)
	}
}

// Latency percentiles come from the window and never underestimate.
//
// Overestimating is the right way round: a health check that under-reported p99
// would be one that missed the thing it exists to catch.
func TestLatencyPercentilesNeverUnderstateTheTail(t *testing.T) {
	c := &testClock{at: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	w := resolution.NewWindow(c.now)

	// Ninety fast, ten slow.
	for i := 0; i < 90; i++ {
		w.Record(resolution.Sample{Elapsed: time.Millisecond})
	}
	for i := 0; i < 10; i++ {
		w.Record(resolution.Sample{Elapsed: 400 * time.Millisecond})
	}

	got := w.Snapshot()
	if got.P50 > 2*time.Millisecond {
		t.Errorf("p50 = %s, want about 1ms — ninety per cent of these were fast", got.P50)
	}
	if got.P99 < 400*time.Millisecond {
		t.Errorf("p99 = %s, want at least the 400ms the slow tenth took; "+
			"a percentile that understates the tail hides the problem it exists to find",
			got.P99)
	}
}
