package resolution

import (
	"sync"
	"time"
)

// A rolling window of resolver counters.
//
// This exists because of a specific defect rather than as general
// infrastructure. The dashboard computed a resolver's error rate by dividing a
// counter accumulated since process start by a query count covering a different
// period. The result was not a rate of anything: on a resolver that had been up
// for a month it was dominated by failures nobody remembered, and it could not
// go down, so a deployment that had recovered still looked broken.
//
// So every figure a health check reads comes from one structure covering one
// period, and the period is reported alongside the numbers. A caller cannot
// accidentally divide two counters from different windows, because there is
// only one window.
//
// Implementation: fixed buckets in a ring. Memory is constant, there is nothing
// to prune, and a bucket older than the window is recognised by its timestamp
// and treated as empty rather than being cleared by a background sweep. The
// cost of a record is one lock, one modulo and a handful of increments.

// windowSpan is the period health is measured over.
//
// Five minutes: long enough that a handful of queries do not make a rate swing
// wildly, short enough that a resolver which recovered ten minutes ago reads as
// healthy. Both directions matter — a window that never forgets is the defect
// this replaces.
const windowSpan = 5 * time.Minute

// windowBuckets is how finely the span is divided. Ten-second granularity: the
// oldest tenth of the window ages out in one step rather than the whole window
// dropping at once.
const windowBuckets = 30

const bucketSpan = windowSpan / windowBuckets

// latencyBounds are the upper edges of the latency histogram, in milliseconds.
//
// Chosen for what a DNS resolver actually does rather than as a round-number
// ladder. The dense region is 1–50ms, where a cache hit and a warm recursive
// answer live and where a change is worth seeing; above 200ms the exact figure
// stops mattering because the answer is already slow. The final bucket is
// unbounded, so a percentile that lands in it is reported as "at least the
// previous edge" rather than as a number invented to fill a gap.
// latencyBucketCount is the histogram width: one bucket per bound plus one
// for everything above the last.
const latencyBucketCount = 20

var latencyBounds = [latencyBucketCount - 1]time.Duration{
	100 * time.Microsecond,
	500 * time.Microsecond,
	time.Millisecond,
	2 * time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	20 * time.Millisecond,
	35 * time.Millisecond,
	50 * time.Millisecond,
	75 * time.Millisecond,
	100 * time.Millisecond,
	150 * time.Millisecond,
	200 * time.Millisecond,
	300 * time.Millisecond,
	500 * time.Millisecond,
	750 * time.Millisecond,
	time.Second,
	2 * time.Second,
	5 * time.Second,
}

// Sample is one resolution, as the window records it.
type Sample struct {
	// Elapsed is how long it took.
	Elapsed time.Duration
	// Cached reports a cache hit.
	Cached bool
	// Collapsed reports a caller that waited on another's flight. Counted
	// apart from Cached: it did no network work but it was not fast, and
	// folding it into the hit rate would inflate exactly the number an
	// operator watches during a burst.
	Collapsed bool
	// Err reports that no answer was obtained: a timeout, an unreachable
	// server, an internal failure. Never a security decision.
	Err bool
	// Servfail reports that the client was sent SERVFAIL, for whatever
	// reason including a refused bogus answer.
	Servfail bool
	// Bogus reports that an answer was refused because it did not
	// authenticate. Counted apart from Err on purpose: see Health.Bogus.
	Bogus bool
	// AuthTimeout reports an authoritative server that did not answer.
	AuthTimeout bool
}

type bucket struct {
	at        time.Time
	queries   uint64
	hits      uint64
	errors    uint64
	servfail  uint64
	bogus     uint64
	authTimes uint64
	collapsed uint64
	latency   [latencyBucketCount]uint64
}

// Window is a rolling window of resolution counters.
//
// Safe for concurrent use. The lock is held for a few increments per query,
// which on the reference deployment — one vCPU — is cheaper than the atomics
// and the reconciliation an unlocked design would need, and is nowhere near
// the cost of the DNS exchange it is measuring.
type Window struct {
	now func() time.Time

	mu      sync.Mutex
	buckets [windowBuckets]bucket
	// total counts every sample ever recorded, for the lifetime figures a
	// dashboard still wants. Kept apart from the window's counters so nothing
	// can divide one by the other by accident.
	total uint64
}

// NewWindow builds a window. A nil clock means time.Now.
func NewWindow(now func() time.Time) *Window {
	if now == nil {
		now = time.Now
	}
	return &Window{now: now}
}

// Record adds one resolution.
func (w *Window) Record(s Sample) {
	at := w.now()

	w.mu.Lock()
	defer w.mu.Unlock()

	b := w.bucketFor(at)
	b.queries++
	if s.Cached {
		b.hits++
	}
	if s.Collapsed {
		b.collapsed++
	}
	if s.Err {
		b.errors++
	}
	if s.Servfail {
		b.servfail++
	}
	if s.Bogus {
		b.bogus++
	}
	if s.AuthTimeout {
		b.authTimes++
	}
	b.latency[latencyBucket(s.Elapsed)]++
	w.total++
}

// bucketFor returns the bucket for an instant, resetting it if it holds data
// from a previous turn of the ring.
//
// The reset is what makes this a rolling window rather than a growing one, and
// it happens on write rather than on a timer: a resolver that stops receiving
// queries has nothing to age out, and a background goroutine to notice that
// would be a goroutine per backend doing nothing.
func (w *Window) bucketFor(at time.Time) *bucket {
	start := at.Truncate(bucketSpan)
	idx := (start.UnixNano() / int64(bucketSpan)) % windowBuckets
	if idx < 0 {
		idx += windowBuckets
	}
	b := &w.buckets[idx]
	if !b.at.Equal(start) {
		*b = bucket{at: start}
	}
	return b
}

// Snapshot reads the window.
func (w *Window) Snapshot() Health {
	at := w.now()
	cutoff := at.Add(-windowSpan)

	w.mu.Lock()
	defer w.mu.Unlock()

	h := Health{OK: true, Window: windowSpan, CacheHitRate: -1}
	var (
		hits    uint64
		lookups uint64
		latency [latencyBucketCount]uint64
	)
	for i := range w.buckets {
		b := &w.buckets[i]
		if b.at.IsZero() || b.at.Before(cutoff) {
			continue
		}
		h.Queries += b.queries
		h.Errors += b.errors
		h.Servfail += b.servfail
		h.Bogus += b.bogus
		h.AuthoritativeTimeouts += b.authTimes
		h.Collapsed += b.collapsed
		hits += b.hits
		lookups += b.queries
		for j := range b.latency {
			latency[j] += b.latency[j]
		}
	}

	// A rate of zero and no measurement at all are different facts. Reporting
	// the second as the first is how a dashboard shows an unmeasured 0% as
	// though it had been measured, which this deployment has already done
	// once with cache statistics.
	if lookups > 0 {
		h.CacheHitRate = float64(hits) / float64(lookups)
	}
	if h.Queries > 0 {
		h.P50 = percentile(latency, h.Queries, 0.50)
		h.P95 = percentile(latency, h.Queries, 0.95)
		h.P99 = percentile(latency, h.Queries, 0.99)
	}
	return h
}

// Total is every sample ever recorded, for lifetime figures.
func (w *Window) Total() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.total
}

// latencyBucket returns the histogram index for a duration.
func latencyBucket(d time.Duration) int {
	for i, bound := range latencyBounds {
		if d <= bound {
			return i
		}
	}
	return len(latencyBounds)
}

// percentile reads a bucketed percentile.
//
// The upper edge of the bucket the percentile falls in, which is an
// overestimate by construction — never an underestimate. That is the right way
// round for latency: a health check that under-reported p99 would be a health
// check that missed the thing it exists to catch.
//
// The overflow bucket has no upper edge, so a percentile landing there is
// reported as the last bound. A caller displaying it should say "at least",
// and Health documents that.
func percentile(counts [latencyBucketCount]uint64, total uint64, p float64) time.Duration {
	if total == 0 {
		return 0
	}
	want := uint64(float64(total) * p)
	if want == 0 {
		want = 1
	}
	var seen uint64
	for i, n := range counts {
		seen += n
		if seen >= want {
			if i >= len(latencyBounds) {
				return latencyBounds[len(latencyBounds)-1]
			}
			return latencyBounds[i]
		}
	}
	return latencyBounds[len(latencyBounds)-1]
}
