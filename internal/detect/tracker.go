package detect

import "time"

// tracker holds per-key behavioural state inside a bounded, expiring window.
//
// Two properties matter more than anything else here, because this structure
// is fed directly by untrusted network traffic:
//
//	It is bounded. A client spraying a million unique names must not be able
//	to make the resolver allocate a million tracking entries. When the cap is
//	reached, entries are evicted and the eviction is counted — a detection gap
//	we report rather than an out-of-memory kill we do not survive.
//
//	Eviction is O(1). Scanning every entry to find the oldest would hand an
//	attacker a quadratic amount of work per query, turning the detector into
//	the amplifier. Instead a small random sample is taken and the least
//	recently updated of that sample is evicted, which is the standard
//	approximate-LRU trade: not exactly the oldest, cheap, and good enough when
//	the aim is bounding memory rather than perfect cache retention.
//
// The engine drives every tracker from a single goroutine, so nothing here
// takes a lock. Counters that the metrics endpoint reads are published by the
// engine, not read from here directly.
type tracker[S any] struct {
	entries map[string]*entry[S]
	// max bounds how many keys are tracked at once.
	max int
	// window is how long state accumulates before it is evaluated and reset.
	window time.Duration
	// idle is how long an untouched entry is kept before deletion. Two windows
	// means a client that goes quiet for one evaluation cycle keeps its slot,
	// but a one-off burst does not hold memory indefinitely.
	idle time.Duration
	// newState builds the zero state for a new key.
	newState func() S

	evicted uint64
	created uint64
}

type entry[S any] struct {
	key   string
	state S
	start time.Time
	last  time.Time
}

func newTracker[S any](max int, window time.Duration, newState func() S) *tracker[S] {
	if max <= 0 {
		max = 4096
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &tracker[S]{
		entries:  make(map[string]*entry[S]),
		max:      max,
		window:   window,
		idle:     2 * window,
		newState: newState,
	}
}

// evictionSample is how many entries are considered when making room. Eight is
// the same sample size Redis uses for approximate LRU; it picks an entry in
// the oldest ~12% with high probability at negligible cost.
const evictionSample = 8

// get returns the state for key, creating it if necessary.
func (t *tracker[S]) get(key string, now time.Time) *entry[S] {
	if e, ok := t.entries[key]; ok {
		e.last = now
		return e
	}
	if len(t.entries) >= t.max {
		t.evictOne()
	}
	e := &entry[S]{key: key, state: t.newState(), start: now, last: now}
	t.entries[key] = e
	t.created++
	return e
}

// evictOne removes the least recently updated entry from a random sample.
func (t *tracker[S]) evictOne() {
	var (
		victim  string
		oldest  time.Time
		sampled int
	)
	// Go randomises map iteration order, which is exactly the sample we want.
	for k, e := range t.entries {
		if victim == "" || e.last.Before(oldest) {
			victim, oldest = k, e.last
		}
		sampled++
		if sampled >= evictionSample {
			break
		}
	}
	if victim != "" {
		delete(t.entries, victim)
		t.evicted++
	}
}

// due returns the entries whose observation window has closed, and resets each
// one to start a fresh window.
//
// The window is tumbling rather than sliding. A sliding window would need
// per-observation timestamps for every counter, which for a detector watching
// tens of thousands of keys is a great deal of memory to buy a small
// improvement in edge-case timing. The cost is that behaviour straddling a
// boundary is split across two windows; sustained behaviour — which is what
// these detectors are looking for — simply fires on the next one.
func (t *tracker[S]) due(now time.Time) []*entry[S] {
	var out []*entry[S]
	for _, e := range t.entries {
		if now.Sub(e.start) >= t.window {
			out = append(out, e)
		}
	}
	return out
}

// reset starts a fresh window for e, keeping its slot.
func (t *tracker[S]) reset(e *entry[S], now time.Time) {
	e.state = t.newState()
	e.start = now
}

// sweep deletes entries that have seen no observations for idle.
func (t *tracker[S]) sweep(now time.Time) {
	for k, e := range t.entries {
		if now.Sub(e.last) >= t.idle {
			delete(t.entries, k)
		}
	}
}

// len reports how many keys are tracked.
func (t *tracker[S]) len() int { return len(t.entries) }

// boundedSet counts distinct values up to a cap.
//
// Cardinality is the headline signal for tunnelling and DGA activity, and the
// naive way to measure it — keep every value — is precisely what a flood of
// unique names would exploit. Capping the stored set bounds memory; the
// counter keeps rising past the cap so the signal still separates "a few
// hundred" from "a few thousand", it simply stops being able to deduplicate.
// Once the cap is hit the count is an upper bound, and findings say so.
type boundedSet struct {
	seen  map[string]struct{}
	cap   int
	total int
	// overflow records that the set stopped deduplicating.
	overflow bool
}

func newBoundedSet(capacity int) *boundedSet {
	if capacity <= 0 {
		capacity = 1024
	}
	return &boundedSet{seen: make(map[string]struct{}), cap: capacity}
}

// add records v and reports whether it was new.
func (s *boundedSet) add(v string) bool {
	if _, ok := s.seen[v]; ok {
		return false
	}
	if len(s.seen) >= s.cap {
		// Stop storing, keep counting. Everything past the cap is assumed
		// distinct, which is the conservative direction for a detector that
		// must not silently under-report a large tunnel.
		s.overflow = true
		s.total++
		return true
	}
	s.seen[v] = struct{}{}
	s.total++
	return true
}

// count returns the number of distinct values observed, exact below the cap
// and an upper bound above it.
func (s *boundedSet) count() int { return s.total }

// contains reports whether v is in the stored set.
//
// Above the cap the set stops storing, so this can answer false for a value
// that was counted. Callers use it to avoid double-work, never to make a
// security decision, so an occasional miss under extreme cardinality costs
// accuracy in the signal rather than correctness.
func (s *boundedSet) contains(v string) bool {
	_, ok := s.seen[v]
	return ok
}
