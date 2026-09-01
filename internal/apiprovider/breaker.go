package apiprovider

import (
	"sync"
	"time"
)

// BreakerState is where a circuit breaker currently sits.
type BreakerState string

const (
	// BreakerClosed is the normal state: calls go through.
	BreakerClosed BreakerState = "closed"
	// BreakerOpen means calls fail immediately without touching the network.
	BreakerOpen BreakerState = "open"
	// BreakerHalfOpen admits exactly one probe to find out whether the
	// provider has recovered.
	BreakerHalfOpen BreakerState = "half-open"
)

// Breaker stops a failing provider from costing anything.
//
// The failure this exists for is not a single error — the retry handles that —
// but a provider that is down for ten minutes while the resolver keeps
// dialling it. Without a breaker every enrichment task pays the full timeout,
// the worker pool fills with calls that will not succeed, and the queue backs
// up behind a service that has nothing to say. With one, the first few
// failures are paid for and the rest cost a mutex.
//
//	                  failures ≥ threshold
//	CLOSED ─────────────────────────────────► OPEN
//	   ▲                                        │
//	   │ probe succeeds                         │ cooldown elapsed
//	   │                                        ▼
//	   └──────────────────────────────────  HALF-OPEN
//	                                            │
//	                                            │ probe fails
//	                                            ▼
//	                                          OPEN
//
// Safe for concurrent use.
type Breaker struct {
	threshold int
	cooldown  time.Duration
	now       func() time.Time

	mu            sync.Mutex
	state         BreakerState
	failures      int
	openedAt      time.Time
	probeInFlight bool

	// Counters for the dashboard and metrics. A breaker that has tripped
	// twice today is a different operational story from one that has tripped
	// two hundred times, and neither is visible from the current state alone.
	trips         uint64
	shortCircuits uint64
}

// BreakerOptions configures a Breaker. Zero values take documented defaults.
type BreakerOptions struct {
	// Threshold is consecutive failures before opening. Default 5.
	Threshold int
	// Cooldown is how long to stay open before admitting a probe. Default 30s.
	Cooldown time.Duration
	// Now is injectable so tests can drive the clock rather than sleep.
	Now func() time.Time
}

// NewBreaker returns a closed breaker.
func NewBreaker(o BreakerOptions) *Breaker {
	if o.Threshold <= 0 {
		o.Threshold = 5
	}
	if o.Cooldown <= 0 {
		o.Cooldown = 30 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Breaker{
		threshold: o.Threshold,
		cooldown:  o.Cooldown,
		now:       o.Now,
		state:     BreakerClosed,
	}
}

// Allow reports whether a call may proceed, and moves the breaker into
// half-open when the cooldown has elapsed.
//
// A caller that gets true must call exactly one of Success or Failure. Not
// doing so in the half-open state leaves the probe slot held and the breaker
// stuck, which is why the engine's call site is a single function with a
// defer rather than a branch anyone can add a return to.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case BreakerClosed:
		return true

	case BreakerOpen:
		if b.now().Sub(b.openedAt) < b.cooldown {
			b.shortCircuits++
			return false
		}
		// Cooldown elapsed: one probe, and one only.
		b.state = BreakerHalfOpen
		b.probeInFlight = true
		return true

	case BreakerHalfOpen:
		// A second caller during the probe is short-circuited. Letting them
		// all through would mean a provider that recovers gets a thundering
		// herd at the instant it comes back.
		if b.probeInFlight {
			b.shortCircuits++
			return false
		}
		b.probeInFlight = true
		return true
	}
	return true
}

// Success records a call that worked.
func (b *Breaker) Success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.probeInFlight = false
	b.state = BreakerClosed
}

// Failure records a call that did not.
func (b *Breaker) Failure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.probeInFlight = false
	b.failures++

	// A failed probe re-opens immediately and restarts the cooldown, rather
	// than counting towards the threshold again: the provider has already
	// demonstrated it is down, and making it fail five more times to prove it
	// is five more timeouts nobody needs to pay.
	if b.state == BreakerHalfOpen || b.failures >= b.threshold {
		if b.state != BreakerOpen {
			b.trips++
		}
		b.state = BreakerOpen
		b.openedAt = b.now()
	}
}

// State reports where the breaker is, without moving it.
//
// Deliberately does not perform the open→half-open transition that Allow does.
// This is what the dashboard and metrics read, and an observer must not change
// what it observes: a metrics scrape every fifteen seconds would otherwise
// consume the probe slot the next real call needs.
func (b *Breaker) State() BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == BreakerOpen && b.now().Sub(b.openedAt) >= b.cooldown {
		// Report what a caller would find, without taking the slot.
		return BreakerHalfOpen
	}
	return b.state
}

// Stats returns the counters behind the state.
func (b *Breaker) Stats() (trips, shortCircuits uint64, consecutiveFailures int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.trips, b.shortCircuits, b.failures
}

// Cancel releases a call admitted by Allow that never reached the provider.
//
// The invariant Allow establishes is that exactly one of Success, Failure or
// Cancel follows it, because in half-open the probe slot is held until one of
// them runs. Cancel is the third case and it is a real one: a call whose
// budget expired waiting for a rate-limit token learned nothing about the
// provider, so counting it as a failure would trip a breaker because the
// operator set the rate too low — a self-inflicted outage caused by the
// mechanism meant to prevent one.
func (b *Breaker) Cancel() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probeInFlight = false
	// The state is left alone. A cancel in half-open leaves the breaker
	// half-open with its slot free, so the next real call takes the probe.
}

// Reset closes the breaker and clears its failure count.
//
// For an operator who has fixed the provider and does not want to wait out the
// cooldown — the "test connection" button uses it, because a test that
// short-circuits tells them nothing about whether their fix worked.
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = BreakerClosed
	b.failures = 0
	b.probeInFlight = false
}
