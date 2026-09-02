package apiprovider

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token bucket, one per provider.
//
// Written rather than pulled in from golang.org/x/time/rate for the same
// reason the metrics endpoint is hand-rolled: the behaviour needed here is
// forty lines, and on a 1 GB box every dependency is a dependency to audit and
// a binary to grow. The semantics are deliberately the simple ones — refill at
// a steady rate, burst up to the bucket size, block until a token or the
// context is done.
//
// Where it blocks matters. Only engine workers wait here; the resolution path
// reads a cache and enqueues, so a saturated limiter costs a queued item and
// never a slow DNS answer.
type Limiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	// refill is tokens per second.
	refill float64
	last   time.Time
	now    func() time.Time

	// waited counts how many calls had to wait at all, which is the number
	// that tells an operator their configured rate is below what the
	// deployment actually asks for.
	waited uint64
}

// NewLimiter returns a limiter allowing perMinute calls per minute.
//
// The bucket starts full so a fresh provider can answer a burst of queued
// lookups immediately rather than trickling through the first minute — the
// common case at startup, where the queue holds everything resolved while the
// engine was warming up.
func NewLimiter(perMinute int) *Limiter {
	return newLimiterWithClock(perMinute, time.Now)
}

func newLimiterWithClock(perMinute int, now func() time.Time) *Limiter {
	if perMinute <= 0 {
		perMinute = 60
	}
	// Burst is one second's worth, floored at one. A bucket the size of a full
	// minute would let a restart fire sixty requests at a metered API in the
	// same instant, which is the behaviour rate limits exist to prevent.
	capacity := float64(perMinute) / 60
	if capacity < 1 {
		capacity = 1
	}
	return &Limiter{
		tokens:   capacity,
		capacity: capacity,
		refill:   float64(perMinute) / 60,
		last:     now(),
		now:      now,
	}
}

// Wait blocks until a token is available or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	for {
		delay, ok := l.reserve()
		if ok {
			return nil
		}
		// The context deadline is authoritative. A provider whose rate would
		// make us wait longer than the caller's budget should fail now rather
		// than at the end of a wait nobody is still interested in.
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Allow takes a token if one is free, without waiting.
func (l *Limiter) Allow() bool {
	_, ok := l.reserve()
	return ok
}

// reserve takes a token, or reports how long until one exists.
func (l *Limiter) reserve() (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	elapsed := now.Sub(l.last)
	if elapsed > 0 {
		l.tokens += elapsed.Seconds() * l.refill
		if l.tokens > l.capacity {
			l.tokens = l.capacity
		}
		l.last = now
	}

	if l.tokens >= 1 {
		l.tokens--
		return 0, true
	}

	l.waited++
	// How long until the bucket holds one whole token.
	need := 1 - l.tokens
	wait := time.Duration(need / l.refill * float64(time.Second))
	// A floor, so a pathological refill rate cannot produce a spin loop of
	// zero-length timers.
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	return wait, false
}

// Waited reports how many calls have had to wait for a token.
func (l *Limiter) Waited() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.waited
}

// SetRate changes the refill rate in place.
//
// Called when an operator edits a provider, so a rate change takes effect on
// the next lookup rather than the next restart. The bucket is not refilled: an
// operator raising the limit should not also be handed a burst.
func (l *Limiter) SetRate(perMinute int) {
	if perMinute <= 0 {
		perMinute = 60
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	capacity := float64(perMinute) / 60
	if capacity < 1 {
		capacity = 1
	}
	l.capacity = capacity
	l.refill = float64(perMinute) / 60
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
}
