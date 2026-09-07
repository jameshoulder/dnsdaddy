package dnssec

import "time"

// Clock supplies the validator's notion of the current time.
//
// RFC 4035 §5.3.1 phrases both validity checks in terms of "the validator's
// notion of the current time" (R-SIG-05, R-SIG-06), which is an unusually
// direct invitation to make it injectable. A validator that reads the wall
// clock directly cannot be tested at either boundary, and both boundaries are
// inclusive, so both are worth a test that pins the exact second.
//
// It is also the honest model of the situation: a validator with a wrong
// clock declares correctly signed zones Bogus, and that failure mode is much
// easier to reason about when the clock is a value rather than an ambient
// fact.
type Clock interface {
	Now() time.Time
}

// SystemClock reads the wall clock.
type SystemClock struct{}

// Now returns the current time in UTC. UTC because signature validity is
// expressed in seconds since the epoch and a local zone adds nothing but the
// chance of a confusing trace.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// FixedClock returns one instant, always. Test code uses it to sit exactly on
// an inception or expiration second.
type FixedClock struct{ Instant time.Time }

// Now returns the fixed instant.
func (c FixedClock) Now() time.Time { return c.Instant.UTC() }
