package dnssec

import (
	"math"
	"testing"
	"time"
)

// The 32-bit wrap in DNSSEC signature timestamps is specified behaviour, not
// an overflow to be avoided, so it needs testing at the boundary rather than
// a comment saying it is fine.
//
// RFC 4034 §3.1.5: the fields are "a 32-bit unsigned number of seconds
// elapsed since 1 January 1970", "An RRSIG RR can have an Expiration field
// value that is numerically smaller than the Inception field value if the
// expiration field value is near the 32-bit wrap-around point", and "all
// comparisons involving these fields MUST use 'Serial number arithmetic'".

// wrapInstant is the moment the 32-bit seconds count rolls over:
// 2106-02-07T06:28:16Z, one second after the largest representable value.
var wrapInstant = time.Unix(int64(math.MaxUint32)+1, 0).UTC()

func TestDNSSECTimeWrapsAtTheProtocolBoundary(t *testing.T) {
	tests := []struct {
		name string
		at   time.Time
		want uint32
	}{
		{"the epoch", time.Unix(0, 0).UTC(), 0},
		{"a representative signing time", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 1767225600},
		{"the last representable second", time.Unix(int64(math.MaxUint32), 0).UTC(), math.MaxUint32},
		{"one second past it wraps to zero", wrapInstant, 0},
		{"one second after the wrap", wrapInstant.Add(time.Second), 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DNSSECTime(tc.at); got != tc.want {
				t.Errorf("DNSSECTime(%s) = %d, want %d", tc.at.Format(time.RFC3339), got, tc.want)
			}
		})
	}
}

// Serial arithmetic across the wrap, which is the case that makes the
// truncation correct rather than merely tolerable. A signature issued shortly
// before the rollover and expiring shortly after it has an expiration
// numerically smaller than its inception, and must still be judged current.
func TestSerialArithmeticAcrossTheWrap(t *testing.T) {
	const max = uint32(math.MaxUint32)

	tests := []struct {
		name string
		a, b uint32
		want bool
	}{
		{"equal values are at or after each other", 1000, 1000, true},
		{"ordinary ordering", 2000, 1000, true},
		{"ordinary ordering, reversed", 1000, 2000, false},
		{"zero is not after the maximum by ordinary reading", max, 0, false},
		{"but a value just past the wrap is after one just before it", 5, max - 5, true},
		{"and the reverse is not", max - 5, 5, false},
		{"just inside the half-space is ordered", 1<<31 - 1, 0, true},
		{"the far side of the half-space reverses, as RFC 1982 defines", 1 << 31, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := serialGE(tc.a, tc.b); got != tc.want {
				t.Errorf("serialGE(%d, %d) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// The property the whole thing exists for: a signature whose validity window
// straddles the 2106 rollover is current inside it and not current outside,
// even though its expiration is numerically smaller than its inception.
//
// An implementation that widened these fields to int64 to satisfy a static
// analyser would call this signature expired at every instant, including the
// ones it covers.
func TestASignatureStraddlingTheWrapIsJudgedCorrectly(t *testing.T) {
	// Inception one hour before the rollover, expiration one hour after it.
	inception := DNSSECTime(wrapInstant.Add(-time.Hour))
	expiration := DNSSECTime(wrapInstant.Add(time.Hour))

	if inception <= expiration {
		t.Fatalf("fixture is wrong: inception %d should exceed expiration %d across the wrap", inception, expiration)
	}

	inside := []time.Time{
		wrapInstant.Add(-30 * time.Minute),
		wrapInstant,
		wrapInstant.Add(30 * time.Minute),
	}
	for _, at := range inside {
		now := DNSSECTime(at)
		if !serialGE(now, inception) || !serialGE(expiration, now) {
			t.Errorf("%s should be inside the window [%d, %d] but reads as outside (now=%d)",
				at.Format(time.RFC3339), inception, expiration, now)
		}
	}

	outside := []time.Time{
		wrapInstant.Add(-2 * time.Hour),
		wrapInstant.Add(2 * time.Hour),
	}
	for _, at := range outside {
		now := DNSSECTime(at)
		if serialGE(now, inception) && serialGE(expiration, now) {
			t.Errorf("%s should be outside the window [%d, %d] but reads as inside (now=%d)",
				at.Format(time.RFC3339), inception, expiration, now)
		}
	}
}
