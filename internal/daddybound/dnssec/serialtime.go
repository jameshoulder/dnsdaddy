package dnssec

import "time"

// DNSSEC signature timestamps are 32-bit and wrap, and comparisons over them
// are serial-number arithmetic rather than ordinary integer arithmetic. This
// file is the one place that knows that, so the narrow conversions the
// protocol requires live together with the reasoning and the tests.
//
// RFC 4034 §3.1.5:
//
//	The Signature Expiration and Inception field values specify a date and
//	time in the form of a 32-bit unsigned number of seconds elapsed since
//	1 January 1970 00:00:00 UTC, ignoring leap seconds, in network byte
//	order. The longest interval that can be expressed by this format without
//	wrapping is approximately 136 years. An RRSIG RR can have an Expiration
//	field value that is numerically smaller than the Inception field value
//	if the expiration field value is near the 32-bit wrap-around point or if
//	the signature is long lived. Because of this, all comparisons involving
//	these fields MUST use "Serial number arithmetic", as defined in
//	[RFC1982]. As a direct consequence, the values contained in these fields
//	cannot refer to dates more than 68 years in either the past or the
//	future.
//
// Widening these to int64 to silence a static analyser would break the
// protocol, not fix it: an expiration numerically smaller than its inception
// is *legal* near the wrap point, and int64 comparison would call such a
// signature expired when RFC 1982 says it is current. The truncation is the
// specification.

// DNSSECTime converts a wall-clock instant to the 32-bit form RRSIG
// inception and expiration fields use.
//
// The truncation is deliberate and is what RFC 4034 §3.1.5 specifies. Every
// comparison against the result goes through serialGE, which implements
// RFC 1982 serial arithmetic, so a value that has wrapped past 2106 still
// compares correctly against neighbouring timestamps — that is the whole
// point of the 32-bit representation, rather than a limitation of it.
//
// Callers pass a validator's notion of the current time or a signer's chosen
// validity bounds; neither is attacker-controlled in a way that a wider type
// would protect against.
func DNSSECTime(t time.Time) uint32 {
	// #nosec G115 -- RFC 4034 §3.1.5 defines these fields as a 32-bit
	// unsigned seconds count that wraps, and RFC 1982 serial arithmetic (see
	// serialGE) is defined over exactly that truncation. Widening the type
	// would misjudge signatures whose expiration is numerically smaller than
	// their inception, which the same section says is legal near the
	// wrap-around point. Boundary behaviour is pinned by
	// TestDNSSECTimeWrapsAtTheProtocolBoundary.
	return uint32(t.Unix())
}

// serialGE reports whether a is at or after b under RFC 1982 serial-number
// arithmetic, as RFC 4034 §3.1.5 requires for signature timestamps.
//
// The subtraction is performed in uint32 — where it wraps, which is the
// intended behaviour — and the result is reinterpreted as a signed 32-bit
// value. A difference in the closed half of the number space reads as
// positive and one in the other half reads as negative, which is exactly
// RFC 1982's definition. Two timestamps more than 2^31 seconds (about 68
// years) apart have no defined ordering, and RFC 4034 §3.1.5 says so:
// "the values contained in these fields cannot refer to dates more than 68
// years in either the past or the future."
func serialGE(a, b uint32) bool {
	// #nosec G115 -- the reinterpretation is RFC 1982 serial arithmetic, not
	// an accidental narrowing. Pinned by TestSerialArithmeticAcrossTheWrap.
	return int32(a-b) >= 0
}
