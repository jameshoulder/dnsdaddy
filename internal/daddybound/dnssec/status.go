// Package dnssec implements DNSSEC trust logic from first principles.
//
// "From first principles" is a claim about the trust logic, not about the
// mathematics. Signature arithmetic comes from Go's crypto packages and wire
// serialisation comes from github.com/miekg/dns. What lives here is the part
// that decides things: which key is allowed to sign what, whether a DS
// authenticates a DNSKEY, what bytes a signature actually covers, how a chain
// of trust is walked, and — the part that matters most — what this package is
// entitled to claim when it cannot tell.
//
// Every rule is traceable to a sentence in a standard. The identifiers in
// comments (R-SIG-01, R-CANON-02, and so on) index docs/daddybound/standards.md,
// which quotes the source text. A rule with no identifier is a bug or an
// invention, and both are worth finding.
//
// This package is experimental. It does not answer DNS for anybody.
package dnssec

// ValidationStatus is the outcome of validating an RRset, as defined by
// RFC 4033 §5 and RFC 4035 §4.3. There are exactly four, and the definitions
// are narrower than their English names suggest — see the constants.
type ValidationStatus uint8

const (
	// StatusIndeterminate is the zero value on purpose. A result that was
	// never filled in should read as "this validator could not tell", which
	// is both true and safe; a zero value meaning Secure would turn every
	// forgotten assignment into a false Secure.
	//
	// RFC 4033 §5: "There is no trust anchor that would indicate that a
	// specific portion of the tree is secure. This is the default operation
	// mode."
	//
	// Daddybound also returns Indeterminate in cases where a complete
	// validator would return Insecure, because reaching Insecure honestly
	// requires denial-of-existence proofs that v0.1 does not implement. See
	// StatusInsecure.
	StatusIndeterminate ValidationStatus = iota

	// StatusSecure means a chain of trust was walked from a configured trust
	// anchor to the RRset and every signature on the way verified.
	//
	// RFC 4033 §5: "The validating resolver has a trust anchor, has a chain
	// of trust, and is able to verify all the signatures in the response."
	StatusSecure

	// StatusInsecure means there is signed proof that the data is not
	// signed — specifically, proof that no DS record exists at some
	// delegation point.
	//
	// RFC 4033 §5: "The validating resolver has a trust anchor, a chain of
	// trust, and, at some delegation point, signed proof of the non-existence
	// of a DS record."
	//
	// Note the words "signed proof". Insecure is not "we looked and found no
	// signature"; it is a positive, authenticated statement that none should
	// exist. Producing that proof needs NSEC or NSEC3, which v0.1 does not
	// implement, so no code path in v0.1 returns this status. The constant
	// exists because the type models the standard rather than the current
	// milestone, and because a test asserts the absence — see status_test.go.
	StatusInsecure

	// StatusBogus means the data should have validated and did not.
	//
	// RFC 4033 §5: "The validating resolver has a trust anchor and a secure
	// delegation indicating that subsidiary data is signed, but the response
	// fails to validate for some reason".
	//
	// The precondition matters as much as the failure: Bogus accuses someone
	// of serving broken or forged data, and that accusation is only available
	// once a secure delegation has actually been established. A failure
	// before that point is Indeterminate, because nothing has yet promised
	// the data would be signed.
	StatusBogus
)

// String returns the lower-case name used in traces, logs and JSON.
func (s ValidationStatus) String() string {
	switch s {
	case StatusSecure:
		return "secure"
	case StatusInsecure:
		return "insecure"
	case StatusBogus:
		return "bogus"
	case StatusIndeterminate:
		return "indeterminate"
	}
	return "indeterminate"
}

// MarshalText makes the status render as its name in JSON rather than as an
// integer, so a stored trace stays readable when the constants are renumbered.
func (s ValidationStatus) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Valid reports whether s is one of the four defined statuses. Anything else
// arrived by conversion from an integer and should not be trusted to mean
// what it says.
func (s ValidationStatus) Valid() bool { return s <= StatusBogus }
