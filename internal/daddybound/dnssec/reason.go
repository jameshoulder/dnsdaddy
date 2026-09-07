package dnssec

// Reason is the machine-readable cause of a validation outcome.
//
// It is a typed constant, never free text, because policy must never be
// decided by matching an English sentence. Human wording is derived from a
// Reason by Explain; nothing in this package ever goes the other way. If a
// caller finds itself comparing strings to decide something, the taxonomy is
// missing a value and the fix is to add one here.
//
// The values are stable identifiers: they appear in traces, in the
// differential comparator's output, and in the regression corpus, so renaming
// one is a breaking change to recorded evidence.
type Reason string

// Reasons that are not failures.
const (
	// ReasonNone is the zero value: nothing went wrong, or nothing has
	// happened yet.
	ReasonNone Reason = ""

	// ReasonVerified is recorded on a step that succeeded, so a trace reads
	// as a sequence of positive statements rather than a sequence of blanks.
	ReasonVerified Reason = "verified"
)

// Structural problems with the data offered for validation. These are about
// the shape of the input, before any cryptography is attempted.
const (
	// ReasonEmptyRRset: an RRset with no records was offered. There is
	// nothing to authenticate, and signing nothing is not meaningful.
	ReasonEmptyRRset Reason = "empty_rrset"

	// ReasonInconsistentRRset: the records offered do not share one owner
	// name, class and type, so they are not an RRset at all (RFC 2181 §5,
	// R-SET-01). Validating them as one would authenticate a set the signer
	// never signed.
	ReasonInconsistentRRset Reason = "inconsistent_rrset"

	// ReasonMalformedRecord: a record could not be parsed, packed or
	// otherwise handled as the type it claims to be.
	ReasonMalformedRecord Reason = "malformed_record"

	// ReasonMissingRRSIG: the RRset carries no RRSIG at all. Distinct from
	// every signature failing, which is ReasonSignatureCryptoFailed and means
	// something quite different about who is at fault.
	ReasonMissingRRSIG Reason = "missing_rrsig"

	// ReasonMissingDNSKEY: the zone's apex DNSKEY RRset was not available, so
	// no key could be selected.
	ReasonMissingDNSKEY Reason = "missing_dnskey"

	// ReasonMissingDS: no DS record was available for a delegation that the
	// chain walk needed to cross.
	ReasonMissingDS Reason = "missing_ds"
)

// RRSIG admissibility, per RFC 4035 §5.3.1. These are the checks that decide
// whether a signature is even eligible to be verified; failing one means the
// RRSIG does not apply, not that the cryptography is wrong.
const (
	// ReasonOwnerMismatch: R-SIG-01. The RRSIG and the RRset differ in owner
	// name or class.
	ReasonOwnerMismatch Reason = "owner_mismatch"

	// ReasonTypeCoveredMismatch: R-SIG-03. The RRSIG covers a different type.
	ReasonTypeCoveredMismatch Reason = "type_covered_mismatch"

	// ReasonLabelsMismatch: R-SIG-04. The owner name has fewer labels than
	// the RRSIG's Labels field claims.
	ReasonLabelsMismatch Reason = "labels_mismatch"

	// ReasonSignerNotZone: R-SIG-02. The Signer's Name is not the zone that
	// contains the RRset. This is the check that stops a zone signing data it
	// has no authority over — a name in one zone must not be authenticated by
	// a key belonging to an unrelated one.
	ReasonSignerNotZone Reason = "signer_not_zone"

	// ReasonSignatureExpired: R-SIG-05.
	ReasonSignatureExpired Reason = "signature_expired"

	// ReasonSignatureNotYetValid: R-SIG-06.
	ReasonSignatureNotYetValid Reason = "signature_not_yet_valid"

	// ReasonNoMatchingKey: R-SIG-07. No DNSKEY in the apex RRset matches the
	// RRSIG's Signer's Name, Algorithm and Key Tag together.
	ReasonNoMatchingKey Reason = "no_matching_key"

	// ReasonSignatureCryptoFailed: R-SIG-09. The signature was admissible and
	// the arithmetic said no.
	ReasonSignatureCryptoFailed Reason = "signature_crypto_failed"
)

// DNSKEY problems, per RFC 4034 §2.1.
const (
	// ReasonKeyNotZoneKey: R-KEY-02 / R-SIG-08. The Zone flag (bit 7) is not
	// set, so this key may not sign zone data.
	ReasonKeyNotZoneKey Reason = "key_not_zone_key"

	// ReasonKeyBadProtocol: R-KEY-01. The Protocol field is not 3, and
	// RFC 4034 §2.1.2 says such a DNSKEY "MUST be treated as invalid during
	// signature verification".
	ReasonKeyBadProtocol Reason = "key_bad_protocol"

	// ReasonKeyMalformed: the public key material could not be decoded as the
	// algorithm it claims — wrong length, bad point, unusable exponent.
	ReasonKeyMalformed Reason = "key_malformed"
)

// Delegation Signer problems, per RFC 4034 §5.1.
const (
	// ReasonDSDigestMismatch: R-DS-03. A DS matched a DNSKEY on key tag and
	// algorithm, and the recomputed digest disagreed. This is the one that
	// catches a substituted key, so it is deliberately distinct from "no DS
	// referred to this key at all".
	ReasonDSDigestMismatch Reason = "ds_digest_mismatch"

	// ReasonNoDSMatchedKey: no DS at the delegation referred to any DNSKEY in
	// the child's apex RRset by tag and algorithm.
	ReasonNoDSMatchedKey Reason = "no_ds_matched_key"
)

// Algorithm and digest handling. Support and permission are separate
// questions with separate reasons, because RFC 9905 §2 places contradictory
// obligations on implementations and operators for the same algorithm: an
// implementation "MUST continue to support validation using these algorithms"
// while an operator "MUST treat [them] as unsupported". Collapsing the two
// into one reason makes it impossible to tell which obligation is in play.
const (
	// ReasonUnsupportedAlgorithm: this build has no verifier for the
	// algorithm. A statement about Daddybound.
	ReasonUnsupportedAlgorithm Reason = "unsupported_algorithm"

	// ReasonDisallowedAlgorithm: a verifier exists and policy refuses to rely
	// on it. A statement about the operator's configuration.
	ReasonDisallowedAlgorithm Reason = "disallowed_algorithm"

	// ReasonUnsupportedDigest: this build cannot compute the DS digest type.
	ReasonUnsupportedDigest Reason = "unsupported_digest"

	// ReasonDisallowedDigest: the digest type can be computed and policy
	// refuses to rely on it.
	ReasonDisallowedDigest Reason = "disallowed_digest"
)

// Trust anchor problems.
const (
	// ReasonNoTrustAnchor: no configured trust anchor covers the name being
	// validated, so there is nowhere to start. RFC 4033 §5 calls this the
	// default operation mode, and it maps to Indeterminate.
	ReasonNoTrustAnchor Reason = "no_trust_anchor"

	// ReasonTrustAnchorMismatch: a trust anchor covers the name and no
	// DNSKEY at that point matched it. The chain is broken at the root of
	// the walk rather than somewhere in the middle.
	ReasonTrustAnchorMismatch Reason = "trust_anchor_mismatch"
)

// Limits of this milestone, and limits of any single validation run. These
// exist so that "we did not do this" never has to be disguised as a verdict.
const (
	// ReasonDenialNotImplemented: reaching the correct answer needs a
	// denial-of-existence proof (NSEC or NSEC3), which v0.1 does not
	// implement. Returned with StatusIndeterminate. This is the reason that
	// keeps Daddybound honest about the gap described in
	// docs/daddybound/standards.md §5.3.
	ReasonDenialNotImplemented Reason = "denial_not_implemented"

	// ReasonResourceLimit: validation stopped because it hit a configured
	// bound on work — chain depth, records considered, signatures verified.
	// Stopping is the correct behaviour; claiming a verdict afterwards is
	// not.
	ReasonResourceLimit Reason = "resource_limit"

	// ReasonCancelled: the caller's context ended before validation finished.
	ReasonCancelled Reason = "cancelled"

	// ReasonUnknown is for a failure this taxonomy genuinely does not
	// describe. It is a real value with a real meaning — "something went
	// wrong and Daddybound cannot characterise it" — and it must map to
	// Indeterminate, never to a verdict. If it starts appearing in traces,
	// that is a signal to extend the taxonomy, not to widen an existing
	// reason until it fits.
	ReasonUnknown Reason = "unknown"
)

// explanations maps each Reason to a sentence for humans. The map is
// deliberately one-directional: text is generated from reasons and never
// parsed back into them.
var explanations = map[Reason]string{
	ReasonNone:     "nothing to report",
	ReasonVerified: "verified",

	ReasonEmptyRRset:        "the RRset contained no records",
	ReasonInconsistentRRset: "the records do not share one owner name, class and type, so they are not a single RRset",
	ReasonMalformedRecord:   "a record could not be handled as the type it claims to be",
	ReasonMissingRRSIG:      "the RRset carries no signature",
	ReasonMissingDNSKEY:     "the zone's apex DNSKEY RRset was not available",
	ReasonMissingDS:         "no DS record was available for this delegation",

	ReasonOwnerMismatch:         "the signature's owner name or class does not match the RRset",
	ReasonTypeCoveredMismatch:   "the signature covers a different record type",
	ReasonLabelsMismatch:        "the owner name has fewer labels than the signature claims",
	ReasonSignerNotZone:         "the signer's name is not the zone that contains this RRset",
	ReasonSignatureExpired:      "the signature expired",
	ReasonSignatureNotYetValid:  "the signature is not valid yet",
	ReasonNoMatchingKey:         "no key in the zone's apex DNSKEY RRset matches this signature's signer, algorithm and key tag",
	ReasonSignatureCryptoFailed: "the signature did not verify against the key",

	ReasonKeyNotZoneKey:  "the key is not marked as a zone key, so it may not sign zone data",
	ReasonKeyBadProtocol: "the key's protocol field is not 3",
	ReasonKeyMalformed:   "the key material could not be decoded for its algorithm",

	ReasonDSDigestMismatch: "the delegation's digest does not match the key it refers to",
	ReasonNoDSMatchedKey:   "no delegation record refers to any key in the child zone",

	ReasonUnsupportedAlgorithm: "this build cannot verify that signature algorithm",
	ReasonDisallowedAlgorithm:  "policy does not permit relying on that signature algorithm",
	ReasonUnsupportedDigest:    "this build cannot compute that delegation digest type",
	ReasonDisallowedDigest:     "policy does not permit relying on that delegation digest type",

	ReasonNoTrustAnchor:       "no configured trust anchor covers this name",
	ReasonTrustAnchorMismatch: "no key at the trust anchor's name matched the configured anchor",

	ReasonDenialNotImplemented: "answering this needs a proof of non-existence, which this version does not implement",
	ReasonResourceLimit:        "validation stopped at a configured limit before reaching an answer",
	ReasonCancelled:            "validation was cancelled before it finished",
	ReasonUnknown:              "validation failed in a way this validator cannot characterise",
}

// Explain returns a sentence describing r, for humans.
//
// A Reason with no entry returns the wording for ReasonUnknown rather than
// echoing the raw value, so an unexplained reason reads as an admission
// instead of as a leaked identifier.
func (r Reason) Explain() string {
	if s, ok := explanations[r]; ok {
		return s
	}
	return explanations[ReasonUnknown]
}

// String returns the stable identifier.
func (r Reason) String() string { return string(r) }

// Known reports whether r is a reason this package defines. Used by tests to
// stop a typo'd literal from silently becoming a new category.
func (r Reason) Known() bool {
	_, ok := explanations[r]
	return ok
}

// aboutValidator reports whether r describes a limitation of this validator
// rather than a fault in the data.
//
// The distinction decides a verdict, which is why it is a method on Reason
// and not a judgement made at each call site. RFC 4033 §5 licenses Bogus only
// where "the response fails to validate" — an accusation about the data. When
// the response is fine and Daddybound simply cannot check it, saying Bogus
// blames a correctly signed zone for this binary's build options or this
// operator's policy.
//
// RFC 6840 makes the same point twice for the algorithm cases, in §5.3 for
// signature algorithms and §5.2 for DS digests: where nothing usable is left,
// "the zone is treated as if it were unsigned". A complete validator reports
// Insecure there. v0.1 cannot, because Insecure needs a signed proof of
// non-existence and v0.1 implements none, so it reports Indeterminate with
// the specific reason — a weaker claim than the RFC's, and an honest one.
// docs/daddybound/standards.md §5.3 records that gap.
func (r Reason) aboutValidator() bool {
	switch r {
	case ReasonUnsupportedAlgorithm, ReasonDisallowedAlgorithm,
		ReasonUnsupportedDigest, ReasonDisallowedDigest,
		ReasonDenialNotImplemented, ReasonResourceLimit,
		ReasonCancelled, ReasonUnknown:
		return true
	default:
		return false
	}
}
