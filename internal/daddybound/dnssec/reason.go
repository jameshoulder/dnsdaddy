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

// Authenticated denial of existence, per RFC 4035 §5.4 and RFC 6840 §4.
//
// These are separate reasons rather than one "denial failed" because they
// describe genuinely different situations, and two of them decide a verdict.
// A response that supplied no proof at all is a different accusation from one
// that supplied a proof of the wrong thing, and a proof that contradicts the
// server's own rcode is different again.
const (
	// ReasonNoDenialProof: a proof of non-existence was required and the
	// response carried no authenticated NSEC or NSEC3 records capable of
	// supplying one. R-DEN-01.
	ReasonNoDenialProof Reason = "no_denial_proof"

	// ReasonDenialIncomplete: denial records were present and authenticated,
	// and together they do not establish what the response claims. The
	// commonest case by far is an NXDOMAIN that proves the queried name is
	// missing but never proves that no wildcard could have answered
	// (R-DEN-05), which is the half-proof an attacker would supply.
	ReasonDenialIncomplete Reason = "denial_incomplete"

	// ReasonDenialContradicted: an authenticated NSEC says the very thing
	// the response denies is present — the queried type is in the bitmap of
	// the NSEC that matches the name, or a CNAME is (R-DEN-02, R-DEN-03).
	// The zone's own signed records contradict the answer it was sent with.
	ReasonDenialContradicted Reason = "denial_contradicted"

	// ReasonAliasAmbiguous: more than one CNAME at a name. RFC 2181 §10.1
	// forbids a CNAME coexisting with other data, and a fortiori with a
	// second CNAME; following one of them would mean choosing a target out
	// of a response an attacker ordered.
	ReasonAliasAmbiguous Reason = "alias_ambiguous"

	// ReasonDnameNoMatch: a DNAME was offered for a name its owner does not
	// cover. Only whole labels are replaced (RFC 6672 §2.2), so a name that
	// merely ends in the owner's characters is not redirected by it.
	ReasonDnameNoMatch Reason = "dname_no_match"

	// ReasonDnameTooLong: the DNAME substitution would produce a name longer
	// than the DNS allows. RFC 6672 §2.2 has a server answer YXDOMAIN; there
	// is nothing to authenticate about a name that cannot exist.
	ReasonDnameTooLong Reason = "dname_too_long"

	// ReasonAnyNotProvable: an empty answer to a QTYPE=* query. No NSEC or
	// NSEC3 type bitmap can deny type 255, because no record has that type,
	// so there is no proof to check rather than a proof that failed. A
	// statement about what is provable, not about the zone.
	ReasonAnyNotProvable Reason = "any_not_provable"

	// ReasonDenialOptOutSpan: the name whose non-existence the proof depends
	// on falls inside an Opt-Out span, and RFC 5155 §12.2 states plainly what
	// that costs — "the loss of the ability to prove the existence or
	// nonexistence of an insecure delegation within the span of an Opt-Out
	// NSEC3 RR".
	//
	// The proof is not broken and the zone is not accused of anything: the
	// records verify and the shape is the one §8.4 asks for. What is missing
	// is the conclusion. §7.1 lets a signer omit only unsigned delegations
	// from the chain, so a name inside such a span either does not exist or
	// is unsigned, and §12.2's first paragraph settles which verdict that is:
	// "All unsigned names are, by definition, insecure."
	//
	// So this reason carries Insecure rather than Bogus or Indeterminate, and
	// it is the only reason in this taxonomy that does.
	ReasonDenialOptOutSpan Reason = "denial_opt_out_span"

	// ReasonAliasLoop: the alias chain returns to a name it already visited.
	// The records may all be authentic — the zone published a loop — so this
	// is a statement about the data's shape rather than its authenticity.
	ReasonAliasLoop Reason = "alias_loop"

	// ReasonDenialWrongZone: an NSEC was offered as proof of something it is
	// not entitled to prove — an ancestor delegation NSEC used below its own
	// zone cut (R-DEN-06), an NSEC with the DNAME bit used to deny a
	// subdomain (R-DEN-07), or the child's apex NSEC offered as proof that
	// no DS exists, when only the parent's may be used (R-DEN-09).
	//
	// This one is worth its own value because the signature on such a record
	// is perfectly good. The record is real, the zone really signed it, and
	// it simply does not say what it is being used to say. A validator that
	// reported this as an ordinary signature failure would send an
	// investigator looking at the cryptography.
	ReasonDenialWrongZone Reason = "denial_wrong_zone"
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

	ReasonAliasAmbiguous:   "more than one CNAME exists at this name, so there is no single target to follow",
	ReasonAliasLoop:        "the alias chain returns to a name it has already visited",
	ReasonAnyNotProvable:   "an empty answer to a QTYPE=ANY query cannot be authenticated: no NSEC or NSEC3 type bitmap can deny type ANY",
	ReasonDenialOptOutSpan: "the name is inside an Opt-Out span, within which RFC 5155 §12.2 says non-existence cannot be proved; every name in such a span is unsigned",
	ReasonDnameNoMatch:     "the DNAME offered does not cover the queried name",
	ReasonDnameTooLong:     "the DNAME substitution would produce a name longer than the DNS allows",

	ReasonNoDenialProof:      "the response carried no authenticated proof that the name or type does not exist",
	ReasonDenialIncomplete:   "the denial records do not prove everything the response claims; commonly the wildcard denial is missing",
	ReasonDenialContradicted: "the zone's own signed denial records say the name or type does exist",
	ReasonDenialWrongZone:    "a denial record was offered as proof of something its zone has no authority to state",

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
// Insecure there. This one reports Indeterminate instead, and the difference
// is deliberate rather than a missing feature: Insecure is a claim that the
// data was *proved* unsigned, and the proof this validator has is an
// authenticated absence of DS at a delegation. Nothing proves a zone unsigned
// merely because this build cannot read its algorithm — the zone is signed,
// and saying otherwise would let a build option decide what a zone published.
// Indeterminate with the specific reason is the weaker and honest claim.
// docs/daddybound/standards.md §5.3 records it.
func (r Reason) aboutValidator() bool {
	switch r {
	case ReasonUnsupportedAlgorithm, ReasonDisallowedAlgorithm,
		ReasonUnsupportedDigest, ReasonDisallowedDigest,
		ReasonDenialNotImplemented, ReasonResourceLimit,
		ReasonAnyNotProvable,
		ReasonCancelled, ReasonUnknown:
		return true
	default:
		return false
	}
}
