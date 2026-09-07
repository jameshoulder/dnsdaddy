package dnssec

import (
	"time"

	"github.com/miekg/dns"
)

// rrsigAdmissible applies the RFC 4035 §5.3.1 conditions that do not involve
// cryptography: the ones that decide whether this signature even applies to
// this RRset.
//
// Separating admissibility from verification is not tidiness. The two
// failures mean different things — "this signature is about something else"
// versus "this signature is wrong" — and a validator that reports them
// identically cannot explain why a zone failed. It also keeps expensive work
// behind cheap checks, so a malformed RRSIG cannot make Daddybound do
// public-key arithmetic on attacker-chosen input.
//
// The clock is passed in rather than read, because R-SIG-05 and R-SIG-06 are
// defined against "the validator's notion of the current time".
func rrsigAdmissible(set RRset, sig *dns.RRSIG, now time.Time) Reason {
	// R-SIG-01: same owner name and class. Compared in canonical form so
	// that case-randomised answers are not rejected for their casing.
	if dns.CanonicalName(sig.Hdr.Name) != set.Name || sig.Hdr.Class != set.Class {
		return ReasonOwnerMismatch
	}

	// R-SIG-03: the signature covers this type.
	if sig.TypeCovered != set.RRType {
		return ReasonTypeCoveredMismatch
	}

	// R-SIG-04: "The number of labels in the RRset owner name MUST be
	// greater than or equal to the value in the RRSIG RR's Labels field."
	//
	// Greater-than is legal and means wildcard expansion, which is why the
	// check is an inequality rather than equality. A validator that demands
	// equality rejects every wildcard-derived answer.
	if int(sig.Labels) > dns.CountLabel(set.Name) {
		return ReasonLabelsMismatch
	}

	// R-SIG-02: "The RRSIG RR's Signer's Name field MUST be the name of the
	// zone that contains the RRset."
	//
	// v0.1 does not perform recursive resolution and so does not learn zone
	// cuts from delegations. What can be checked without them is that the
	// signer's name is at or above the owner name, which is the property
	// that stops one zone signing another zone's data. A signer that is a
	// strict ancestor but not the containing zone — example.test signing
	// data that actually lives in a delegated sub.example.test — is not
	// caught here and is caught by the chain walk, which validates each zone
	// against its own apex DNSKEY RRset and will find no key for it.
	//
	// Stating the gap rather than implying the check is complete: this is
	// the weakest of the admissibility rules in v0.1, and it is weak because
	// the information needed to make it strong is a recursive resolver.
	if !dns.IsSubDomain(dns.CanonicalName(sig.SignerName), set.Name) {
		return ReasonSignerNotZone
	}

	// R-SIG-05 and R-SIG-06. Both bounds are inclusive in the RFC's wording
	// — "less than or equal to the ... Expiration field", "greater than or
	// equal to the ... Inception field" — so the comparisons are strict in
	// the opposite direction, and a signature is valid on both boundary
	// seconds.
	//
	// The RRSIG timestamps are 32-bit seconds since the epoch, compared with
	// the serial-number arithmetic of RFC 4034 §3.1.5 and RFC 1982. See
	// serialtime.go: the wrap is the specified behaviour, not an overflow to
	// be avoided, and widening to int64 would misjudge signatures near the
	// wrap point.
	nowSerial := DNSSECTime(now)
	if !serialGE(nowSerial, sig.Inception) {
		return ReasonSignatureNotYetValid
	}
	if !serialGE(sig.Expiration, nowSerial) {
		return ReasonSignatureExpired
	}

	return ReasonNone
}

// verifyRRset verifies an RRset against one signature and one key.
//
// By the time it is called, admissibility (rrsigAdmissible) and key
// eligibility (keyUsable) have already passed, and the key has been selected
// by R-SIG-07. What is left is R-SIG-09: build the signed data and check the
// arithmetic.
func verifyRRset(v SignatureVerifier, set RRset, sig *dns.RRSIG, k *dns.DNSKEY) Reason {
	keyBytes, reason := keyMaterial(k)
	if reason != ReasonNone {
		return reason
	}

	sigBytes, err := decodeSignature(sig)
	if err != nil {
		return ReasonMalformedRecord
	}

	signed, err := canonicalSignedData(sig, set.Records)
	if err != nil {
		return ReasonMalformedRecord
	}

	return v.Verify(Algorithm(sig.Algorithm), keyBytes, signed, sigBytes)
}

// candidateKeys returns the keys eligible to have made sig, per R-SIG-07:
// "The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the
// owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex
// DNSKEY RRset."
//
// It returns a slice and not a single key, deliberately. The key tag is a
// 16-bit checksum over the key's RDATA (RFC 4034 Appendix B), not an
// identifier, and nothing forbids two keys in one apex RRset from sharing
// one. An implementation that takes the first match and stops will reject a
// correctly signed zone whenever the collision falls the wrong way — rarely,
// non-reproducibly, and in a way that looks like a network problem.
func candidateKeys(signerName string, sig *dns.RRSIG, keys []*dns.DNSKEY) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, k := range keys {
		if dns.CanonicalName(k.Hdr.Name) != signerName {
			continue
		}
		if k.Algorithm != sig.Algorithm {
			continue
		}
		if k.KeyTag() != sig.KeyTag {
			continue
		}
		out = append(out, k)
	}
	return out
}
