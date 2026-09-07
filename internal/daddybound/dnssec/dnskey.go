package dnssec

import (
	"encoding/base64"

	"github.com/miekg/dns"
)

// DNSKEY flag bits, RFC 4034 §2.1.1.
//
// The RFC numbers bits from the most significant end of the 16-bit field, so
// "bit 7" is 0x0100 and "bit 15" is 0x0001. Writing the masks out with the
// RFC's bit numbers next to them is worth the two lines: transcribing them
// the other way round produces a validator that reads the SEP flag as the
// zone flag, which accepts and rejects exactly the wrong keys.
const (
	// flagZone is bit 7 — "the Zone Key flag" (R-KEY-02).
	flagZone uint16 = 1 << 8
	// flagSEP is bit 15 — "the Secure Entry Point flag" (R-KEY-03).
	// Recorded in traces, never acted on.
	flagSEP uint16 = 1 << 0
	// flagRevoke is bit 8, from RFC 5011 §2.1. v0.1 does not implement
	// RFC 5011 trust anchor rollover, so the bit is observed and reported
	// but no key is treated as revoked on the strength of it — doing so
	// would be implementing half of a protocol whose other half provides
	// the safety.
	flagRevoke uint16 = 1 << 7
)

// keyUsable reports whether a DNSKEY is eligible to verify zone data,
// checking the properties RFC 4034 requires of any signing key.
//
// This is eligibility, not identity: it says nothing about whether the key is
// trusted. A key can pass every check here and still be an attacker's key,
// which is what the DS and trust anchor steps are for.
func keyUsable(k *dns.DNSKEY) Reason {
	// R-KEY-01, RFC 4034 §2.1.2: "The Protocol Field MUST have value 3, and
	// the DNSKEY RR MUST be treated as invalid during signature verification
	// if it is found to be some value other than 3."
	if k.Protocol != 3 {
		return ReasonKeyBadProtocol
	}

	// R-KEY-02 / R-SIG-08: the key must be a zone key to sign zone data.
	if k.Flags&flagZone == 0 {
		return ReasonKeyNotZoneKey
	}

	// The registry's Zone Signing column is consulted rather than assumed:
	// an algorithm marked N there may not sign zone data whatever its flags
	// say.
	if !Algorithm(k.Algorithm).ZoneSigning() {
		return ReasonUnsupportedAlgorithm
	}

	// Deliberately absent: any check of the SEP bit. R-KEY-03, RFC 4034
	// §2.1.1: validators "MUST NOT alter their behavior during the signature
	// validation process in any way based on the setting of this bit", and
	// RFC 6840 §5.10 repeats that "the validation process is specifically
	// prohibited from using that bit".
	//
	// This is worth an explicit note because "the KSK signs the DNSKEY RRset
	// and the ZSK signs everything else" is the usual operational
	// description of DNSSEC, and it is a convention of zone signing rather
	// than a validation rule. A validator that enforces it rejects zones that
	// sign with a single key, which is a legal and reasonably common setup.

	return ReasonNone
}

// keyMaterial decodes a DNSKEY's public key from its base64 presentation.
//
// miekg/dns keeps the key as a base64 string because that is its presentation
// format; everything below the SignatureVerifier boundary works in octets.
func keyMaterial(k *dns.DNSKEY) ([]byte, Reason) {
	// StdEncoding, not RawStdEncoding: DNSKEY presentation format uses
	// padded base64, and accepting the unpadded form as well would mean two
	// spellings of the same key.
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(raw) == 0 {
		return nil, ReasonKeyMalformed
	}
	return raw, ReasonNone
}

// keyStep builds the trace step describing a key, so the same observations
// are recorded the same way wherever a key is examined.
func keyStep(kind StepKind, zone string, k *dns.DNSKEY) ValidationStep {
	step := ValidationStep{
		Kind:      kind,
		Zone:      zone,
		Algorithm: k.Algorithm,
		KeyTag:    k.KeyTag(),
	}
	// The SEP and revoke bits are reported because an operator debugging a
	// zone wants to see them, and withheld from every decision because the
	// standards say they may not influence one.
	switch {
	case k.Flags&flagRevoke != 0:
		step.Note = "revoke bit set (RFC 5011 not implemented; not treated as revoked)"
	case k.Flags&flagSEP != 0:
		step.Note = "SEP bit set (not used in validation)"
	}
	return step
}
