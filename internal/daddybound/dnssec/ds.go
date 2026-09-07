package dnssec

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/miekg/dns"
)

// dsDigest computes the digest a DS record should contain for a given DNSKEY.
//
// RFC 4034 §5.1.4 (R-DS-02):
//
//	digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
//	 "|" denotes concatenation
//	DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
//
// The owner name is in canonical form — down-cased, uncompressed, fully
// qualified. Using the name as it arrived on the wire instead is a defect
// that never shows up in a lab that echoes case exactly, and fails against
// every resolver that randomises query case (0x20 encoding), which is most of
// them. It is exactly the class of bug this project exists to find early.
func dsDigest(digestType DigestType, k *dns.DNSKEY) ([]byte, error) {
	h, ok := digestType.hash()
	if !ok || !h.Available() {
		return nil, errors.New("dnssec: unsupported DS digest type")
	}

	owner := dns.CanonicalName(k.Hdr.Name)
	nameWire := make([]byte, 256)
	n, err := dns.PackDomainName(owner, nameWire, 0, nil, false)
	if err != nil {
		return nil, err
	}

	// The RDATA is taken from a packed copy of the key rather than assembled
	// field by field. Assembling it here would be a second implementation of
	// the DNSKEY wire format inside the same binary, and two implementations
	// of one format is one more than can be kept in agreement.
	keyCopy := dns.Copy(k).(*dns.DNSKEY)
	keyCopy.Hdr.Name = owner
	wire, err := packCanonical(keyCopy)
	if err != nil {
		return nil, err
	}
	rdata, err := rdataOf(wire, keyCopy)
	if err != nil {
		return nil, err
	}

	hasher := h.New()
	hasher.Write(nameWire[:n])
	hasher.Write(rdata)
	return hasher.Sum(nil), nil
}

// dsMatchesKey reports whether a DS record authenticates a DNSKEY, and why
// not when it does not.
//
// R-DS-03: key tag and algorithm select candidates, and the digest decides.
// The two are separated in the returned reason because they mean different
// things operationally. A DS that refers to no key at all usually means a
// stale delegation after a key rollover. A DS that refers to a key by tag and
// algorithm and then disagrees on the digest means the key material is not
// what the parent published — which is either a broken signer or a
// substituted key, and is the case worth being loud about.
func dsMatchesKey(policy Policy, ds *dns.DS, k *dns.DNSKEY) Reason {
	if ds.KeyTag != k.KeyTag() || ds.Algorithm != k.Algorithm {
		return ReasonNoDSMatchedKey
	}

	digestType := DigestType(ds.DigestType)
	if reason := policy.CheckDigest(digestType); reason != ReasonNone {
		return reason
	}

	want, err := hex.DecodeString(ds.Digest)
	if err != nil || len(want) == 0 {
		return ReasonMalformedRecord
	}

	got, err := dsDigest(digestType, k)
	if err != nil {
		return ReasonUnsupportedDigest
	}

	// A plain comparison, not a constant-time one. Both operands are public
	// values published in the DNS: the digest of a public key, against a
	// digest anyone can recompute. There is no secret here for a timing
	// channel to leak, and reaching for subtle.ConstantTimeCompare would
	// suggest to a later reader that there is.
	if !bytes.Equal(want, got) {
		return ReasonDSDigestMismatch
	}
	return ReasonNone
}
