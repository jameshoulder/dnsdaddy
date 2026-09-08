package dnssec

import (
	// #nosec G505 -- NSEC3 is defined over SHA-1 and over nothing else.
	// RFC 5155 §5 defines the owner-name hash as an iterated application of
	// "the Hash Algorithm selected by the NSEC3 RR", and the IANA "DNSSEC
	// NSEC3 Hash Algorithms" registry contains exactly one assigned value:
	// 1, SHA-1. A validator without it cannot read a denial proof from any
	// NSEC3-signed zone on the Internet, which is most of the large ones.
	//
	// It is a preimage barrier here, not a signature. What authenticates an
	// NSEC3 record is the RRSIG over it, verified in the usual way; the hash
	// only decides which name a record is about. A SHA-1 collision — the
	// attack the deprecations are about — buys an attacker nothing, because
	// they would still need a signature over the colliding record from a key
	// in the zone's authenticated DNSKEY RRset.
	//
	// Removing this would not make Daddybound safer. It would make it unable
	// to check the denial proofs of the zones most worth checking.
	"crypto/sha1"
	"encoding/base32"
	"strings"

	"github.com/miekg/dns"
)

// NSEC3 hashing, RFC 5155 §5.
//
// This is protocol logic rather than cryptography: the iteration construction,
// the salt placement and the canonical form of the input are all specified by
// the RFC, and getting any of them wrong produces a hash that names a
// different record. The SHA-1 compression function itself comes from the
// standard library.
//
// It is deliberately not shared with the test lab, which hashes through
// github.com/miekg/dns. Two implementations of one rule, written from the same
// specification but not from each other, is the only cheap way to notice that
// both are wrong in the same way — and a validator whose hashing agreed only
// with its own test fixtures would accept a chain no signer produces.

// NSEC3HashSHA1 is hash algorithm 1, the only value IANA has assigned.
const NSEC3HashSHA1 uint8 = 1

// nsec3Base32 is RFC 4648's "Extended Hex Alphabet", without padding.
//
// The alphabet is not interchangeable with ordinary base32. RFC 5155 §1.3
// depends on this one specifically: "this order is the same as the canonical
// DNS name order specified in [RFC4034], when the hashed owner names are in
// base32, encoded with an Extended Hex Alphabet". Standard base32 does not
// preserve the ordering of the underlying bytes, so an NSEC3 chain read
// through it would appear unsorted and every interval test would be wrong.
var nsec3Base32 = base32.HexEncoding.WithPadding(base32.NoPadding)

// nsec3Hash returns the base32hex-encoded hash of a name, as it appears in an
// NSEC3 owner name.
//
// RFC 5155 §5:
//
//	IH(salt, x, 0) = H(x || salt), and
//	IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0
//
//	Then the calculated hash of an owner name is IH(salt, owner name,
//	iterations), where the owner name is in the canonical form.
//
// Note that iterations = 0 still means one hash, of the name concatenated
// with the salt. Reading the field as a repeat count instead — hashing zero
// times at zero — is an easy misreading that produces a validator agreeing
// with nothing.
//
// The canonical form is the wire format, fully expanded and lower-cased, with
// a wildcard left as its literal "*" label. Hashing the presentation string
// would hash escape sequences rather than the octets they stand for.
func nsec3Hash(name string, alg uint8, iterations uint16, salt []byte) (string, bool) {
	if alg != NSEC3HashSHA1 {
		// RFC 5155 §8.1: "A validator MUST ignore NSEC3 RRs with unknown
		// hash types." Refusing here is how that is enforced, and it is a
		// refusal rather than a guess: no other algorithm is assigned, so
		// there is nothing to fall back to.
		return "", false
	}

	wire := make([]byte, 256)
	n, err := dns.PackDomainName(dns.CanonicalName(name), wire, 0, nil, false)
	if err != nil {
		return "", false
	}

	// #nosec G401 -- see the import comment: RFC 5155 §5 defines the NSEC3
	// owner-name hash as SHA-1, and this is a name lookup rather than a
	// security assertion. SHA-1's collision weakness buys an attacker
	// nothing here: the hash is not a commitment to anything, it is the
	// coordinate a signed NSEC3 record is filed under, and the *record* is
	// what authenticates. Substituting a colliding name would still need a
	// signature over the record naming it.
	//
	// Changing the algorithm is not available either. Hash algorithm 1 is
	// the only value IANA has assigned, and a validator that hashed with
	// anything else would agree with no zone in existence.
	//
	// The nosemgrep must be the last line before the statement: Semgrep
	// honours it only on the matched line or the one immediately above, so
	// an intervening comment line silently disables it. That has already
	// happened in this repository once, to three suppressions at a stroke.
	// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
	digest := sha1.Sum(append(append([]byte{}, wire[:n]...), salt...))
	out := digest[:]

	for i := uint16(0); i < iterations; i++ {
		// #nosec G401 -- as above.
		// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
		next := sha1.Sum(append(append([]byte{}, out...), salt...))
		out = next[:]
	}
	return strings.ToUpper(nsec3Base32.EncodeToString(out)), true
}

// nsec3OwnerHash returns the first label of an NSEC3 owner name, upper-cased,
// together with the zone the rest of the name identifies.
//
// The zone matters as much as the hash. An NSEC3 owner is "the hash of the
// original owner name, prepended as a single label to the zone name"
// (RFC 5155 §7.1), so a record whose remaining labels are some other zone is
// a record from some other zone, however well its hash matches.
func nsec3OwnerHash(owner string) (hash, zone string, ok bool) {
	c := dns.CanonicalName(owner)
	idx := dns.Split(c)
	if len(idx) < 2 {
		// A bare hash with no zone beneath it, or the root. Neither can be
		// an NSEC3 owner name.
		return "", "", false
	}
	label := c[:idx[1]-1]
	if label == "" {
		return "", "", false
	}
	return strings.ToUpper(label), c[idx[1]:], true
}

// nsec3NextHash returns an NSEC3's next hashed owner name, upper-cased.
//
// github.com/miekg/dns exposes the field already base32hex-encoded, so this
// only normalises case. Case matters because the interval comparison is a
// byte comparison and the extended hex alphabet's letters sort after its
// digits only in one case.
func nsec3NextHash(rr *dns.NSEC3) string { return strings.ToUpper(rr.NextDomain) }

// hashInInterval reports whether a hash falls strictly between an NSEC3's
// owner hash and its next hashed owner name.
//
// The same wrap as NSEC: the last record in hash order points back at the
// first, so its owner sorts after its next value and it covers everything
// past the end of the chain.
func hashInInterval(hash, owner, next string) bool {
	switch {
	case owner < next:
		return hash > owner && hash < next
	case owner > next:
		return hash > owner || hash < next
	default:
		// A single-record chain points at itself and covers every hash but
		// its own.
		return hash != owner
	}
}
