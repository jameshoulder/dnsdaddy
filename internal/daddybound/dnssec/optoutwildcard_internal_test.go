package dnssec

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestAWildcardAnswerOverAnOptOutSpanIsNotProved is the second arm of
// R-N3-13, and RFC 5155 §12.2 names this case in as many words:
//
//	In particular, this means that a malicious entity may be able to insert
//	or delete RRs with unsigned names.  These RRs are normally NS RRs, but
//	this also includes signed wildcard expansions (while the wildcard RR
//	itself is signed, its expanded name is an unsigned name).
//
// The signature on a wildcard-expanded answer is genuine; what §8.8's extra
// proof is for is establishing that no closer name existed to answer instead.
// Over an Opt-Out span that is exactly what cannot be established, so the
// answer is Insecure rather than Secure — the records are authentic, and the
// expansion is not shown to have been the right thing to do.
//
// Built at the record level rather than through the lab. The lab's wildcard
// lives in a zone that does not use opt-out, and moving it would change the
// fixture every other NSEC3 scenario is written against; a set constructed
// here isolates the one rule under test and states its inputs in the open.
func TestAWildcardAnswerOverAnOptOutSpanIsNotProved(t *testing.T) {
	const zone = "example."
	// The answer is at a.b.example., expanded from *.b.example. (three
	// labels signed), so the next closer name is a.b.example. itself.
	const qname = "a.b.example."
	const expandedFrom = 2 // "*.b.example." has 2 labels beside the wildcard

	closer, ok := nextCloser(qname, ancestorWithLabels(qname, expandedFrom))
	if !ok {
		t.Fatalf("no next closer name for %s", qname)
	}

	set := func(flags uint8) *nsec3Set {
		return &nsec3Set{
			zone:    zone,
			alg:     NSEC3HashSHA1,
			budget:  &hashBudget{remaining: 128},
			records: []authenticNSEC3{covering(t, zone, closer, flags)},
		}
	}

	// Without the flag the proof is complete: the span asserts that nothing
	// lies inside it, so the expansion was legitimate.
	if reason := set(0).proveWildcardAnswer(qname, expandedFrom); reason != ReasonNone {
		t.Fatalf("a plain covering record failed the proof: %s", reason)
	}

	// The same record with the Opt-Out bit set asserts nothing about the
	// names inside it, so the same proof establishes nothing.
	if reason := set(1).proveWildcardAnswer(qname, expandedFrom); reason != ReasonDenialOptOutSpan {
		t.Fatalf("reason = %s, want %s: an Opt-Out span cannot rule out a closer match",
			reason, ReasonDenialOptOutSpan)
	}
}

// TestAWildcardNoDataOverAnOptOutSpanIsNotProved is the third arm of
// R-N3-13, RFC 5155 §8.7.
//
// A wildcard NODATA response says two things: that QNAME does not exist, so a
// wildcard was the right thing to consult, and that the wildcard has no data
// of the queried type. The second half is proved by a matching NSEC3 at the
// wildcard. The first half is a closest encloser proof — and over an Opt-Out
// span that half is not proved, so the response's account of itself is not
// established even though every record in it verifies.
//
// Without this arm the engine would report Secure for a NODATA whose whole
// premise — that no closer name existed — rests on a span RFC 5155 §12.2 says
// proves no such thing.
func TestAWildcardNoDataOverAnOptOutSpanIsNotProved(t *testing.T) {
	const zone = "example."
	const qname = "a.b.example."
	const encloser = "b.example."

	build := func(flags uint8) *nsec3Set {
		return &nsec3Set{
			zone:   zone,
			alg:    NSEC3HashSHA1,
			budget: &hashBudget{remaining: 128},
			records: []authenticNSEC3{
				// The closest encloser exists...
				matching(t, zone, encloser, []uint16{dns.TypeA, dns.TypeRRSIG}),
				// ...the next closer name does not...
				covering(t, zone, qname, flags),
				// ...and the wildcard exists without the queried type.
				matching(t, zone, "*."+encloser, []uint16{dns.TypeTXT, dns.TypeRRSIG}),
			},
		}
	}

	if reason := build(0).proveNoData(qname, dns.TypeA); reason != ReasonNone {
		t.Fatalf("a plain covering record failed the wildcard NODATA proof: %s", reason)
	}
	if reason := build(1).proveNoData(qname, dns.TypeA); reason != ReasonDenialOptOutSpan {
		t.Fatalf("reason = %s, want %s: an Opt-Out span cannot establish that QNAME was absent",
			reason, ReasonDenialOptOutSpan)
	}
}

// matching builds an authentic NSEC3 record whose owner is name's hash, so it
// matches name rather than covering it.
func matching(t *testing.T, zone, name string, types []uint16) authenticNSEC3 {
	t.Helper()
	hash := strings.ToUpper(dns.HashName(dns.CanonicalName(name), dns.SHA1, 0, ""))
	rr := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name: strings.ToLower(hash) + "." + zone, Rrtype: dns.TypeNSEC3,
			Class: dns.ClassINET, Ttl: 3600,
		},
		Hash: dns.SHA1, Flags: 0, Iterations: 0, SaltLength: 0,
		// The interval is deliberately the smallest one that exists: the
		// next hash after this record's own. A matching record is consulted
		// for its bitmap, not its span, and giving it the whole zone — which
		// is what owner == next means — would make it cover the very names
		// the covering record below is meant to cover, silently deciding
		// which record answers "is this name absent". That happened while
		// this test was being written: the opt-out flag was read off the
		// wrong record and the test passed with the rule removed.
		NextDomain: bump(hash), HashLength: 20,
		TypeBitMap: types,
	}
	return authenticNSEC3{rr: rr, signer: zone, hash: hash, zone: zone}
}

// covering builds an authentic NSEC3 record whose interval contains name's
// hash, with the given flags.
//
// The interval is derived from the hash rather than written down, so the
// record covers the name by construction and the test cannot quietly stop
// covering it if the hashing changes.
func covering(t *testing.T, zone, name string, flags uint8) authenticNSEC3 {
	t.Helper()
	hash := strings.ToUpper(dns.HashName(dns.CanonicalName(name), dns.SHA1, 0, ""))
	owner, next := neighbours(hash)
	rr := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name: strings.ToLower(owner) + "." + zone, Rrtype: dns.TypeNSEC3,
			Class: dns.ClassINET, Ttl: 3600,
		},
		Hash: dns.SHA1, Flags: flags, Iterations: 0, SaltLength: 0,
		NextDomain: next, HashLength: 20,
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
	}
	return authenticNSEC3{rr: rr, signer: zone, hash: owner, zone: zone}
}

// bump returns the base32hex string one greater than h, so that a record
// owning h spans nothing.
func bump(h string) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	out := []byte(h)
	for i := len(out) - 1; i >= 0; i-- {
		idx := strings.IndexByte(alphabet, out[i])
		if idx < 0 {
			return h
		}
		if idx+1 < len(alphabet) {
			out[i] = alphabet[idx+1]
			return string(out)
		}
		out[i] = alphabet[0] // carry
	}
	return string(out)
}

// neighbours returns two base32hex hashes that strictly bracket h.
func neighbours(h string) (before, after string) {
	// The alphabet is "0123456789ABCDEFGHIJKLMNOPQRSTUV", so a hash with its
	// first character replaced by '0' sorts at or before h and one with 'V'
	// sorts at or after it. Making the first differ and the rest extreme
	// keeps both strictly outside.
	return "0" + strings.Repeat("0", len(h)-1), "V" + strings.Repeat("V", len(h)-1)
}
