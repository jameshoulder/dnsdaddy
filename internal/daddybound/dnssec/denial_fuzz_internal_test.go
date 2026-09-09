package dnssec

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Fuzz targets for the denial primitives.
//
// These reason over records an attacker supplies, so the properties worth
// asserting are the ones that hold no matter what arrives: the reasoning
// terminates, it never panics, and where it produces a name that name is one
// it was entitled to produce. Correctness of a specific proof is a scenario's
// job; this is about the shapes nobody thought to write down.
//
// Panics matter more here than in most code. A denial proof is parsed from
// hostile input on every negative answer, and a panic in a resolver is a
// remote crash rather than a stack trace someone reads later.

// FuzzCanonicalNameOrderIsATotalOrder checks the property every interval
// argument silently depends on.
//
// If the ordering is not a total order, "sorts between these two names" means
// nothing, and an NSEC interval can be made to include or exclude a name
// depending on which comparison happens first.
func FuzzCanonicalNameOrderIsATotalOrder(f *testing.F) {
	f.Add("example.", "a.example.", "z.example.")
	f.Add(".", "example.", "example.example.")
	f.Add("*.example.", "\\000.example.", "\\255.example.")
	f.Add("A.EXAMPLE.", "a.example.", "b.example.")
	f.Add(strings.Repeat("a", 64)+".example.", "example.", ".")

	f.Fuzz(func(t *testing.T, a, b, c string) {
		ab := compareCanonicalNames(a, b)
		ba := compareCanonicalNames(b, a)

		// Antisymmetry. Without it a sort is undefined and two validators
		// reading the same chain can disagree about what it covers.
		if sign(ab) != -sign(ba) {
			t.Fatalf("antisymmetry: cmp(%q,%q)=%d but cmp(%q,%q)=%d", a, b, ab, b, a, ba)
		}
		if compareCanonicalNames(a, a) != 0 {
			t.Fatalf("reflexivity: %q does not equal itself", a)
		}

		// Transitivity, on the orderings the three inputs happen to give.
		bc := compareCanonicalNames(b, c)
		ac := compareCanonicalNames(a, c)
		if ab <= 0 && bc <= 0 && ac > 0 {
			t.Fatalf("transitivity: %q <= %q <= %q but %q > %q", a, b, c, a, c)
		}
		if ab >= 0 && bc >= 0 && ac < 0 {
			t.Fatalf("transitivity: %q >= %q >= %q but %q < %q", a, b, c, a, c)
		}
	})
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// FuzzNameInIntervalNeverClaimsTheOwner checks the one thing NSEC interval
// coverage must never do.
//
// An NSEC asserts that nothing exists *strictly* between its owner and its
// next name. A record that covered its own owner name would prove the
// non-existence of a name the zone just published, which is a signed
// contradiction and, read the wrong way round, a denial of existing data.
func FuzzNameInIntervalNeverClaimsTheOwner(f *testing.F) {
	f.Add("b.example.", "a.example.", "c.example.")
	f.Add("a.example.", "z.example.", "a.example.")
	f.Add("example.", "example.", "example.")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, qname, owner, next string) {
		if nameInInterval(owner, owner, next) {
			t.Fatalf("an NSEC at %q (next %q) covered its own owner name", owner, next)
		}
		// Terminates and does not panic for anything at all; the result is
		// only meaningful for names the ordering can place.
		_ = nameInInterval(qname, owner, next)
	})
}

// FuzzNSEC3HashNeverPanics feeds arbitrary names, salts and iteration counts
// through the hash.
//
// The iteration count is capped inside the target rather than at the caller,
// because the fuzzer will otherwise spend every run computing 65535 SHA-1
// rounds and never reach a second input. The bound the real code applies is
// tested from the outside, in denial_resource_test.go.
func FuzzNSEC3HashNeverPanics(f *testing.F) {
	f.Add("example.", uint16(0), []byte(nil))
	f.Add("*.a.example.", uint16(12), []byte{0xaa, 0xbb, 0xcc, 0xdd})
	f.Add("", uint16(1), []byte{0})
	f.Add(strings.Repeat("a.", 200)+"example.", uint16(3), []byte{0xff})

	f.Fuzz(func(t *testing.T, name string, iterations uint16, salt []byte) {
		if iterations > 64 {
			iterations = 64
		}
		first, ok := nsec3Hash(name, NSEC3HashSHA1, iterations, salt)
		second, ok2 := nsec3Hash(name, NSEC3HashSHA1, iterations, salt)
		if ok != ok2 || first != second {
			t.Fatalf("hashing %q is not deterministic: %q/%v then %q/%v", name, first, ok, second, ok2)
		}
		if ok {
			// Base32hex of a SHA-1 digest: twenty octets in five-bit
			// groups. A different length means the encoding changed under
			// us, and every interval comparison is a string comparison.
			if len(first) != 32 {
				t.Fatalf("hash of %q is %d characters, want 32", name, len(first))
			}
			if strings.ToUpper(first) != first {
				t.Fatalf("hash of %q is not upper-case: %q", name, first)
			}
		}
	})
}

// FuzzNSEC3ProofsNeverPanic drives the proof functions with arbitrary NSEC3
// records.
//
// The records here are not authenticated and could not be — that is the
// point. What is under test is the reasoning, which must survive nonsense
// intervals, empty bitmaps, self-referential next names and hashes that
// belong to nothing, without crashing and without looping.
func FuzzNSEC3ProofsNeverPanic(f *testing.F) {
	f.Add("nope.example.", "example.", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", uint8(0), uint16(1))
	f.Add("a.b.c.example.", "example.", "", "", uint8(1), uint16(43))
	f.Add("", "", "", "", uint8(255), uint16(0))

	f.Fuzz(func(t *testing.T, qname, zone, ownerHash, nextHash string, flags uint8, rrtype uint16) {
		rr := &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name: "x." + dns.CanonicalName(zone), Rrtype: dns.TypeNSEC3,
				Class: dns.ClassINET, Ttl: 3600,
			},
			Hash:       NSEC3HashSHA1,
			Flags:      flags,
			Iterations: 0,
			NextDomain: nextHash,
			TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
		}
		second, ok := dns.Copy(rr).(*dns.NSEC3)
		if !ok {
			t.Skip()
		}
		second.NextDomain = strings.ToUpper(ownerHash)
		second.TypeBitMap = []uint16{dns.TypeSOA}
		second.Flags = flags ^ 0x01

		records := mergeNSEC3ByHash([]authenticNSEC3{
			{rr: rr, signer: dns.CanonicalName(zone),
				hash: strings.ToUpper(ownerHash), zone: dns.CanonicalName(zone)},
			{rr: second, signer: dns.CanonicalName(zone),
				hash: strings.ToUpper(ownerHash), zone: dns.CanonicalName(zone)},
		})
		if len(records) != 1 {
			t.Fatalf("two records at one hash merged into %d, want 1", len(records))
		}
		// Opt-out merges by conjunction: a group is opt-out only if every
		// record in it says so, because the flag permits a conclusion.
		if optOut(records[0].rr) && !(optOut(rr) && optOut(second)) {
			t.Fatalf("the merged group claims opt-out that not every record carried")
		}

		set := &nsec3Set{
			records: records,
			zone:    dns.CanonicalName(zone),
			alg:     NSEC3HashSHA1,
			budget:  &hashBudget{remaining: 512},
		}

		// None of these may panic, and none may loop: the encloser walk is
		// bounded by the label count of a name already parsed.
		_ = set.proveNameError(qname)
		_ = set.proveNoData(qname, rrtype)
		// Both rcode branches, because the name-error arm is a different
		// path through the same record set and an input that panics on one
		// of them is no less a panic.
		_ = set.proveNoDS(qname, false)
		_ = set.proveNoDS(qname, true)
		_ = set.proveWildcardAnswer(qname, 1)
	})
}

// FuzzNSECProofsNeverPanic is the same for the NSEC side, where the
// interesting malformed inputs are next names that point backwards, at
// themselves, or out of the zone entirely.
func FuzzNSECProofsNeverPanic(f *testing.F) {
	f.Add("nope.example.", "example.", "a.example.", uint16(1))
	f.Add("a.example.", "z.example.", "a.example.", uint16(2))
	f.Add("", "", "", uint16(0))
	f.Add("x.example.", "x.example.", "x.example.", uint16(43))

	f.Fuzz(func(t *testing.T, qname, owner, next string, rrtype uint16) {
		rr := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name: dns.CanonicalName(owner), Rrtype: dns.TypeNSEC,
				Class: dns.ClassINET, Ttl: 3600,
			},
			NextDomain: dns.CanonicalName(next),
			TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
		}
		// Two records at the same owner, so the merge path is fuzzed too:
		// it is new, it copies records, and it decides what "the record at
		// this name" means for everything downstream.
		second, ok := dns.Copy(rr).(*dns.NSEC)
		if !ok {
			t.Skip()
		}
		second.NextDomain = dns.CanonicalName(qname)
		second.TypeBitMap = []uint16{dns.TypeA}

		merged := mergeNSECByOwner([]authenticNSEC{
			{rr: rr, signer: dns.CanonicalName(owner)},
			{rr: second, signer: dns.CanonicalName(owner)},
		})
		if len(merged) != 1 {
			t.Fatalf("two records at one owner merged into %d, want 1", len(merged))
		}
		proof := &denialProof{nsec: merged}

		_ = proof.proveNameError(qname, rrtype)
		_ = proof.proveNoData(qname, rrtype)
		_ = proof.proveNoDS(qname, false)
		_ = proof.proveNoDS(qname, true)
		_ = proof.proveWildcardAnswer(qname, 1, rrtype)
	})
}

// FuzzClosestEncloserReturnsAnAncestor checks the derivation NSEC's wildcard
// proof rests on.
//
// Whatever record it is given, the name it derives must be an ancestor of the
// queried name. A derivation that wandered elsewhere would have the validator
// demanding the denial of a wildcard under some unrelated name — which the
// response would happily supply, since it is a name nobody protects.
func FuzzClosestEncloserReturnsAnAncestor(f *testing.F) {
	f.Add("x.y.example.", "a.example.", "b.example.")
	f.Add("example.", "example.", "example.")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, qname, owner, next string) {
		rr := &dns.NSEC{
			Hdr:        dns.RR_Header{Name: dns.CanonicalName(owner), Rrtype: dns.TypeNSEC},
			NextDomain: dns.CanonicalName(next),
		}
		got, ok := closestEncloser(qname, authenticNSEC{rr: rr, signer: dns.CanonicalName(owner)})
		if !ok {
			// Refusing is always allowed. What is not allowed is answering
			// with a name that is not an ancestor, because the caller will
			// go on to demand the denial of a wildcard beneath it.
			return
		}
		if got == "" {
			t.Fatalf("closest encloser of %q was accepted but empty, which is not a name", qname)
		}
		if !isSubDomainOf(got, qname) {
			t.Fatalf("closest encloser of %q came back as %q, which is not an ancestor of it", qname, got)
		}
	})
}
