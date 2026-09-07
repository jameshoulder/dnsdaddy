package dnssec

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// These tests assert the bytes canonicalisation produces, against the rules
// in RFC 4034 §6 as corrected by RFC 6840 §5.1 — not against what a library
// happens to return. That distinction is the point: signed data is the
// trusted computing base, and a test that only checked "the library was
// called" would still pass if the library's canonical packing changed
// underneath it.

func testSig(owner string, rrtype uint16, labels uint8, origTTL uint32) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: origTTL,
		},
		TypeCovered: rrtype,
		Algorithm:   uint8(AlgED25519),
		Labels:      labels,
		OrigTtl:     origTTL,
		Inception:   1000,
		Expiration:  2000,
		KeyTag:      1234,
		SignerName:  "example.test.",
		Signature:   "AAAA",
	}
}

func aRecord(owner string, ttl uint32, ip string) dns.RR {
	rr, err := dns.NewRR(owner + " " + itoa(uint(ttl)) + " IN A " + ip)
	if err != nil {
		panic(err)
	}
	return rr
}

// R-CANON-02. The TTL inside signed data is the RRSIG's Original TTL, not the
// TTL the record arrived with.
//
// This is the rule whose absence produces a validator that works at the
// instant of signing and fails a second later, because caching decrements
// TTLs. It presents as intermittent network trouble rather than as a bug,
// which is why it gets its own test rather than being covered incidentally.
func TestSignedDataUsesTheOriginalTTLNotTheReceivedOne(t *testing.T) {
	sig := testSig("www.example.test.", dns.TypeA, 3, 3600)

	fresh, err := canonicalSignedData(sig, []dns.RR{aRecord("www.example.test.", 3600, "192.0.2.1")})
	if err != nil {
		t.Fatalf("fresh: %v", err)
	}
	// The same record after sitting in a cache for an hour.
	aged, err := canonicalSignedData(sig, []dns.RR{aRecord("www.example.test.", 7, "192.0.2.1")})
	if err != nil {
		t.Fatalf("aged: %v", err)
	}

	if !bytes.Equal(fresh, aged) {
		t.Errorf("signed data changed when the record's TTL decremented;\n fresh=%x\n aged =%x", fresh, aged)
	}
}

// R-CANON-03. Owner names are down-cased, so a case-randomised answer
// (0x20 encoding, which most deployed resolvers use) produces the same signed
// data as the query the signer signed.
func TestSignedDataDownCasesTheOwnerName(t *testing.T) {
	sig := testSig("www.example.test.", dns.TypeA, 3, 3600)

	lower, err := canonicalSignedData(sig, []dns.RR{aRecord("www.example.test.", 3600, "192.0.2.1")})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	mixed, err := canonicalSignedData(sig, []dns.RR{aRecord("wWw.ExAmPlE.tEsT.", 3600, "192.0.2.1")})
	if err != nil {
		t.Fatalf("mixed: %v", err)
	}

	if !bytes.Equal(lower, mixed) {
		t.Errorf("signed data changed with the owner name's casing;\n lower=%x\n mixed=%x", lower, mixed)
	}
}

// R-CANON-05 and the set semantics of RFC 2181 §5. An RRset is a set, so a
// record arriving twice must produce the same signed data as one arriving
// once — otherwise an on-path attacker could invalidate a correctly signed
// answer just by duplicating a record.
func TestSignedDataIsUnchangedByDuplicatesAndOrder(t *testing.T) {
	sig := testSig("www.example.test.", dns.TypeA, 3, 3600)
	one := aRecord("www.example.test.", 3600, "192.0.2.1")
	two := aRecord("www.example.test.", 3600, "192.0.2.2")

	ordered, err := canonicalSignedData(sig, []dns.RR{one, two})
	if err != nil {
		t.Fatalf("ordered: %v", err)
	}
	shuffled, err := canonicalSignedData(sig, []dns.RR{two, one, one})
	if err != nil {
		t.Fatalf("shuffled: %v", err)
	}

	if !bytes.Equal(ordered, shuffled) {
		t.Errorf("signed data depends on order or duplication;\n ordered =%x\n shuffled=%x", ordered, shuffled)
	}
}

// R-CANON-06 and RFC 4034 §3.1.3. By the time an answer reaches a validator
// the wildcard has already been expanded, and only the RRSIG's Labels field
// reveals that the signer signed *.example.test. Canonical form must put the
// wildcard owner back.
func TestSignedDataRestoresAWildcardOwner(t *testing.T) {
	// Labels=2 for a three-label owner: the signer signed *.example.test.
	expanded := testSig("anything.example.test.", dns.TypeA, 2, 3600)
	viaWildcard, err := canonicalSignedData(expanded, []dns.RR{aRecord("anything.example.test.", 3600, "192.0.2.1")})
	if err != nil {
		t.Fatalf("expanded: %v", err)
	}

	// A different expansion of the same wildcard must produce identical
	// signed data, which is what makes one signature cover every name the
	// wildcard matches.
	other, err := canonicalSignedData(expanded, []dns.RR{aRecord("something-else.example.test.", 3600, "192.0.2.1")})
	if err != nil {
		t.Fatalf("other: %v", err)
	}
	if !bytes.Equal(viaWildcard, other) {
		t.Errorf("two expansions of one wildcard produced different signed data;\n a=%x\n b=%x", viaWildcard, other)
	}

	// And it must differ from a name signed in its own right, or a wildcard
	// signature would authenticate an explicitly signed name.
	explicit := testSig("anything.example.test.", dns.TypeA, 3, 3600)
	direct, err := canonicalSignedData(explicit, []dns.RR{aRecord("anything.example.test.", 3600, "192.0.2.1")})
	if err != nil {
		t.Fatalf("explicit: %v", err)
	}
	if bytes.Equal(viaWildcard, direct) {
		t.Error("wildcard-derived signed data is identical to explicitly signed data")
	}
}

// R-CANON-04 and R-CANON-04a. The set of types whose RDATA names are
// down-cased is enumerated by RFC 4034 §6.2 and corrected by RFC 6840 §5.1.
// Getting the membership wrong produces selective failure: most of a zone
// validates and one record type does not.
func TestRDATADownCasingFollowsTheCorrectedTypeList(t *testing.T) {
	tests := []struct {
		name     string
		rr       dns.RR
		want     string
		contains func(dns.RR) string
	}{
		{
			name:     "MX is in the list",
			rr:       mustRR("example.test. 3600 IN MX 10 MaIl.ExAmPle.TeSt."),
			want:     "mail.example.test.",
			contains: func(rr dns.RR) string { return rr.(*dns.MX).Mx },
		},
		{
			name:     "NS is in the list",
			rr:       mustRR("example.test. 3600 IN NS Ns1.ExAmPle.TeSt."),
			want:     "ns1.example.test.",
			contains: func(rr dns.RR) string { return rr.(*dns.NS).Ns },
		},
		{
			name:     "SOA is in the list, both names",
			rr:       mustRR("example.test. 3600 IN SOA Ns1.ExAmPle.TeSt. HoStMaster.ExAmPle.TeSt. 1 2 3 4 5"),
			want:     "ns1.example.test.",
			contains: func(rr dns.RR) string { return rr.(*dns.SOA).Ns },
		},
		{
			// RFC 6840 §5.1: "DNS names in the RDATA section of RRSIG
			// resource records are converted to lowercase."
			name:     "RRSIG signer name is down-cased",
			rr:       mustRR("example.test. 3600 IN RRSIG A 15 2 3600 20260101000000 20250101000000 1234 ExAmPle.TeSt. AAAA"),
			want:     "example.test.",
			contains: func(rr dns.RR) string { return rr.(*dns.RRSIG).SignerName },
		},
		{
			// RFC 6840 §5.1: "DNS names in the RDATA section of NSEC
			// resource records are not converted to lowercase." RFC 4034
			// said they were; following RFC 4034 literally here declares
			// correctly signed zones bogus.
			name:     "NSEC next-domain is NOT down-cased",
			rr:       mustRR("example.test. 3600 IN NSEC NeXt.ExAmPle.TeSt. A RRSIG NSEC"),
			want:     "NeXt.ExAmPle.TeSt.",
			contains: func(rr dns.RR) string { return rr.(*dns.NSEC).NextDomain },
		},
		{
			// RFC 6840 §5.1: HINFO "records contain no domain names, [so]
			// they are not subject to case conversion." RFC 4034 lists it
			// twice, in error.
			name:     "HINFO fields are untouched",
			rr:       mustRR(`example.test. 3600 IN HINFO "MiXeD" "CaSe"`),
			want:     "MiXeD",
			contains: func(rr dns.RR) string { return rr.(*dns.HINFO).Cpu },
		},
		{
			// SVCB postdates RFC 4034 and is not in the enumeration.
			// Inventing membership would produce signed data no signer ever
			// signed.
			name:     "SVCB target is not in the enumerated list",
			rr:       mustRR("example.test. 3600 IN SVCB 1 TaRgEt.ExAmPle.TeSt."),
			want:     "TaRgEt.ExAmPle.TeSt.",
			contains: func(rr dns.RR) string { return rr.(*dns.SVCB).Target },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := dns.Copy(tc.rr)
			downcaseRDATANames(c)
			if got := tc.contains(c); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The owner name is down-cased for every type, including the ones whose RDATA
// is not. Worth separating, because "HINFO is not case-converted" is easy to
// over-apply to the header.
func TestOwnerNameIsDownCasedEvenForTypesWhoseRDATAIsNot(t *testing.T) {
	sig := testSig("example.test.", dns.TypeHINFO, 2, 3600)
	rr := mustRR(`ExAmPle.TeSt. 3600 IN HINFO "MiXeD" "CaSe"`)

	wire, err := canonicalRR(sig, rr)
	if err != nil {
		t.Fatalf("canonicalRR: %v", err)
	}
	name, _, err := dns.UnpackDomainName(wire, 0)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if name != "example.test." {
		t.Errorf("owner name = %q, want %q", name, "example.test.")
	}
	if !strings.Contains(string(wire), "MiXeD") {
		t.Errorf("HINFO CPU field was case-converted; wire=%q", wire)
	}
}

func mustRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

// The tests above check downcaseRDATANames in isolation, which proves the
// type list is right and proves nothing about whether canonical form applies
// it. Removing the call from canonicalRR left every one of them passing.
//
// So this asserts the wiring: two RRsets differing only in the casing of a
// name inside the RDATA must produce identical signed data. Without the call,
// they do not, and a zone whose MX target arrives in different case from the
// way it was signed fails validation for no visible reason.
func TestSignedDataDownCasesNamesInsideRDATA(t *testing.T) {
	sig := testSig("example.test.", dns.TypeMX, 2, 3600)

	lower, err := canonicalSignedData(sig, []dns.RR{mustRR("example.test. 3600 IN MX 10 mail.example.test.")})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	mixed, err := canonicalSignedData(sig, []dns.RR{mustRR("example.test. 3600 IN MX 10 MaIl.ExAmPle.TeSt.")})
	if err != nil {
		t.Fatalf("mixed: %v", err)
	}

	if !bytes.Equal(lower, mixed) {
		t.Errorf("signed data changed with the casing of a name in the RDATA;\n lower=%x\n mixed=%x", lower, mixed)
	}
}

// The counterpart: a type outside RFC 4034 §6.2's enumeration must NOT have
// its RDATA names folded, because doing so would produce signed data no
// signer ever signed. SVCB postdates the enumeration.
func TestSignedDataLeavesRDATANamesAloneForTypesOutsideTheList(t *testing.T) {
	sig := testSig("example.test.", dns.TypeSVCB, 2, 3600)

	lower, err := canonicalSignedData(sig, []dns.RR{mustRR("example.test. 3600 IN SVCB 1 target.example.test.")})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	mixed, err := canonicalSignedData(sig, []dns.RR{mustRR("example.test. 3600 IN SVCB 1 TaRgEt.ExAmPle.TeSt.")})
	if err != nil {
		t.Fatalf("mixed: %v", err)
	}

	if bytes.Equal(lower, mixed) {
		t.Error("SVCB RDATA was case-folded; it is not in the RFC 4034 §6.2 enumeration")
	}
}
