package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

// An NXDOMAIN whose closest encloser is the root.
//
// Every query for a top-level domain that does not exist has this shape, so
// it is one of the commonest authenticated denials on the Internet — and it
// was Bogus here until the live corpus ran. The cause was wildcardAt("."),
// which built "*.." by concatenation: not a name, covered by no NSEC, so the
// wildcard half of the name-error proof could never be satisfied.
//
// The lab could not have found it. A lab hierarchy delegates out of the root
// at once, so no scenario in it has the root as a closest encloser; the
// shape simply does not occur. That is the argument for running a corpus of
// real names, in one test.
//
// The records below are the root's own, captured from a live query for a
// name that does not exist. They are reproduced rather than constructed so
// that the interval arithmetic is exercised against the real chain — the
// apex NSEC whose next name is "aaa.", and the delegation NSEC that spans
// the queried name.
func TestANameErrorAtTheRootIsProvable(t *testing.T) {
	// . NSEC aaa. NS SOA RRSIG NSEC DNSKEY ZONEMD
	apex := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 86400},
		NextDomain: "aaa.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY, dns.TypeZONEMD},
	}
	// no. NSEC nokia. NS DS RRSIG NSEC — a delegation NSEC, which spans the
	// queried name without being entitled to speak about anything below its
	// own owner.
	delegation := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "no.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 86400},
		NextDomain: "nokia.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	proof := &denialProof{nsec: []authenticNSEC{
		{rr: apex, signer: "."},
		{rr: delegation, signer: "."},
	}}

	const qname = "no-such-tld-4b1c9e."

	// The two records the proof is made of, checked separately so a failure
	// says which half is missing rather than only that the whole failed.
	if proof.covering(qname, dns.TypeA) == nil {
		t.Fatalf("no authenticated NSEC covers %s; the delegation record spans it", qname)
	}
	if got := wildcardAt("."); got != "*." {
		t.Fatalf("wildcardAt(%q) = %q, want %q — a name with two dots is not a name", ".", got, "*.")
	}
	if proof.covering("*.", dns.TypeA) == nil {
		t.Fatalf("no authenticated NSEC covers the root wildcard; the apex record spans it")
	}

	if reason := proof.proveNameError(qname, dns.TypeA); reason != ReasonNone {
		t.Fatalf("a complete root name-error proof was refused: %s", reason)
	}
}

// The same records must not prove a name that the root does list.
//
// Without this, the test above could be passed by a proof routine that said
// yes to everything, which is the failure mode that matters.
func TestTheRootDenialDoesNotProveTooMuch(t *testing.T) {
	apex := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 86400},
		NextDomain: "aaa.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
	}
	delegation := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "no.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 86400},
		NextDomain: "nokia.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	proof := &denialProof{nsec: []authenticNSEC{
		{rr: apex, signer: "."},
		{rr: delegation, signer: "."},
	}}

	for _, qname := range []string{
		// Outside both intervals: "org." sorts after "nokia.".
		"org.",
		// The delegation's own owner exists, so it cannot be denied.
		"no.",
		// Below the delegation. RFC 6840 §4.1: an ancestor delegation NSEC
		// says nothing about names beneath the cut, however well it spans
		// them in the ordering.
		"example.no.",
	} {
		if reason := proof.proveNameError(qname, dns.TypeA); reason == ReasonNone {
			t.Errorf("the root's two NSEC records were accepted as proof that %s does not exist", qname)
		}
	}
}
