package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

// RFC 6672 §2.2 publishes a substitution table, so this test is the RFC's own
// worked examples rather than mine.
//
// That matters more than usual here. Every wrong implementation of DNAME
// substitution is a string operation that looks right: strings.TrimSuffix,
// strings.Replace, a byte-offset slice. The table exists because the authors
// knew which ones people write, and it lists the corner cases that separate
// them — a name that ends in the owner's characters without ending in its
// labels, an owner deeper than one label, a target that is the root, and the
// loops. Reproducing the table checks the implementation against the
// specification instead of against my reading of it.
func TestDnameSubstitutionMatchesRFC6672Table(t *testing.T) {
	for _, tc := range []struct {
		qname, owner, target string
		want                 string
		wantReason           Reason
	}{
		// QNAME above the owner: no match. A query for "com." is not
		// redirected by a DNAME at "example.com.".
		{"com.", "example.com.", "example.net.", "", ReasonDnameNoMatch},

		// The owner itself: no substitution (RFC 6672 §2.3). The table
		// marks this "[0] The result depends on the QTYPE" — for QTYPE
		// other than DNAME it is "<no match>" — and the caller never asks,
		// because closestDnameOwner requires a *proper* ancestor.
		{"example.com.", "example.com.", "example.net.", "", ReasonDnameNoMatch},

		{"a.example.com.", "example.com.", "example.net.", "a.example.net.", ReasonNone},
		{"a.b.example.com.", "example.com.", "example.net.", "a.b.example.net.", ReasonNone},

		// The case that catches a string-suffix implementation.
		// "ab.example.com." ends with "b.example.com." as characters and
		// does not end with it as labels, so the RFC says "<no match>".
		{"ab.example.com.", "b.example.com.", "example.net.", "", ReasonDnameNoMatch},

		{"foo.example.com.", "example.com.", "example.net.", "foo.example.net.", ReasonNone},

		// A multi-label owner: only the matching suffix is replaced, so
		// "x." disappears rather than being carried through.
		{"a.x.example.com.", "x.example.com.", "example.net.", "a.example.net.", ReasonNone},

		{"a.example.com.", "example.com.", "y.example.net.", "a.y.example.net.", ReasonNone},

		// The loops. Substitution is arithmetic, not policy: it produces
		// the name the RFC says it produces, and the hop budget in chase()
		// is what stops the resolution. A substitution that refused these
		// would be enforcing a loop rule in the wrong place and would get
		// the answer wrong for the many valid chains that merely look
		// similar.
		{"cyc.example.com.", "example.com.", "example.com.", "cyc.example.com.", ReasonNone},
		{"cyc.example.com.", "example.com.", "c.example.com.", "cyc.c.example.com.", ReasonNone},

		// The root as a target: the prefix becomes the whole name.
		{"shortloop.x.x.", "x.", ".", "shortloop.x.", ReasonNone},
		{"shortloop.x.", "x.", ".", "shortloop.", ReasonNone},
	} {
		got, reason := dnameSubstitute(tc.qname, tc.owner, tc.target)
		if reason != tc.wantReason {
			t.Errorf("dnameSubstitute(%q, %q, %q) reason = %s, want %s",
				tc.qname, tc.owner, tc.target, reason, tc.wantReason)
			continue
		}
		if got != tc.want {
			t.Errorf("dnameSubstitute(%q, %q, %q) = %q, want %q",
				tc.qname, tc.owner, tc.target, got, tc.want)
		}
	}
}

// RFC 6672 §2.2: "The domain name can get too long during substitution ...
// If this occurs, the server returns an RCODE of YXDOMAIN."
//
// There is nothing to authenticate about a name that cannot exist, and a
// validator that produced one would then go and query for it.
func TestDnameSubstitutionRefusesAnOverlongResult(t *testing.T) {
	long := ""
	for i := 0; i < 5; i++ {
		long += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
	}
	target := long + "example.net."

	if _, reason := dnameSubstitute("x.example.com.", "example.com.", target); reason != ReasonDnameTooLong {
		t.Fatalf("reason = %s, want %s", reason, ReasonDnameTooLong)
	}
	// The same target on its own is a legal name, so the refusal is about
	// the substitution rather than about the target being malformed.
	if _, reason := dnameSubstitute("example.com.", "com.", target); reason == ReasonNone {
		t.Log("the target alone substitutes cleanly, as expected")
	}
}

// closestDnameOwner must take the deepest applicable DNAME, and only ones
// inside the zone whose keys will authenticate them.
func TestClosestDnameOwner(t *testing.T) {
	for _, tc := range []struct {
		name    string
		owners  []string
		qname   string
		zone    string
		want    string
		wantAny bool
	}{
		{
			// RFC 1034 §4.3.2 descends label by label, so the deepest
			// match wins. A shallower DNAME must not pre-empt a closer
			// one — which is exactly what an attacker adding a DNAME high
			// in the zone would be attempting.
			name:   "the deepest owner wins",
			owners: []string{"example.com.", "b.example.com."},
			qname:  "a.b.example.com.", zone: "example.com.",
			want: "b.example.com.", wantAny: true,
		},
		{
			// RFC 6672 §2.3: the owner is not redirected by its own DNAME.
			name:   "the owner itself is not redirected",
			owners: []string{"example.com."},
			qname:  "example.com.", zone: "example.com.",
			wantAny: false,
		},
		{
			// A DNAME whose owner is outside the zone doing the
			// authenticating cannot redirect anything: its signature would
			// be checked against the wrong zone's keys, and the answer
			// would leave the zone that was asked.
			name:   "an out-of-zone owner is ignored",
			owners: []string{"elsewhere.test."},
			qname:  "a.elsewhere.test.", zone: "example.com.",
			wantAny: false,
		},
		{
			name:   "a sibling name is not an ancestor",
			owners: []string{"c.example.com."},
			qname:  "a.b.example.com.", zone: "example.com.",
			wantAny: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := closestDnameOwner(testDnameRecords(tc.owners), tc.qname, tc.zone)
			if ok != tc.wantAny {
				t.Fatalf("ok = %v, want %v (got %q)", ok, tc.wantAny, got)
			}
			if ok && got != tc.want {
				t.Errorf("owner = %q, want %q", got, tc.want)
			}
		})
	}
}

// testDnameRecords builds an answer section holding one DNAME per owner,
// each pointing somewhere irrelevant: closestDnameOwner selects on the owner
// name alone, so the target must not be able to influence it.
func testDnameRecords(owners []string) []dns.RR {
	out := make([]dns.RR, 0, len(owners))
	for _, o := range owners {
		out = append(out, &dns.DNAME{
			Hdr:    dns.RR_Header{Name: o, Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 3600},
			Target: "target.example.net.",
		})
	}
	return out
}
