package dnssec_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// The synthesised CNAME in a DNAME response is not evidence of anything.
//
// RFC 6672 §5.3.1: "if there is [a synthesized CNAME], the CNAME will never
// be signed." It is a convenience for DNAME-unaware caches, and its target is
// whatever the sender wrote. A validator that reads it has taken a redirection
// on the sender's word while a signed DNAME sits in the same message looking
// like justification for doing so — the worst shape a false Secure can have,
// because the response contains genuine cryptography that authenticates
// something else.
//
// So the test is not "a rewritten CNAME is rejected". It is stronger: the
// verdict and the resolved answer must be *identical* whatever the CNAME
// says, including when it is absent. A validator that produced a different
// answer for a different CNAME would be reading it.
func TestTheSynthesisedCNAMEInADnameResponseIsIgnored(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	verdict := func(t *testing.T, rewrite func([]dns.RR) []dns.RR) dnssec.ValidationResult {
		t.Helper()
		src := &relayingSource{inner: h, name: lab.DnameMatch, rrtype: dns.TypeA, rewrite: rewrite}
		return dnssec.New(src, cfg).Validate(context.Background(), lab.DnameMatch, dns.TypeA)
	}

	untouched := verdict(t, func(answer []dns.RR) []dns.RR { return answer })
	if untouched.Status != dnssec.StatusSecure {
		t.Fatalf("the unmodified DNAME response did not validate: %s (%s)\n%s",
			untouched.Status, untouched.Reason, untouched.Trace())
	}

	for _, tc := range []struct {
		name    string
		rewrite func([]dns.RR) []dns.RR
	}{
		{
			// The attack. The DNAME says the query goes to
			// www.example.dnsdaddylab.; the CNAME says it goes to a name
			// in a zone the attacker controls. Every signature in the
			// message still verifies.
			name: "the CNAME points somewhere else entirely",
			rewrite: func(answer []dns.RR) []dns.RR {
				out := make([]dns.RR, 0, len(answer))
				for _, rr := range answer {
					c := dns.Copy(rr)
					if cn, ok := c.(*dns.CNAME); ok {
						cn.Target = lab.UnsignedName
					}
					out = append(out, c)
				}
				return out
			},
		},
		{
			// RFC 6672 §5.3.1 says the CNAME "might or might not" be
			// there. A validator that needed it would fail here, which is
			// the same defect seen from the other side.
			name: "the CNAME is missing altogether",
			rewrite: func(answer []dns.RR) []dns.RR {
				out := make([]dns.RR, 0, len(answer))
				for _, rr := range answer {
					if _, isCNAME := rr.(*dns.CNAME); !isCNAME {
						out = append(out, rr)
					}
				}
				return out
			},
		},
		{
			// A CNAME with a signature over it, from an attacker who
			// noticed the unsigned one was being ignored and tried
			// signing it. The signature is nonsense, but the point is
			// that its presence must not change the path taken: the
			// DNAME is still what decides.
			name: "the CNAME arrives with a signature attached",
			rewrite: func(answer []dns.RR) []dns.RR {
				out := make([]dns.RR, 0, len(answer)+1)
				for _, rr := range answer {
					c := dns.Copy(rr)
					if cn, ok := c.(*dns.CNAME); ok {
						cn.Target = lab.UnsignedName
					}
					out = append(out, c)
				}
				return append(out, &dns.RRSIG{
					Hdr: dns.RR_Header{
						Name: lab.DnameMatch, Rrtype: dns.TypeRRSIG,
						Class: dns.ClassINET, Ttl: 3600,
					},
					TypeCovered: dns.TypeCNAME, Algorithm: 15, Labels: 4,
					OrigTtl: 3600, Expiration: 4102444800, Inception: 1,
					KeyTag: 39172, SignerName: lab.LeafZone, Signature: "AAAA",
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := verdict(t, tc.rewrite)
			if got.Status != untouched.Status || got.Reason != untouched.Reason {
				t.Fatalf("editing the synthesised CNAME changed the verdict:\n"+
					"  untouched: %s (%s)\n  edited:    %s (%s)\n%s",
					untouched.Status, untouched.Reason, got.Status, got.Reason, got.Trace())
			}
		})
	}
}

// A DNAME added by an attacker high in the zone must not pre-empt the closer
// one that legitimately applies.
//
// RFC 1034 §4.3.2 descends label by label, so the deepest match is the one
// that redirects. Taking the first DNAME seen instead would let anyone who
// can insert a record into the answer section redirect a subtree that a
// deeper, genuine DNAME already governs — and the inserted record does not
// even need to authenticate for the *choice* to have been made wrongly.
func TestTheDeepestDnameWins(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	// An unsigned DNAME at the zone apex, prepended so that a first-match
	// implementation picks it up.
	shallow := &dns.DNAME{
		Hdr:    dns.RR_Header{Name: lab.LeafZone, Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: lab.UnsignedZone,
	}
	src := &relayingSource{
		inner: h, name: lab.DnameMatch, rrtype: dns.TypeA,
		rewrite: func(answer []dns.RR) []dns.RR {
			return append([]dns.RR{shallow}, answer...)
		},
	}
	got := dnssec.New(src, cfg).Validate(context.Background(), lab.DnameMatch, dns.TypeA)
	if got.Status != dnssec.StatusSecure {
		t.Fatalf("an injected shallow DNAME displaced the genuine deeper one: %s (%s)\n%s",
			got.Status, got.Reason, got.Trace())
	}
}
