package dnssec_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// The answer to a query is the RRset at the queried name.
//
// This looks too obvious to need a test, which is why it did not have one and
// why the engine got it wrong. An answer section legitimately carries records
// for other names — RFC 1034 §4.3.2 step 3a has a server follow a CNAME within
// its own zone and return the alias together with what it points at — so
// "records of the right type in the answer section" and "the answer" are
// different sets, and a validator that conflates them authenticates the wrong
// thing.
//
// The attack needs no forgery. Take any signed RRset of the queried type from
// anywhere in the zone, return it in answer to a query for an unrelated name,
// omit the CNAME that would have justified it, and a validator that does not
// check the owner name reports Secure. Every signature verifies, because every
// record is genuine; nothing ties any of it to the question that was asked.

// relayingSource answers from a hierarchy and then rewrites one answer, the
// way a server on the path can.
type relayingSource struct {
	inner   dnssec.Source
	name    string
	rrtype  uint16
	rewrite func([]dns.RR) []dns.RR
}

func (s *relayingSource) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	resp, err := s.inner.Lookup(ctx, name, rrtype)
	if err != nil || dns.CanonicalName(name) != dns.CanonicalName(s.name) || rrtype != s.rrtype {
		return resp, err
	}
	resp.Answer = s.rewrite(resp.Answer)
	return resp, nil
}

func TestAnRRsetForAnotherNameIsNotAnAnswer(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// A genuine, correctly signed A RRset — at a name nobody asked about.
	elsewhere, err := h.Lookup(context.Background(), lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	t.Run("substituted for the answer", func(t *testing.T) {
		// The alias is stripped and the target's records put in its place,
		// so the response asserts "this is the answer for alias" with
		// nothing that says so.
		src := &relayingSource{
			inner: h, name: lab.AliasName, rrtype: dns.TypeA,
			rewrite: func([]dns.RR) []dns.RR { return elsewhere.Answer },
		}
		got := dnssec.New(src, cfg).Validate(context.Background(), lab.AliasName, dns.TypeA)
		if got.Status == dnssec.StatusSecure {
			t.Fatalf("an RRset owned by %s was accepted as the answer for %s\n%s",
				lab.AnswerName, lab.AliasName, got.Trace())
		}
	})

	t.Run("alongside the alias that justifies it", func(t *testing.T) {
		// The same records, this time with the CNAME left in place: what a
		// server following the alias within its own zone actually sends.
		// The extra records are not the answer either, but the alias is, so
		// the chain resolves and the verdict is Secure — reached by
		// following the alias rather than by trusting the passengers.
		src := &relayingSource{
			inner: h, name: lab.AliasName, rrtype: dns.TypeA,
			rewrite: func(answer []dns.RR) []dns.RR {
				return append(append([]dns.RR(nil), answer...), elsewhere.Answer...)
			},
		}
		got := dnssec.New(src, cfg).Validate(context.Background(), lab.AliasName, dns.TypeA)
		if got.Status != dnssec.StatusSecure {
			t.Fatalf("a legitimate chased answer was refused: %s (%s)\n%s",
				got.Status, got.Reason, got.Trace())
		}
	})
}

// The same rule, applied to the delegation walk rather than to the answer.
//
// A response answers one question, and the records that answer it are the
// ones at the queried name. Everything else in the section is context, and
// the DNS puts context there routinely — so "records of the right type in the
// answer section" and "the answer" are different sets at *every* step of the
// walk, not only at the last one.
//
// The live corpus found the delegation half. Asked for the DS of
// www.office365.com — a name that is a CNAME to its own zone apex — a public
// resolver returned the apex's DS instead, signed by com. The walk, standing
// in office365.com by then, tried to authenticate a com.-signed RRset against
// office365.com's keys and reported Bogus for a correctly signed name; both
// reference validators returned Secure. Three names in a 612-question corpus
// hit it, all of the shape www.X -> X.
//
// Only that direction is available here, which is worth pinning as well as
// stating: RFC 4034 §5.1.4 computes a DS digest over the *DNSKEY's* owner
// name, so a DS belonging to another name never matches a child's keys
// however well it is signed. The subtests below assert both halves — the
// legitimate case validates, and the substituted case does not become Secure.
func TestARecordForAnotherNameIsNotADelegation(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	// A genuine, correctly signed DS RRset — for a different child of the
	// same parent, so its signer name is right and only its owner is wrong.
	sibling, err := h.Lookup(context.Background(), lab.OtherZone, dns.TypeDS)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	t.Run("a sibling's DS is not this delegation", func(t *testing.T) {
		src := &relayingSource{
			inner: h, name: lab.LeafZone, rrtype: dns.TypeDS,
			rewrite: func([]dns.RR) []dns.RR { return sibling.Answer },
		}
		got := dnssec.New(src, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeA)
		if got.Status == dnssec.StatusSecure {
			t.Fatalf("a DS owned by %s was accepted as the delegation for %s\n%s",
				lab.OtherZone, lab.LeafZone, got.Trace())
		}
	})

	t.Run("a sibling's DS alongside the real one is ignored", func(t *testing.T) {
		// What the resolver actually did: the right records plus some
		// context. The delegation must still be found and the answer must
		// still validate — a validator that refused here would report Bogus
		// for every name whose resolver is helpful, which is what the corpus
		// caught.
		src := &relayingSource{
			inner: h, name: lab.LeafZone, rrtype: dns.TypeDS,
			rewrite: func(answer []dns.RR) []dns.RR {
				return append(append([]dns.RR(nil), sibling.Answer...), answer...)
			},
		}
		got := dnssec.New(src, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeA)
		if got.Status != dnssec.StatusSecure {
			t.Fatalf("an unrelated DS in the delegation response cost the verdict: %s (%s)\n%s",
				got.Status, got.Reason, got.Trace())
		}
	})

	t.Run("a foreign DNSKEY set is not this zone's", func(t *testing.T) {
		other, err := h.Lookup(context.Background(), lab.OtherZone, dns.TypeDNSKEY)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		src := &relayingSource{
			inner: h, name: lab.LeafZone, rrtype: dns.TypeDNSKEY,
			rewrite: func(answer []dns.RR) []dns.RR {
				return append(append([]dns.RR(nil), other.Answer...), answer...)
			},
		}
		got := dnssec.New(src, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeA)
		if got.Status != dnssec.StatusSecure {
			t.Fatalf("a foreign DNSKEY RRset in the response cost the verdict: %s (%s)\n%s",
				got.Status, got.Reason, got.Trace())
		}
	})
}
