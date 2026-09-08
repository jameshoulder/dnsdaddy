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
