package dnssec_test

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// answeringSource answers the delegation question about every name the same
// way, whatever the truth is.
//
// It stands in for a resolver whose view of the tree is wrong in the worst
// available direction — an attacker who controls the referrals, which is the
// threat model a delegation probe has to survive.
type answeringSource struct {
	inner dnssec.Source
	say   bool
	// asked counts the delegation questions the walk put to this source. A
	// test that does not check it can pass without the branch under test
	// having been reached at all — which is exactly what the first version of
	// this file did, because it stripped the authority section and left the
	// DS RRset in the answer, so the walk never had a missing DS to reason
	// about.
	asked *int
}

func (a answeringSource) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	return a.inner.Lookup(ctx, name, rrtype)
}

func (a answeringSource) ZoneCutsFor(ctx context.Context, name string) (map[string]bool, bool) {
	if a.asked != nil {
		*a.asked++
	}
	return map[string]bool{dns.CanonicalName(name): a.say}, true
}

// noDSAnywhere removes the DS RRset and every denial of it, at every name.
//
// Both sections, which is the difference between reaching noDSAtDelegation and
// not. Stripping only the authority section leaves the DS itself in the answer,
// the walk crosses the delegation normally, and the branch this file is about
// is never executed.
type noDSAnywhere struct{ inner dnssec.Source }

func (d noDSAnywhere) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	resp, err := d.inner.Lookup(ctx, name, rrtype)
	if err != nil || rrtype != dns.TypeDS {
		return resp, err
	}
	resp.Answer, resp.Authority = nil, nil
	return resp, nil
}

// The safety property of the whole change, stated over every question the
// standard hierarchy can be asked.
//
// Establishing delegations is meant to remove refusals. It must not add
// acceptances, and an attacker who controls what the resolver believes about
// the shape of the tree — answering "everything is a cut", or "nothing is" —
// must not be able to turn any verdict into Secure.
//
// The argument for why not is short, and the test is here because an argument
// is not evidence. Secure requires a signature made by a key in an apex DNSKEY
// RRset the walk has already authenticated through a DS at every cut it
// crossed. Neither answer to the delegation question supplies a key or a DS,
// so neither can manufacture one.
func TestDiscoveringDelegationsNeverProducesSecure(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	honest := dnssec.New(h, cfg)

	type question struct {
		name   string
		rrtype uint16
	}
	questions := []question{
		{lab.AnswerName, dns.TypeA},
		{lab.MailName, dns.TypeMX},
		{lab.WildcardMatch, dns.TypeA},
		{lab.DeepName, dns.TypeA},
		{lab.EmptyNonTerminal, dns.TypeA},
		{lab.MissingName, dns.TypeA},
		{lab.OtherName, dns.TypeA},
		{lab.UnsignedName, dns.TypeA},
		{lab.AliasName, dns.TypeA},
		{lab.CrossZoneAlias, dns.TypeA},
		{lab.AliasToInsecure, dns.TypeA},
		{lab.DnameMatch, dns.TypeA},
		{lab.LeafZone, dns.TypeDNSKEY},
		{lab.UnsignedZone, dns.TypeDS},
	}

	// Six hostile combinations: the delegation answer inverted in both
	// directions, over an honest source, over one whose delegation *proofs*
	// are stripped, and over one where the DS itself is gone everywhere.
	//
	// The last pair is the one that reaches noDSAtDelegation. The other four
	// mostly do not — the DS RRset is still in the answer, so the walk crosses
	// each delegation normally — and they are kept because "a hostile
	// delegation answer changes nothing when the chain is intact" is itself
	// worth asserting.
	type variant struct {
		build       func() dnssec.Source
		mustConsult bool
	}
	sources := map[string]variant{
		"everything-is-a-cut": {build: func() dnssec.Source {
			return answeringSource{inner: h, say: true}
		}},
		"nothing-is-a-cut": {build: func() dnssec.Source {
			return answeringSource{inner: h, say: false}
		}},
		"everything-is-a-cut/proofs-stripped": {build: func() dnssec.Source {
			return answeringSource{inner: suppressingSource{inner: h}, say: true}
		}},
		"nothing-is-a-cut/proofs-stripped": {build: func() dnssec.Source {
			return answeringSource{inner: suppressingSource{inner: h}, say: false}
		}},
		"everything-is-a-cut/no-ds-anywhere": {mustConsult: true, build: func() dnssec.Source {
			return answeringSource{inner: noDSAnywhere{inner: h}, say: true}
		}},
		"nothing-is-a-cut/no-ds-anywhere": {mustConsult: true, build: func() dnssec.Source {
			return answeringSource{inner: noDSAnywhere{inner: h}, say: false}
		}},
	}

	for label, v := range sources {
		for _, q := range questions {
			name := label + "/" + q.name + "/" + dns.TypeToString[q.rrtype]
			t.Run(name, func(t *testing.T) {
				asked := 0
				src := v.build()
				if as, ok := src.(answeringSource); ok {
					as.asked = &asked
					src = as
				}

				before := honest.Validate(context.Background(), q.name, q.rrtype)
				after := dnssec.New(src, cfg).Validate(context.Background(), q.name, q.rrtype)

				if v.mustConsult && asked == 0 {
					t.Fatalf("the walk never put a delegation question to the source, so this " +
						"case proves nothing about what it does with the answer")
				}
				if after.Status == dnssec.StatusSecure && before.Status != dnssec.StatusSecure {
					t.Fatalf("a hostile delegation answer turned %s into secure\n%s",
						before.Status, after.Trace())
				}
				if chainRankFor(after.Status) < chainRankFor(before.Status) {
					t.Fatalf("a hostile delegation answer strengthened the verdict: %s -> %s\n%s",
						before.Status, after.Status, after.Trace())
				}
			})
		}
	}
}

// An observed delegation must never become Insecure, however the walk came to
// observe it.
//
// Insecure is a claim that the parent *proved* no DS exists, and the proof is
// a signed NSEC. A referral is not a proof: it arrives unauthenticated, and an
// attacker who strips a DS RRset in transit produces exactly the shape a
// genuine insecure delegation has. Were the walk to read a discovered cut as
// Insecure, establishing delegations would have built the classic DNSSEC
// downgrade out of the very mechanism meant to remove a false Bogus.
//
// This is the one direction the probe must never make easier, so it is
// asserted over every name rather than at the single site where the branch
// lives.
func TestADiscoveredCutIsNeverReadAsAnAuthenticatedAbsence(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	for _, name := range []string{lab.AnswerName, lab.DeepName, lab.OtherName, lab.MailName} {
		t.Run(name, func(t *testing.T) {
			// Every DS and every denial of one removed, and a source
			// asserting a cut everywhere: the stripped-DS attack dressed as
			// an insecure delegation at every step. Both sections have to go,
			// or the walk crosses each delegation on the DS still sitting in
			// the answer and never reaches the branch under test.
			asked := 0
			src := answeringSource{inner: noDSAnywhere{inner: h}, say: true, asked: &asked}
			got := dnssec.New(src, cfg).Validate(context.Background(), name, dns.TypeA)

			if asked == 0 {
				t.Fatal("the walk never asked about a delegation, so it cannot have taken " +
					"the branch this test is about")
			}
			if got.Status == dnssec.StatusSecure {
				t.Fatalf("a stripped DS produced Secure:\n%s", got.Trace())
			}
			if got.Status == dnssec.StatusInsecure {
				t.Fatalf("a stripped DS was downgraded to Insecure — any signed zone could be "+
					"turned unsigned by removing one RRset in transit:\n%s", got.Trace())
			}
			if got.Status != dnssec.StatusIndeterminate {
				t.Fatalf("status = %s, want Indeterminate\n%s", got.Status, got.Trace())
			}
			if got.Reason != dnssec.ReasonDelegationUnprovable {
				t.Errorf("reason = %q, want %q so the two situations are named rather than merged",
					got.Reason, dnssec.ReasonDelegationUnprovable)
			}
		})
	}
}

// The fallback has to remain reachable, and has to remain the thing it was.
//
// A source that declines to answer is the ordinary case for anything that is
// not an iterative resolver — netsource, a forwarder, the differential
// harness — and for an iterative one whose budget has run out. The walk's
// v0.1 assumption is what catches all of them, so a change that quietly
// removed it would turn "cannot tell" into a verdict for every deployment that
// is not Learn mode.
func TestTheAssumptionStillCatchesASourceThatCannotAnswer(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	src := &countingDelegationSource{inner: suppressingSource{inner: h}, noOpinion: true}
	got := dnssec.New(src, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeA)

	if src.zoneCuts == 0 {
		t.Fatal("the walk never asked, so this proves nothing about what it does with the answer")
	}
	if !strings.Contains(got.Trace(), "assuming this is not a zone cut") {
		t.Errorf("a source that declined to answer did not reach the assumption; "+
			"every non-iterative source depends on it:\n%s", got.Trace())
	}
}
