package dnssec_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// The zone-cut assumption, stated as a property rather than as an argument.
//
// A chain walk asks the parent for a DS at every name it descends through. A
// response with no DS and no proof either way is ambiguous: the name may not
// be a zone cut at all — true of nearly every name a walk passes — or it may
// be an insecure delegation whose subtree is legitimately unsigned. Where no
// authenticated proof settles it, the walk assumes "not a zone cut" and keeps
// descending inside the parent zone.
//
// That assumption is deliberate and one-sided, and the argument for it is in
// noDSAtDelegation. The argument runs: concluding Secure requires a signature
// made by a key in an apex DNSKEY RRset the walk has already authenticated,
// and nobody below an insecure delegation holds one, so being wrong costs a
// refusal and never an acceptance.
//
// An argument is not evidence. What follows is the evidence: an attacker who
// controls the authority section of every DS response — which is exactly what
// suppressing the proof means — cannot turn any verdict into Secure.

// suppressingSource strips the authority section from DS responses, so that
// no delegation is ever provable in either direction and the assumption fires
// on every descent.
type suppressingSource struct{ inner dnssec.Source }

func (s suppressingSource) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	resp, err := s.inner.Lookup(ctx, name, rrtype)
	if err == nil && rrtype == dns.TypeDS {
		resp.Authority = nil
	}
	return resp, err
}

func TestSuppressingDelegationProofsNeverProducesSecure(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	honest := dnssec.New(h, cfg)
	starved := dnssec.New(suppressingSource{inner: h}, cfg)

	// Every name and type the standard hierarchy can be asked about, so the
	// property is not established on a hand-picked few.
	type question struct {
		name   string
		rrtype uint16
	}
	questions := []question{
		{lab.AnswerName, dns.TypeA},
		{lab.AnswerName, dns.TypeTXT},
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
		{lab.AliasHop1, dns.TypeA},
		{lab.DnameMatch, dns.TypeA},
		{lab.LeafZone, dns.TypeDNSKEY},
		{lab.LeafZone, dns.TypeSOA},
		{lab.UnsignedZone, dns.TypeDS},
	}

	for _, q := range questions {
		name := q.name + "/" + dns.TypeToString[q.rrtype]
		t.Run(name, func(t *testing.T) {
			before := honest.Validate(context.Background(), q.name, q.rrtype)
			after := starved.Validate(context.Background(), q.name, q.rrtype)

			// The property. Whatever the walk assumed, it cannot have
			// assumed its way to an acceptance.
			if after.Status == dnssec.StatusSecure && before.Status != dnssec.StatusSecure {
				t.Fatalf("removing every delegation proof turned %s into secure\n%s",
					before.Status, after.Trace())
			}

			// And the direction it is allowed to move in. Suppressing
			// evidence may cost a verdict — Secure becoming Bogus is the
			// false Bogus the assumption is known to pay for — but it must
			// never buy one.
			if chainRankFor(after.Status) < chainRankFor(before.Status) {
				t.Fatalf("removing every delegation proof strengthened the verdict: %s -> %s\n%s",
					before.Status, after.Status, after.Trace())
			}
		})
	}
}

// The assumption must also not survive contact with an authenticated proof
// that contradicts it. Where the parent does prove an insecure delegation,
// the answer is Insecure and stays Insecure — the assumption applies only in
// the absence of evidence, and a walk that preferred its assumption to a
// signed record would be validating its own guess.
func TestAnAuthenticatedDelegationProofBeatsTheAssumption(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	got := v.Validate(context.Background(), lab.UnsignedName, dns.TypeA)
	if got.Status != dnssec.StatusInsecure {
		t.Fatalf("a proved insecure delegation was reported %s, not insecure\n%s",
			got.Status, got.Trace())
	}
}

// chainRankFor mirrors the lattice the chain walk uses, written out here so
// the test does not depend on an unexported helper and cannot be satisfied by
// a change to it.
func chainRankFor(s dnssec.ValidationStatus) int {
	switch s {
	case dnssec.StatusBogus:
		return 3
	case dnssec.StatusIndeterminate:
		return 2
	case dnssec.StatusInsecure:
		return 1
	default:
		return 0
	}
}
