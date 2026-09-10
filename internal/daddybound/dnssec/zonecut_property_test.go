package dnssec_test

import (
	"context"
	"strings"
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

// delegationAwareSource is a source that knows where the zone cuts are, as an
// iterative resolver does.
//
// It wraps the laboratory, which supplies the records, and answers the
// delegation question from a fixed map — standing in for the referrals a real
// resolver would have crossed.
type delegationAwareSource struct {
	inner dnssec.Source
	cuts  map[string]bool
	// noOpinion makes the source decline to answer, as one that has never
	// resolved through the name would.
	noOpinion bool
	// asked records the names the walk enquired about, so a test can prove
	// the walk consulted the evidence rather than reaching the same answer
	// by chance.
	asked map[string]int
}

func (d *delegationAwareSource) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	return d.inner.Lookup(ctx, name, rrtype)
}

func (d *delegationAwareSource) ZoneCutsFor(ctx context.Context, name string) (map[string]bool, bool) {
	if d.asked == nil {
		d.asked = map[string]int{}
	}
	n := dns.CanonicalName(name)
	d.asked[n]++
	if d.noOpinion {
		return nil, false
	}
	// A resolver with complete knowledge answers about the name it was
	// asked, either way. Returning a map that simply omits the name would
	// mean "I have no idea", which is a different statement and the one the
	// walk must not read as evidence.
	out := map[string]bool{n: d.cuts[n]}
	for k, v := range d.cuts {
		out[k] = v
	}
	return out, true
}

// TestTheWalkPrefersRealDelegationEvidenceToItsAssumption is the acceptance
// criterion of issue #64.
//
// The laboratory's DS responses are stripped of their authority section, so
// the walk reaches the branch where it used to assume "not a zone cut". With a
// source that can answer the question, it asks instead — and the assumption is
// not reached at all.
func TestTheWalkPrefersRealDelegationEvidenceToItsAssumption(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	starved := suppressingSource{inner: h}
	// Everything the walk passes through is positively not a zone cut,
	// which is what a resolver that crossed no referral there observed.
	aware := &delegationAwareSource{inner: starved, cuts: map[string]bool{}}

	got := dnssec.New(aware, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeA)

	// The source must actually have been consulted. Without this the test
	// would pass on a validator that ignored the capability entirely.
	if len(aware.asked) == 0 {
		t.Fatal("the walk never asked the source about zone cuts; it is still assuming")
	}

	// The evidence says "not a zone cut", which is what the assumption said
	// too — so the verdict is unchanged and the *reason* is what differs.
	// A trace that still cites the assumption means the branch was not taken.
	trace := got.Trace()
	if strings.Contains(trace, "assuming this is not a zone cut") {
		t.Errorf("the walk fell back to the assumption despite a source that could answer:\n%s", trace)
	}
	if !strings.Contains(trace, "crossed no delegation here") {
		t.Errorf("the trace does not record that the decision came from observed delegations:\n%s", trace)
	}
}

// The direction that matters most for safety.
//
// When the resolver says "this really is a delegation" and the parent supplied
// no readable DS and no authenticated denial, the walk must NOT conclude
// Insecure. Insecure is a claim that absence was proved, and a referral proves
// nothing — an attacker who strips a DS RRset produces exactly this shape, so
// reading it as Insecure would downgrade any signed zone to unsigned.
//
// Indeterminate with a reason is the honest answer, and it is what an
// enforcing resolver has to fail safe on.
func TestAnObservedDelegationWithNoProvableDSIsIndeterminateNotInsecure(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	// A source that strips both the DS RRset and its denial, and reports the
	// name as a real delegation — the stripped-DS attack, dressed as an
	// insecure delegation.
	aware := &delegationAwareSource{
		inner: dsStrippingSource{inner: h, at: "example.dnsdaddylab."},
		cuts:  map[string]bool{"example.dnsdaddylab.": true},
	}

	got := dnssec.New(aware, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeA)

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
}

// dsStrippingSource removes the DS RRset and any denial of it at one name,
// which is what an attacker downgrading a signed zone does.
type dsStrippingSource struct {
	inner dnssec.Source
	at    string
}

func (d dsStrippingSource) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	resp, err := d.inner.Lookup(ctx, name, rrtype)
	if err != nil || rrtype != dns.TypeDS || dns.CanonicalName(name) != dns.CanonicalName(d.at) {
		return resp, err
	}
	resp.Answer, resp.Authority = nil, nil
	return resp, nil
}
