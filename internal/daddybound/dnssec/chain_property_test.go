package dnssec_test

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// Chain completeness: every link of a chain that comes out Secure must have
// been authenticated, and breaking any one of them must cost the verdict.
//
// A chain is where "Secure" is easiest to get wrong, because the answer is
// assembled from several independent validations and the temptation is to
// report the one the caller asked about. Reporting the terminal RRset's
// verdict ignores an alias nobody authenticated; reporting the first hop's
// ignores everything the alias pointed at. Either lets an attacker place one
// forged link in a chain and have the whole thing come back Secure.
//
// The test is stated as load-bearingness rather than as a claim about the
// implementation: take a chain that validates, break exactly one link, and
// require the result to stop being Secure. Repeat for every link. A validator
// that skipped a hop passes the unbroken case and fails here on that hop.
func TestEveryLinkOfASecureChainIsLoadBearing(t *testing.T) {
	// The chain hop1 -> hop2 -> hop3 -> www, plus the RRset at the end. Each
	// entry names an owner whose signature will be corrupted in turn.
	links := []struct {
		owner  string
		rrtype uint16
	}{
		{lab.AliasHop1, dns.TypeCNAME},
		{lab.AliasHop2, dns.TypeCNAME},
		{lab.AliasHop3, dns.TypeCNAME},
		{lab.AnswerName, dns.TypeA},
	}

	base, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	v, err := base.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	if got := v.Validate(context.Background(), lab.AliasHop1, dns.TypeA); got.Status != dnssec.StatusSecure {
		t.Fatalf("the unbroken chain does not validate: %s (%s)\n%s", got.Status, got.Reason, got.Trace())
	}

	for _, link := range links {
		name := link.owner + "/" + dns.TypeToString[link.rrtype]
		t.Run(name, func(t *testing.T) {
			h, err := lab.Standard()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if err := h.CorruptSignature(lab.LeafZone, link.owner, link.rrtype); err != nil {
				t.Fatalf("corrupt: %v", err)
			}
			v, err := h.Validator(lab.Now())
			if err != nil {
				t.Fatalf("validator: %v", err)
			}
			got := v.Validate(context.Background(), lab.AliasHop1, dns.TypeA)
			if got.Status == dnssec.StatusSecure {
				t.Fatalf("breaking %s left the chain Secure: the link was never authenticated\n%s",
					name, got.Trace())
			}
			if got.Status != dnssec.StatusBogus {
				t.Errorf("breaking %s gave %s; a signature that does not verify is a statement "+
					"about the data, so Bogus\n%s", name, got.Status, got.Trace())
			}
		})
	}
}

// The same property for a DNAME redirection, where the link that carries the
// chain is the DNAME rather than an alias the server wrote.
func TestBothLinksOfADnameRedirectionAreLoadBearing(t *testing.T) {
	for _, link := range []struct {
		owner  string
		rrtype uint16
	}{
		{lab.DnameOwner, dns.TypeDNAME},
		{lab.AnswerName, dns.TypeA},
	} {
		name := link.owner + "/" + dns.TypeToString[link.rrtype]
		t.Run(name, func(t *testing.T) {
			h, err := lab.Standard()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if err := h.CorruptSignature(lab.LeafZone, link.owner, link.rrtype); err != nil {
				t.Fatalf("corrupt: %v", err)
			}
			v, err := h.Validator(lab.Now())
			if err != nil {
				t.Fatalf("validator: %v", err)
			}
			got := v.Validate(context.Background(), lab.DnameMatch, dns.TypeA)
			if got.Status == dnssec.StatusSecure {
				t.Fatalf("breaking %s left the redirection Secure\n%s", name, got.Trace())
			}
		})
	}
}

// Classification stability: the verdict is a function of the evidence, not of
// the prose.
//
// Two things are being separated here. The trace is a diagnostic — it exists
// for a human reading a failure — and the status and reason are decisions,
// because verdict() turns a reason into Bogus or Indeterminate. A validator
// whose verdict moved when a note was reworded, or when the response's
// records arrived in a different order, would be letting whoever controls
// presentation control the outcome; on the wire, that is the attacker.
//
// Permuting the answer section is how the property is exercised. Every hop of
// a chain has its records reordered, which changes the order the engine
// encounters everything in without changing what it was given.
func TestAChainVerdictDoesNotDependOnRecordOrder(t *testing.T) {
	queries := []struct {
		name   string
		rrtype uint16
	}{
		{lab.AliasHop1, dns.TypeA},
		{lab.AliasName, dns.TypeA},
		{lab.CrossZoneAlias, dns.TypeA},
		{lab.AliasToInsecure, dns.TypeA},
		{lab.WildcardAliasMatch, dns.TypeA},
		{lab.DnameMatch, dns.TypeA},
		{lab.AliasLoopA, dns.TypeA},
		{lab.MissingName, dns.TypeA},
	}

	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	for _, q := range queries {
		label := q.name + "/" + dns.TypeToString[q.rrtype]
		t.Run(label, func(t *testing.T) {
			forwards := dnssec.New(h, cfg).Validate(context.Background(), q.name, q.rrtype)
			backwards := dnssec.New(reversingSource{inner: h}, cfg).
				Validate(context.Background(), q.name, q.rrtype)

			if forwards.Status != backwards.Status || forwards.Reason != backwards.Reason {
				t.Fatalf("reversing every section changed the verdict:\n"+
					"  forwards:  %s (%s)\n  backwards: %s (%s)\n%s",
					forwards.Status, forwards.Reason,
					backwards.Status, backwards.Reason, backwards.Trace())
			}
		})
	}
}

// The diagnostic prose must not be what decides anything.
//
// verdict() maps a reason onto Bogus or Indeterminate, and a reason is a
// closed constant. This asserts the other half: the human-readable note
// attached to a step is absent from that decision, so no amount of rewording
// can move a verdict. Stated by construction — every reason a failing chain
// can carry is one of the taxonomy's values — and checked here by requiring
// the reason to be a known constant rather than free text assembled at the
// point of failure.
func TestAFailingChainReportsAReasonFromTheTaxonomy(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := h.CorruptSignature(lab.LeafZone, lab.AliasHop2, dns.TypeCNAME); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	got := v.Validate(context.Background(), lab.AliasHop1, dns.TypeA)

	if !got.Reason.Known() {
		t.Fatalf("reason %q is not in the taxonomy; a verdict decided from free text "+
			"is a verdict decided by whoever wrote the text", got.Reason)
	}
	// And the explanation is prose that nothing branches on: it exists, and
	// it is not the reason itself being reused as an identifier.
	if e := got.Reason.Explain(); e == "" || e == string(got.Reason) {
		t.Errorf("reason %q has no separate human explanation (%q)", got.Reason, e)
	}
	if strings.TrimSpace(got.Trace()) == "" {
		t.Error("a failing chain produced no trace for a human to read")
	}
}

// reversingSource hands back every section in reverse, which is a permutation
// the sender chooses freely and the validator must be immune to.
type reversingSource struct{ inner dnssec.Source }

func (s reversingSource) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	resp, err := s.inner.Lookup(ctx, name, rrtype)
	if err != nil {
		return resp, err
	}
	resp.Answer = reversed(resp.Answer)
	resp.Authority = reversed(resp.Authority)
	return resp, nil
}

func reversed(in []dns.RR) []dns.RR {
	out := make([]dns.RR, len(in))
	for i, rr := range in {
		out[len(in)-1-i] = rr
	}
	return out
}

// RFC 6840 §5.4, asserted directly because it is the one rule in this engine
// that no oracle comparison can pin.
//
// The section leaves the behaviour to local policy — RFC 4035 §5.3.3: "the
// local resolver security policy determines ... how to resolve conflicts if
// these RRSIG RRs lead to differing results" — and then makes a
// recommendation:
//
//	This document specifies that a resolver SHOULD accept any valid RRSIG
//	as sufficient, and only determine that an RRset is Bogus if all RRSIGs
//	fail validation.
//
//	If a resolver adopts a more restrictive policy ... Such a resolver is
//	also vulnerable to malicious insertion of gibberish signatures.
//
// That last sentence is the security argument, and it runs the opposite way
// from the intuition. Being strict here does not catch anything: an attacker
// cannot make a forged RRset validate by adding signatures, because the
// verdict still requires one that verifies. What being strict *does* is hand
// anyone on the path a denial of service — append a gibberish RRSIG to a
// correctly signed answer and a strict validator calls the zone forged.
//
// Because delv takes the restrictive policy and libunbound does not, the
// differential scenario for this is NoOracle. This is where the behaviour is
// held.
func TestOneValidSignatureIsEnough(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// A second signature over the same RRset, identical in every field the
	// validator orders on, then broken and forced to the front of that
	// order — so the good one is reached only by continuing past a failure.
	if err := h.AddSignature(lab.LeafZone, lab.AnswerName, dns.TypeA, func(*dns.RRSIG) {}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := h.BreakSignatureFirstInOrder(lab.LeafZone, lab.AnswerName, dns.TypeA, 0); err != nil {
		t.Fatalf("break: %v", err)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	got := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)
	if got.Status != dnssec.StatusSecure {
		t.Fatalf("a gibberish signature appended to a correctly signed RRset cost the verdict: %s (%s)\n%s",
			got.Status, got.Reason, got.Trace())
	}

	// The trace must show the failure was actually reached, or the test is
	// asserting the recommendation while exercising the case where nothing
	// failed. That was true of an earlier version of this fixture, which
	// passed while testing nothing.
	if !strings.Contains(got.Trace(), "signature_crypto_failed") {
		t.Fatalf("the broken signature was never tried, so continuing past a "+
			"failure was not exercised\n%s", got.Trace())
	}
}

// And the boundary: with nothing valid left, the RRset is Bogus. Without
// this, the test above is passed by a validator that accepts an RRset because
// a signature was present rather than because one verified — which is the
// false-Secure direction.
func TestAllSignaturesFailingIsBogus(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := h.AddSignature(lab.LeafZone, lab.AnswerName, dns.TypeA, func(*dns.RRSIG) {}); err != nil {
		t.Fatalf("add: %v", err)
	}
	for n := 0; n < 2; n++ {
		if err := h.CorruptSignatureAt(lab.LeafZone, lab.AnswerName, dns.TypeA, n); err != nil {
			t.Fatalf("corrupt %d: %v", n, err)
		}
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	got := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)
	if got.Status != dnssec.StatusBogus {
		t.Fatalf("an RRset with no valid signature was %s, not bogus\n%s", got.Status, got.Trace())
	}
}
