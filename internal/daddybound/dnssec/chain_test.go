package dnssec_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// The first checkpoint: a locally generated signed hierarchy, walked
// independently by Daddybound from a trust anchor to an answer.
func TestSignedHierarchyValidatesAsSecure(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build hierarchy: %v", err)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	got := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)
	if !got.Secure() {
		t.Fatalf("expected secure, got %s\n%s", got.Status, got.Trace())
	}
	if got.Reason != dnssec.ReasonVerified {
		t.Errorf("reason = %s, want %s", got.Reason, dnssec.ReasonVerified)
	}
}

// A Secure verdict on its own does not prove a chain was walked: a validator
// that authenticated the answer directly against the anchor, or one that
// returned Secure without checking anything, would also pass the test above.
// This asserts the shape of the walk — that trust was extended across each
// delegation in turn — so that the first test's verdict means what it says.
func TestSecureVerdictCrossesEveryDelegation(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build hierarchy: %v", err)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	got := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)

	// Each zone's apex DNSKEY RRset must have been authenticated in its own
	// right, and each delegation crossed by a DS that matched a key.
	wantDNSKEY := []string{lab.RootZone, lab.MiddleZone, lab.LeafZone}
	for _, zone := range wantDNSKEY {
		if !hasStep(got, dnssec.StepRRset, dnssec.OutcomeOK, zone, dns.TypeDNSKEY) {
			t.Errorf("no authenticated DNSKEY RRset for %s\n%s", zone, got.Trace())
		}
	}
	for _, zone := range []string{lab.MiddleZone, lab.LeafZone} {
		if !hasStepKind(got, dnssec.StepDS, dnssec.OutcomeOK, zone) {
			t.Errorf("delegation to %s was not crossed by a matching DS\n%s", zone, got.Trace())
		}
	}

	// And the anchor must have been the starting point, rather than a key
	// observed in the response being promoted into one.
	if !hasStepKind(got, dnssec.StepTrustAnchor, dnssec.OutcomeOK, lab.RootZone) {
		t.Errorf("the walk did not start from the configured trust anchor\n%s", got.Trace())
	}
}

func hasStep(r dnssec.ValidationResult, kind dnssec.StepKind, outcome dnssec.StepOutcome, zone string, rrtype uint16) bool {
	for _, s := range r.Steps {
		if s.Kind == kind && s.Outcome == outcome && s.Zone == zone && s.RRType == rrtype {
			return true
		}
	}
	return false
}

func hasStepKind(r dnssec.ValidationResult, kind dnssec.StepKind, outcome dnssec.StepOutcome, zone string) bool {
	for _, s := range r.Steps {
		if s.Kind == kind && s.Outcome == outcome && s.Zone == zone {
			return true
		}
	}
	return false
}
