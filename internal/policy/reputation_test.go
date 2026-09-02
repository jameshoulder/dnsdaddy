package policy

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// countingReputation records every consultation and answers on demand.
type countingReputation struct {
	calls   atomic.Int32
	verdict ReputationVerdict
	answer  bool
	// delay makes the consultant slow, to prove the local path never reaches
	// it for names it should not.
	delay time.Duration
}

func (c *countingReputation) Consult(ctx context.Context, _, _ string) (ReputationVerdict, bool) {
	c.calls.Add(1)
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return ReputationVerdict{}, false
		}
	}
	return c.verdict, c.answer
}

// The property this whole feature is subordinate to: a deployment that has not
// configured a provider must behave exactly as it did before, and must not
// acquire a code path that can wait on anything.
func TestNoConsultantMeansNoReputationWork(t *testing.T) {
	e, _, _ := newEngine(t, nil)

	// Nothing installed. This is the default and the overwhelmingly common
	// case, and the cost of it must be one nil comparison.
	for _, domain := range []string{"example.com", "evil.example", "unknown.test"} {
		d := e.Evaluate("p_standard", domain)
		if d.Blocked && d.Source == "" {
			t.Errorf("%s was blocked with no source, which no local rule produces", domain)
		}
	}
	// Reaching here without a panic or a hang is the assertion: there is no
	// consultant to call, and Evaluate must not assume there is one.
}

func TestSettingAndRemovingAConsultant(t *testing.T) {
	e, _, _ := newEngine(t, nil)
	rep := &countingReputation{
		verdict: ReputationVerdict{Malicious: true, Category: "malware", ProviderName: "TestIntel"},
		answer:  true,
	}

	e.SetReputation(rep)
	d := e.Evaluate("p_standard", "nothing-local-knows.example")
	if !d.Blocked {
		t.Fatal("a malicious verdict did not block")
	}
	if d.Source != "TestIntel" {
		t.Errorf("source = %q, want the provider name — an operator has to know which third party decided", d.Source)
	}
	if d.Category != "malware" {
		t.Errorf("category = %q", d.Category)
	}

	// Removing it goes back to local-only, on the next query rather than the
	// next restart.
	before := rep.calls.Load()
	e.SetReputation(nil)
	if d := e.Evaluate("p_standard", "nothing-local-knows.example"); d.Blocked {
		t.Error("a removed consultant still blocked")
	}
	if after := rep.calls.Load(); after != before {
		t.Errorf("a removed consultant was called %d more times", after-before)
	}
}

// An allow-list entry must short-circuit before the consultant runs. Two
// reasons, and the second is the one that matters: the operator said this
// domain is fine, and a name that is never consulted is a name never disclosed
// to a third party.
func TestAnAllowedDomainIsNeverDisclosedToAProvider(t *testing.T) {
	e, st, _ := newEngine(t, nil)
	if _, err := st.UpdatePolicy(context.Background(), "p_standard", store.PolicyInput{
		AllowDomains: &[]string{"internal.corp"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	rep := &countingReputation{
		verdict: ReputationVerdict{Malicious: true, ProviderName: "TestIntel"},
		answer:  true,
	}
	e.SetReputation(rep)

	d := e.Evaluate("p_standard", "internal.corp")
	if d.Blocked {
		t.Error("an allow-listed domain was blocked by a provider")
	}
	if n := rep.calls.Load(); n != 0 {
		t.Errorf("an allow-listed domain was sent to a provider %d times", n)
	}
}

// A domain a local blocklist already condemned must not be sent either. It is
// already blocked; the lookup would change nothing and would disclose the name
// for no reason.
func TestALocallyBlockedDomainIsNotSentToAProvider(t *testing.T) {
	e, st, _ := newEngine(t, nil)
	if _, err := st.UpdatePolicy(context.Background(), "p_standard", store.PolicyInput{
		BlockDomains: &[]string{"known-bad.example"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	rep := &countingReputation{answer: true}
	e.SetReputation(rep)

	d := e.Evaluate("p_standard", "known-bad.example")
	if !d.Blocked {
		t.Fatal("the local block-list did not block")
	}
	if d.Source != "block-list" {
		t.Errorf("source = %q, want the local rule to own the decision", d.Source)
	}
	if n := rep.calls.Load(); n != 0 {
		t.Errorf("an already-blocked domain was sent to a provider %d times", n)
	}
}

// A consultant that answers "not malicious", or does not answer at all, must
// leave the decision exactly as the local rules left it.
func TestOnlyAMaliciousVerdictChangesTheOutcome(t *testing.T) {
	for _, tc := range []struct {
		name    string
		verdict ReputationVerdict
		answer  bool
	}{
		{"no answer", ReputationVerdict{}, false},
		{"answered, not malicious", ReputationVerdict{Score: 0.6, ProviderName: "X"}, true},
		{"a high score without a malicious verdict", ReputationVerdict{Score: 0.99, ProviderName: "X"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _, _ := newEngine(t, nil)
			e.SetReputation(&countingReputation{verdict: tc.verdict, answer: tc.answer})

			if d := e.Evaluate("p_standard", "ordinary.example"); d.Blocked {
				t.Errorf("%s blocked a domain: %+v", tc.name, d)
			}
		})
	}
}

// A cancelled request must not leave the evaluation waiting out a budget
// nobody is still interested in.
func TestACancelledContextEndsTheConsultation(t *testing.T) {
	e, _, _ := newEngine(t, nil)
	e.SetReputation(&countingReputation{
		verdict: ReputationVerdict{Malicious: true, ProviderName: "Slow"},
		answer:  true,
		delay:   30 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	d := e.EvaluateContext(ctx, "p_standard", "slow.example")
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Errorf("a cancelled evaluation took %s", elapsed)
	}
	if d.Blocked {
		t.Error("a cancelled consultation still produced a block")
	}
}

// Evaluate without a context must still work — every existing caller uses it,
// and it is the signature the dashboard's preview and the tests rely on.
func TestEvaluateStillWorksWithoutAContext(t *testing.T) {
	e, _, _ := newEngine(t, nil)
	e.SetReputation(&countingReputation{
		verdict: ReputationVerdict{Malicious: true, ProviderName: "Intel"},
		answer:  true,
	})
	if d := e.Evaluate("p_standard", "bad.example"); !d.Blocked {
		t.Error("Evaluate without a context did not consult")
	}
}

// A malicious verdict with no category still has to produce a usable block.
// The category ends up in the query log and on the dashboard, and an empty one
// renders as a blocked row nobody can classify.
func TestAVerdictWithNoCategoryStillProducesAUsableBlock(t *testing.T) {
	e, _, _ := newEngine(t, nil)
	e.SetReputation(&countingReputation{
		verdict: ReputationVerdict{Malicious: true, ProviderName: "Intel"}, // no category
		answer:  true,
	})
	d := e.Evaluate("p_standard", "bad.example")
	if !d.Blocked {
		t.Fatal("not blocked")
	}
	if d.Category == "" {
		t.Error("a block with no category cannot be classified in the query log")
	}
	if d.Reason == "" {
		t.Error("a block with no reason cannot be explained to a user on the phone")
	}
}
