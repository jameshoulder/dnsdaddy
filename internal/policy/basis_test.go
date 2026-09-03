package policy

import (
	"context"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// The basis has to identify what decided, for every rule, or the decision
// record cannot be built from it.
func TestEveryRuleReportsItsBasis(t *testing.T) {
	ctx := context.Background()
	e, st, _ := newEngine(t, nil)

	if _, err := st.UpdatePolicy(ctx, "p_standard", store.PolicyInput{
		AllowDomains: &[]string{"allowed.example"},
		BlockDomains: &[]string{"blocked.example"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	allowed := e.Evaluate("p_standard", "allowed.example")
	if allowed.Basis.Rule != RuleAllowList {
		t.Errorf("allow-list basis = %q", allowed.Basis.Rule)
	}
	if !allowed.Basis.Decided() {
		t.Error("an allow-list hit reports no decision")
	}

	blocked := e.Evaluate("p_standard", "blocked.example")
	if blocked.Basis.Rule != RuleBlockList {
		t.Errorf("block-list basis = %q", blocked.Basis.Rule)
	}
	if blocked.Basis.Category != "custom" {
		t.Errorf("block-list category = %q", blocked.Basis.Category)
	}

	// Every basis carries the policy that was in force, whichever rule fired.
	for name, d := range map[string]Decision{"allow": allowed, "block": blocked} {
		if d.Basis.PolicyID == "" || d.Basis.PolicyName == "" {
			t.Errorf("%s basis does not name the policy in force: %+v", name, d.Basis)
		}
	}
}

// A category hit must name the feed by ID as well as by name. The ID is what
// survives a rename, and an explanation that can only point at a name breaks
// the moment somebody edits it.
func TestACategoryBlockNamesTheFeedById(t *testing.T) {
	e, _, _ := newEngine(t, map[string]string{"evil.com": "malware"})
	d := e.Evaluate("p_standard", "evil.com")
	if !d.Blocked {
		t.Fatal("the fixture blocklist did not block")
	}
	if d.Basis.Rule != RuleCategory {
		t.Fatalf("basis rule = %q, want category", d.Basis.Rule)
	}
	if d.Basis.FeedID == "" {
		t.Error("a category block does not record which feed listed the domain")
	}
	if d.Basis.Category == "" {
		t.Error("a category block records no category")
	}
}

// An ordinary allowed query has nothing to explain and must say so, or the
// recorder would write a record per query rather than per decision.
func TestAnOrdinaryQueryHasNoBasis(t *testing.T) {
	e, _, _ := newEngine(t, map[string]string{"evil.com": "malware"})
	d := e.Evaluate("p_standard", "nothing-knows-this.example")
	if d.Blocked {
		t.Fatal("an unrelated domain was blocked")
	}
	if d.Basis.Decided() {
		t.Errorf("an ordinary query reported a basis: %+v", d.Basis)
	}
}

// The basis must not cost an allocation on the resolution path. It is string
// headers copied from the compiled snapshot, and if that ever stops being true
// the cost lands on every query rather than on the blocked few.
//
// Asserted as a test rather than left to a benchmark nobody runs: a regression
// here is invisible until somebody profiles a busy resolver.
func TestEvaluateAllocatesNothingForAnOrdinaryQuery(t *testing.T) {
	e, _, _ := newEngine(t, map[string]string{"evil.com": "malware"})
	// Warm any lazy initialisation so it is not charged to the measurement.
	_ = e.Evaluate("p_standard", "ordinary.example")

	allocs := testing.AllocsPerRun(200, func() {
		_ = e.Evaluate("p_standard", "ordinary.example")
	})
	if allocs > 0 {
		t.Errorf("Evaluate allocated %.1f times per allowed query; the basis must be "+
			"string headers copied from the snapshot, not new memory", allocs)
	}
}

// And a blocked query — which does populate the basis — must not allocate
// either, since every field is a string already held by the snapshot or the
// blocklist entry.
func TestEvaluateAllocatesNothingForABlockedQuery(t *testing.T) {
	e, _, _ := newEngine(t, map[string]string{"evil.com": "malware"})
	_ = e.Evaluate("p_standard", "evil.com")

	allocs := testing.AllocsPerRun(200, func() {
		_ = e.Evaluate("p_standard", "evil.com")
	})
	if allocs > 0 {
		t.Errorf("a blocked query allocated %.1f times; populating the basis was "+
			"supposed to be free", allocs)
	}
}
