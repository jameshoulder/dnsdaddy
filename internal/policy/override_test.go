package policy_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// overrideEngine builds an engine whose default policy blocks malware and
// allow-lists one domain that a feed also lists.
func overrideEngine(t *testing.T, allow []string, listed map[string]string) (*policy.Engine, string) {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()

	b := blocklist.NewBuilder(len(listed))
	for domain, cat := range listed {
		b.Add(domain, blocklist.Entry{Category: cat, FeedID: "f_threat", FeedName: "Threat feed"})
	}
	holder := blocklist.NewHolder()
	holder.Store(b.Build())

	p, err := st.CreatePolicy(ctx, store.PolicyInput{
		Name:         ptr("Override"),
		Categories:   &[]string{"malware"},
		AllowDomains: &allow,
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	e := policy.NewEngine(st, holder)
	if err := e.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return e, p.ID
}

func ptr(s string) *string { return &s }

// TestAnAllowListWinNamesTheListingItBeat.
//
// This is the property the brief calls out and the one the engine could not
// support: the allow-list short-circuits before the feed index is consulted,
// so a decision recorded from it said "allowed by the operator" and nothing
// about the listing it overrode. An operator asking "why is this malware
// domain resolving?" got an answer that did not mention the malware.
//
// Both facts have to survive: the allow-list caused the outcome, and there was
// a listing it beat.
func TestAnAllowListWinNamesTheListingItBeat(t *testing.T) {
	e, pid := overrideEngine(t,
		[]string{"vendor.example"},
		map[string]string{"vendor.example": "malware"},
	)

	d := e.Evaluate(pid, "vendor.example")
	if d.Blocked {
		t.Fatal("the allow-list did not win; the rest of this test is meaningless")
	}
	if d.Basis == nil || d.Basis.Rule != policy.RuleAllowList {
		t.Fatalf("basis = %+v, want an allow-list rule", d.Basis)
	}
	if d.Basis.OverrodeFeedName != "Threat feed" {
		t.Errorf("OverrodeFeedName = %q, want the feed the allow-list beat", d.Basis.OverrodeFeedName)
	}
	if d.Basis.OverrodeFeedID != "f_threat" {
		t.Errorf("OverrodeFeedID = %q", d.Basis.OverrodeFeedID)
	}
	if d.Basis.OverrodeCategory != "malware" {
		t.Errorf("OverrodeCategory = %q, want malware", d.Basis.OverrodeCategory)
	}
}

// TestAnAllowListWinOverNothingSaysNothing. Most allow-listed domains are not
// on any feed, and inventing an override for them would put a malware claim
// next to a domain no list has ever mentioned.
func TestAnAllowListWinOverNothingSaysNothing(t *testing.T) {
	e, pid := overrideEngine(t, []string{"safe.example"}, map[string]string{"other.example": "malware"})

	d := e.Evaluate(pid, "safe.example")
	if d.Basis == nil || d.Basis.Rule != policy.RuleAllowList {
		t.Fatalf("basis = %+v", d.Basis)
	}
	if d.Basis.OverrodeFeedName != "" || d.Basis.OverrodeFeedID != "" || d.Basis.OverrodeCategory != "" {
		t.Errorf("an allow-list win over no listing invented an override: %+v", d.Basis)
	}
}

// TestAnAllowListWinOverACategoryThePolicyDoesNotBlockSaysNothing.
//
// The domain is listed, but under a category this policy has not enabled, so
// nothing was overridden — the domain would have resolved anyway. Claiming an
// override would tell the operator their allow-list is load-bearing when it is
// not, and they might remove it expecting a block.
func TestAnAllowListWinOverACategoryThePolicyDoesNotBlockSaysNothing(t *testing.T) {
	e, pid := overrideEngine(t,
		[]string{"ads.example"},
		map[string]string{"ads.example": "ads"}, // policy enables malware only
	)

	d := e.Evaluate(pid, "ads.example")
	if d.Basis == nil || d.Basis.Rule != policy.RuleAllowList {
		t.Fatalf("basis = %+v", d.Basis)
	}
	if d.Basis.OverrodeFeedName != "" {
		t.Errorf("claimed an override of a category this policy does not block: %+v", d.Basis)
	}
}

// TestTheOverrideLookupDoesNotChangeTheDecision. Consulting the feed index on
// the allow-list path is for the record only; a domain the operator allowed
// must still resolve.
func TestTheOverrideLookupDoesNotChangeTheDecision(t *testing.T) {
	e, pid := overrideEngine(t,
		[]string{"vendor.example"},
		map[string]string{"vendor.example": "malware"},
	)
	d := e.Evaluate(pid, "vendor.example")
	if d.Blocked {
		t.Error("recording the override blocked an allow-listed domain")
	}
	if d.Reason != "Allowed by policy allow-list" {
		t.Errorf("reason = %q, want the allow-list reason unchanged", d.Reason)
	}
	if d.Source != "allow-list" {
		t.Errorf("source = %q", d.Source)
	}
}

// TestASubdomainOfAnAllowListedNameAlsoReportsTheOverride, because allow-list
// matching is suffix-based and the feed may list the subdomain specifically.
func TestASubdomainOfAnAllowListedNameAlsoReportsTheOverride(t *testing.T) {
	e, pid := overrideEngine(t,
		[]string{"vendor.example"},
		map[string]string{"tracker.vendor.example": "malware"},
	)

	d := e.Evaluate(pid, "tracker.vendor.example")
	if d.Blocked {
		t.Fatal("the allow-list did not cover the subdomain")
	}
	if d.Basis.OverrodeCategory != "malware" {
		t.Errorf("the subdomain's listing was not reported as overridden: %+v", d.Basis)
	}
}
