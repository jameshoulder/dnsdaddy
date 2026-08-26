package policy

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func ptr[T any](v T) *T { return &v }

// newEngine returns an engine backed by a temporary store and a blocklist
// containing the given domain→category pairs.
func newEngine(t *testing.T, lists map[string]string) (*Engine, *store.Store, *blocklist.Holder) {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	holder := blocklist.NewHolder()
	b := blocklist.NewBuilder(len(lists))
	for domain, cat := range lists {
		b.Add(domain, blocklist.Entry{Category: cat, FeedID: "f_test", FeedName: "Test feed"})
	}
	holder.Store(b.Build())

	e := NewEngine(st, holder)
	if err := e.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return e, st, holder
}

func TestEvaluateBlocksEnabledCategory(t *testing.T) {
	e, _, _ := newEngine(t, map[string]string{"evil.com": "malware"})

	d := e.Evaluate("p_standard", "evil.com")
	if !d.Blocked {
		t.Fatal("a malware domain was not blocked by the default policy")
	}
	if d.Category != "malware" {
		t.Errorf("Category = %q, want malware", d.Category)
	}
	if d.Reason == "" {
		t.Error("no block reason recorded; the query log would say nothing useful")
	}
	if d.Source != "Test feed" {
		t.Errorf("Source = %q, want the contributing feed name", d.Source)
	}
}

func TestEvaluateBlocksSubdomains(t *testing.T) {
	e, _, _ := newEngine(t, map[string]string{"evil.com": "malware"})

	if d := e.Evaluate("p_standard", "login.evil.com"); !d.Blocked {
		t.Error("a subdomain of a blocked domain resolved")
	}
	if d := e.Evaluate("p_standard", "notevil.com"); d.Blocked {
		t.Error("a lookalike domain was blocked by suffix confusion")
	}
}

func TestEvaluateIgnoresDisabledCategory(t *testing.T) {
	// "adult" is not in the default policy, so an adult-classified domain must
	// resolve even though it is in the index.
	e, _, _ := newEngine(t, map[string]string{"adult.example": "adult"})

	if d := e.Evaluate("p_standard", "adult.example"); d.Blocked {
		t.Error("a category the policy does not enable was blocked anyway")
	}
	if d := e.Evaluate("p_strict", "adult.example"); !d.Blocked {
		t.Error("the strict policy did not block adult content")
	}
}

func TestAllowListBeatsBlocklist(t *testing.T) {
	// This is the false-positive escape hatch: an operator must be able to
	// clear a bad entry without waiting for a feed to be corrected.
	e, st, _ := newEngine(t, map[string]string{"supplier.example": "phishing"})
	ctx := context.Background()

	if d := e.Evaluate("p_standard", "supplier.example"); !d.Blocked {
		t.Fatal("precondition failed: the domain should start out blocked")
	}

	if _, err := st.UpdatePolicy(ctx, "p_standard", store.PolicyInput{
		AllowDomains: &[]string{"supplier.example"},
	}); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	d := e.Evaluate("p_standard", "supplier.example")
	if d.Blocked {
		t.Error("the allow list did not override the blocklist")
	}
	if d := e.Evaluate("p_standard", "www.supplier.example"); d.Blocked {
		t.Error("allow-listing a domain did not cover its subdomains")
	}
}

func TestCustomBlockList(t *testing.T) {
	e, st, _ := newEngine(t, nil)
	ctx := context.Background()

	if err := st.AddPolicyRule(ctx, "p_standard", "block", "timewaster.example", "ticket 4412"); err != nil {
		t.Fatalf("AddPolicyRule: %v", err)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	d := e.Evaluate("p_standard", "sub.timewaster.example")
	if !d.Blocked {
		t.Fatal("the custom block list did not take effect")
	}
	if d.Category != "custom" {
		t.Errorf("Category = %q, want custom", d.Category)
	}
}

func TestMonitorOnlyPolicyBlocksNothing(t *testing.T) {
	e, _, _ := newEngine(t, map[string]string{"evil.com": "malware"})

	d := e.Evaluate("p_monitor", "evil.com")
	if d.Blocked {
		t.Error("the monitor-only policy blocked a query")
	}
	if !d.LogQuery {
		t.Error("the monitor-only policy is not logging, which is its entire purpose")
	}
}

func TestMatchClientPrefersMostSpecificNetwork(t *testing.T) {
	e, st, _ := newEngine(t, nil)
	ctx := context.Background()

	broad, err := st.CreateNetwork(ctx, store.NetworkInput{
		Name: ptr("Office"), CIDRs: &[]string{"10.0.0.0/8"}, PolicyID: ptr("p_standard"),
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	narrow, err := st.CreateNetwork(ctx, store.NetworkInput{
		Name: ptr("Production floor"), CIDRs: &[]string{"10.4.9.0/24"}, PolicyID: ptr("p_strict"),
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if m := e.MatchClient(netip.MustParseAddr("10.4.9.15")); m.NetworkID != narrow.ID {
		t.Errorf("matched %q, want the more specific network %q", m.NetworkID, narrow.ID)
	}
	if m := e.MatchClient(netip.MustParseAddr("10.9.9.15")); m.NetworkID != broad.ID {
		t.Errorf("matched %q, want the broad network %q", m.NetworkID, broad.ID)
	}
}

func TestMatchClientFallsBackToCatchAll(t *testing.T) {
	e, st, _ := newEngine(t, nil)
	ctx := context.Background()

	if _, err := st.CreateNetwork(ctx, store.NetworkInput{
		Name: ptr("Office"), CIDRs: &[]string{"10.0.0.0/8"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	m := e.MatchClient(netip.MustParseAddr("203.0.113.7"))
	if m.NetworkID != "n_default" {
		t.Errorf("unmatched client landed on %q, want the catch-all n_default", m.NetworkID)
	}
}

func TestMatchClientHandlesIPv4MappedAddresses(t *testing.T) {
	// A v4 client arriving over a dual-stack socket shows up as ::ffff:10.0.0.5
	// and must still match the v4 prefix it belongs to.
	e, st, _ := newEngine(t, nil)
	ctx := context.Background()

	n, err := st.CreateNetwork(ctx, store.NetworkInput{
		Name: ptr("Office"), CIDRs: &[]string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if m := e.MatchClient(netip.MustParseAddr("::ffff:10.0.0.5")); m.NetworkID != n.ID {
		t.Errorf("v4-mapped client matched %q, want %q", m.NetworkID, n.ID)
	}
}

func TestMatchNetworkID(t *testing.T) {
	e, _, _ := newEngine(t, nil)

	m, ok := e.MatchNetworkID("n_default")
	if !ok || m.PolicyID != "p_standard" {
		t.Errorf("MatchNetworkID = (%+v, %v), want the seeded network", m, ok)
	}
	if _, ok := e.MatchNetworkID("n_nonexistent"); ok {
		t.Error("MatchNetworkID resolved an unknown network")
	}
}

func TestEvaluateUnknownPolicyUsesDefault(t *testing.T) {
	e, _, _ := newEngine(t, map[string]string{"evil.com": "malware"})

	if d := e.Evaluate("p_does_not_exist", "evil.com"); !d.Blocked {
		t.Error("an unknown policy ID skipped filtering entirely; it must fall back to the default")
	}
}

func TestClientNaming(t *testing.T) {
	e, st, _ := newEngine(t, nil)
	ctx := context.Background()

	if err := st.SetClientName(ctx, "10.0.4.23", "laptop-07"); err != nil {
		t.Fatalf("SetClientName: %v", err)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := e.ClientName("10.0.4.23"); got != "laptop-07" {
		t.Errorf("ClientName = %q, want laptop-07", got)
	}
	if got := e.ClientName("10.0.4.99"); got != "" {
		t.Errorf("ClientName for an unnamed device = %q, want empty", got)
	}
}

func BenchmarkEvaluateMiss(b *testing.B) {
	st, err := store.Open(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()

	holder := blocklist.NewHolder()
	builder := blocklist.NewBuilder(200000)
	for i := 0; i < 200000; i++ {
		builder.Add(benchDomain(i), blocklist.Entry{Category: "malware"})
	}
	holder.Store(builder.Build())

	e := NewEngine(st, holder)
	if err := e.Reload(context.Background()); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Evaluate("p_standard", "www.legitimate-business.co.uk")
	}
}

func benchDomain(i int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, 0, 16)
	n := i
	for j := 0; j < 8; j++ {
		buf = append(buf, letters[n%26])
		n /= 26
	}
	return string(buf) + ".example"
}

// newEngineMultiCategory returns an engine whose index holds the given
// domain→categories claims, each attributed to a named feed.
func newEngineMultiCategory(t *testing.T, claims map[string]map[string]string) (*Engine, *store.Store) {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	holder := blocklist.NewHolder()
	b := blocklist.NewBuilder(8)
	for domain, byCategory := range claims {
		for category, feed := range byCategory {
			b.Add(domain, blocklist.Entry{Category: category, FeedID: "f_" + feed, FeedName: feed})
		}
	}
	holder.Store(b.Build())

	e := NewEngine(st, holder)
	if err := e.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return e, st
}

// policyWith creates a policy enabling exactly the given categories.
func policyWith(t *testing.T, st *store.Store, e *Engine, name string, categories []string) string {
	t.Helper()
	p, err := st.CreatePolicy(context.Background(), store.PolicyInput{
		Name: &name, Categories: &categories,
	})
	if err != nil {
		t.Fatalf("CreatePolicy(%s): %v", name, err)
	}
	if err := e.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return p.ID
}

func TestMultiCategoryIndicatorBlocksUnderEitherCategory(t *testing.T) {
	// One Observatory indicator tagged both malware and C2. A policy enabling
	// either one has to block it: the operator ticking "C2" has no idea the
	// domain is also on a malware list, and should not need to.
	e, st := newEngineMultiCategory(t, map[string]map[string]string{
		"evil.example": {"malware": "Observatory", "c2": "Observatory"},
	})

	cases := []struct {
		name       string
		categories []string
		want       bool
		wantReason string
	}{
		{"malware only", []string{"malware"}, true, "malware"},
		{"c2 only", []string{"c2"}, true, "c2"},
		{"both", []string{"malware", "c2"}, true, "malware"},
		{"neither", []string{"phishing", "gambling"}, false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := policyWith(t, st, e, "p "+tc.name, tc.categories)
			d := e.Evaluate(id, "evil.example")
			if d.Blocked != tc.want {
				t.Fatalf("Blocked = %v, want %v", d.Blocked, tc.want)
			}
			if !tc.want {
				return
			}
			// The reason names a category the operator actually enabled —
			// reporting "malware" to someone who only enabled C2 would be a
			// block they cannot account for.
			if d.Category != tc.wantReason {
				t.Errorf("Category = %q, want %q", d.Category, tc.wantReason)
			}
			if !slices.Contains(tc.categories, d.Category) {
				t.Errorf("blocked under %q, which this policy does not enable", d.Category)
			}
			if d.Reason == "" {
				t.Error("no plain-English reason recorded")
			}
		})
	}
}

func TestDisagreeingFeedsBothBlock(t *testing.T) {
	// URLhaus calls it malware; the Observatory calls it C2. Both claims are
	// real, and a policy enabling either one blocks the domain — with the
	// reason and the source naming the feed that made the claim it matched.
	e, st := newEngineMultiCategory(t, map[string]map[string]string{
		"shared.example": {"malware": "URLhaus", "c2": "Observatory"},
	})

	malwareOnly := policyWith(t, st, e, "malware only", []string{"malware"})
	c2Only := policyWith(t, st, e, "c2 only", []string{"c2"})

	d := e.Evaluate(malwareOnly, "shared.example")
	if !d.Blocked || d.Category != "malware" {
		t.Errorf("malware-only policy: Blocked=%v Category=%q, want true/malware", d.Blocked, d.Category)
	}
	if d.Source != "URLhaus" {
		t.Errorf("malware-only policy: Source = %q, want URLhaus", d.Source)
	}

	d = e.Evaluate(c2Only, "shared.example")
	if !d.Blocked || d.Category != "c2" {
		t.Errorf("c2-only policy: Blocked=%v Category=%q, want true/c2", d.Blocked, d.Category)
	}
	if d.Source != "Observatory" {
		t.Errorf("c2-only policy: Source = %q, want Observatory", d.Source)
	}

	// Subdomains inherit whichever claim the policy enables.
	if d := e.Evaluate(c2Only, "login.shared.example"); !d.Blocked {
		t.Error("a subdomain was not blocked under the c2 claim")
	}
}

func TestAllowListStillBeatsEveryClaim(t *testing.T) {
	// The escape hatch has to keep working no matter how many categories claim
	// a domain, or a false positive becomes unclearable.
	e, st := newEngineMultiCategory(t, map[string]map[string]string{
		"supplier.example": {"malware": "Observatory", "c2": "Observatory", "phishing": "Phishing Army"},
	})
	id := policyWith(t, st, e, "everything", []string{"malware", "c2", "phishing"})

	if d := e.Evaluate(id, "supplier.example"); !d.Blocked {
		t.Fatal("precondition: the domain should be blocked before allow-listing")
	}
	if err := st.AddPolicyRule(context.Background(), id, "allow", "supplier.example", "false positive"); err != nil {
		t.Fatalf("AddPolicyRule: %v", err)
	}
	if err := e.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if d := e.Evaluate(id, "supplier.example"); d.Blocked {
		t.Error("the allow list did not beat a multi-category claim")
	}
}

func TestParentClaimIsNotShadowedByAnUnenabledChildListing(t *testing.T) {
	// evil.example is malware; login.evil.example turns up on an ads list too.
	// A malware-only policy must still block the child — "blocking evil.example
	// blocks login.evil.example" cannot depend on which other lists the child
	// happens to appear on.
	e, st := newEngineMultiCategory(t, map[string]map[string]string{
		"evil.example":       {"malware": "URLhaus"},
		"login.evil.example": {"ads": "StevenBlack"},
	})
	id := policyWith(t, st, e, "malware only", []string{"malware"})

	d := e.Evaluate(id, "login.evil.example")
	if !d.Blocked {
		t.Fatal("an ads listing on the child shadowed the parent's malware listing")
	}
	if d.Category != "malware" {
		t.Errorf("Category = %q, want malware", d.Category)
	}
}
