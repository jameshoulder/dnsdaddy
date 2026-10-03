package policy

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func TestRoamingNetworkDoesNotReplaceDefaultPolicyByName(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	holder := blocklist.NewHolder()
	builder := blocklist.NewBuilder(1)
	builder.Add("blocked.example", blocklist.Entry{Category: "malware", FeedID: "fixture", FeedName: "Fixture"})
	holder.Store(builder.Build())
	engine := NewEngine(st, holder)
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("192.168.1.50")
	before := engine.MatchClient(addr)
	name, policyID := "AAA roaming laptop", "p_monitor"
	n, err := st.CreateNetwork(ctx, store.NetworkInput{Name: &name, PolicyID: &policyID})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	after := engine.MatchClient(addr)
	if after.NetworkID != clientacl.DefaultNetworkID || after.PolicyID != before.PolicyID {
		t.Fatalf("adding a token network changed unrelated clients: before=%+v after=%+v", before, after)
	}
	if !engine.Evaluate(after.PolicyID, "blocked.example").Blocked {
		t.Fatal("adding a Monitor-only roaming profile bypassed Default malware blocking")
	}
	identified, ok := engine.MatchNetworkID(n.ID)
	if !ok || identified.PolicyID != policyID {
		t.Fatal("token-identified clients lost their chosen policy")
	}
	renamed := "ZZZ renamed Default"
	if _, err := st.UpdateNetwork(ctx, clientacl.DefaultNetworkID, store.NetworkInput{Name: &renamed}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if got := engine.MatchClient(addr); got.NetworkID != clientacl.DefaultNetworkID {
		t.Fatalf("renaming Default changed its responsibility: %+v", got)
	}
}

func TestIneligibleDefaultDoesNotReplaceLegacyFallback(t *testing.T) {
	for _, tc := range []struct {
		id       string
		enabled  bool
		prefixes []netip.Prefix
	}{
		{"another", true, nil},
		{clientacl.DefaultNetworkID, false, nil},
		{clientacl.DefaultNetworkID, true, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}},
	} {
		fallback := &compiledNetwork{id: "legacy", enabled: true}
		s := &snapshot{fallback: fallback, networks: []compiledNetwork{{id: tc.id, enabled: tc.enabled, prefixes: tc.prefixes}}}
		preferDefaultNetwork(s)
		if s.fallback != fallback {
			t.Fatal("an absent, disabled or scoped Default replaced the legacy fallback")
		}
	}
}
