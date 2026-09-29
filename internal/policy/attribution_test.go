package policy

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// These tests pin client → network attribution to longest-prefix matching,
// decided per CIDR rather than per network.
//
// The defect they guard against: the engine used to rank whole networks by
// the longest prefix anywhere in their CIDR list and return the first network
// containing the client. A network holding 10.0.0.0/8 and an unrelated
// 192.0.2.123/32 therefore outranked a second network's 10.42.0.0/16 for a
// client at 10.42.1.10 — the /32 promoted the /8 — and the client silently
// received the wrong policy. On the reference configuration below that meant a
// monitor-only policy where the operator had configured a blocking one.

// addNetwork creates a network and reloads the engine.
func addNetwork(t *testing.T, st *store.Store, e *Engine, name, policyID string, cidrs ...string) store.Network {
	t.Helper()
	in := store.NetworkInput{Name: ptr(name), CIDRs: &cidrs}
	if policyID != "" {
		in.PolicyID = ptr(policyID)
	}
	n, err := st.CreateNetwork(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateNetwork(%s): %v", name, err)
	}
	if err := e.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return n
}

func TestAnUnrelatedNarrowPrefixDoesNotPromoteABroadNetwork(t *testing.T) {
	// The configuration from the review that found this. The broad network
	// carries a /32 for one host elsewhere entirely; the narrow one is a /16
	// inside the broad /8. Before the fix the broad network's /32 made it
	// "more specific" than the /16 and a client in 10.42.0.0/16 was
	// attributed to it — and to its monitor-only policy.
	e, st, _ := newEngine(t, map[string]string{"blocked.example": "malware"})

	broad := addNetwork(t, st, e, "Broad monitor network", "p_monitor",
		"10.0.0.0/8", "192.0.2.123/32")
	narrow := addNetwork(t, st, e, "Narrow security network", "p_standard",
		"10.42.0.0/16")

	m := e.MatchClient(netip.MustParseAddr("10.42.1.10"))
	if m.NetworkID != narrow.ID {
		t.Fatalf("10.42.1.10 attributed to %q (%s), want the /16 network %q",
			m.NetworkID, m.NetworkName, narrow.ID)
	}
	if m.PolicyID != "p_standard" {
		t.Fatalf("10.42.1.10 received policy %q, want the /16 network's p_standard", m.PolicyID)
	}

	// The consequence that matters: the blocking policy blocks.
	if d := e.Evaluate(m.PolicyID, "blocked.example"); !d.Blocked {
		t.Error("blocked.example resolved for a client whose network carries a blocking policy")
	}

	// The broad network still owns everything else in the /8, and the /32.
	for _, ip := range []string{"10.9.9.15", "10.43.0.1", "192.0.2.123"} {
		if m := e.MatchClient(netip.MustParseAddr(ip)); m.NetworkID != broad.ID {
			t.Errorf("%s attributed to %q, want the broad network %q", ip, m.NetworkID, broad.ID)
		}
	}
}

func TestTheMostSpecificPrefixContainingTheClientWins(t *testing.T) {
	e, st, _ := newEngine(t, nil)

	site := addNetwork(t, st, e, "Site", "p_monitor", "10.0.0.0/8", "172.16.0.0/12")
	floor := addNetwork(t, st, e, "Floor", "p_standard", "10.42.0.0/16", "172.16.5.0/24")
	host := addNetwork(t, st, e, "Host", "p_strict", "10.42.1.10/32")

	cases := []struct {
		client string
		want   store.Network
	}{
		{"10.42.1.10", host},     // the /32 beats the /16 and the /8
		{"10.42.1.11", floor},    // the /16 beats the /8
		{"10.1.1.1", site},       // only the /8 contains it
		{"172.16.5.9", floor},    // the /24 beats the /12
		{"172.16.6.9", site},     // only the /12 contains it
		{"10.42.255.255", floor}, // the top of the /16 is still inside it
	}
	for _, tc := range cases {
		m := e.MatchClient(netip.MustParseAddr(tc.client))
		if m.NetworkID != tc.want.ID {
			t.Errorf("%s attributed to %q, want %q (%s)", tc.client, m.NetworkName, tc.want.Name, tc.want.ID)
		}
	}
}

func TestEqualPrefixesAreAttributedDeterministically(t *testing.T) {
	// Two networks claiming the same range is a misconfiguration, but until an
	// operator fixes it the answer must be the same on every reload rather
	// than whichever row the database returned first. Name, then ID.
	e, st, _ := newEngine(t, nil)

	addNetwork(t, st, e, "Zulu", "p_monitor", "10.5.0.0/16")
	alpha := addNetwork(t, st, e, "Alpha", "p_strict", "10.5.0.0/16")

	for i := 0; i < 3; i++ {
		if err := e.Reload(context.Background()); err != nil {
			t.Fatalf("Reload: %v", err)
		}
		m := e.MatchClient(netip.MustParseAddr("10.5.4.3"))
		if m.NetworkID != alpha.ID {
			t.Fatalf("reload %d: 10.5.4.3 attributed to %q, want Alpha (first by name)", i, m.NetworkName)
		}
	}
}

func TestIPv6PrefixesAreMatchedByLengthWithinTheirFamily(t *testing.T) {
	e, st, _ := newEngine(t, nil)

	// The wide v6 network also carries a v4 /32, which under the old ranking
	// would have made it "more specific" than the /48 below it.
	wide := addNetwork(t, st, e, "Wide", "p_monitor", "2001:db8::/32", "192.0.2.7/32")
	narrow := addNetwork(t, st, e, "Narrow", "p_strict", "2001:db8:1::/48")

	if m := e.MatchClient(netip.MustParseAddr("2001:db8:1::5")); m.NetworkID != narrow.ID {
		t.Errorf("2001:db8:1::5 attributed to %q, want the /48 network", m.NetworkName)
	}
	if m := e.MatchClient(netip.MustParseAddr("2001:db8:2::5")); m.NetworkID != wide.ID {
		t.Errorf("2001:db8:2::5 attributed to %q, want the /32 network", m.NetworkName)
	}
	// A v4 /32 is a 32-bit prefix and a v6 /32 is a 32-bit prefix; length
	// alone must never let one family's prefix claim the other's client.
	if m := e.MatchClient(netip.MustParseAddr("2001:db8:2::5")); m.PolicyID != "p_monitor" {
		t.Errorf("v6 client received %q, want the wide network's policy", m.PolicyID)
	}
}

func TestIPv4MappedClientMatchesTheNarrowestIPv4Prefix(t *testing.T) {
	e, st, _ := newEngine(t, nil)

	addNetwork(t, st, e, "Broad", "p_monitor", "10.0.0.0/8", "192.0.2.123/32")
	narrow := addNetwork(t, st, e, "Narrow", "p_standard", "10.42.0.0/16")

	// A v4 client over a dual-stack socket arrives as ::ffff:10.42.1.10 and
	// must land exactly where 10.42.1.10 does.
	if m := e.MatchClient(netip.MustParseAddr("::ffff:10.42.1.10")); m.NetworkID != narrow.ID {
		t.Errorf("mapped client attributed to %q, want the /16 network", m.NetworkName)
	}
}

func TestADisabledNetworkContributesNoPrefixes(t *testing.T) {
	e, st, _ := newEngine(t, nil)
	ctx := context.Background()

	broad := addNetwork(t, st, e, "Broad", "p_monitor", "10.0.0.0/8")
	narrow := addNetwork(t, st, e, "Narrow", "p_strict", "10.42.0.0/16")

	if m := e.MatchClient(netip.MustParseAddr("10.42.1.10")); m.NetworkID != narrow.ID {
		t.Fatalf("precondition: expected the /16 network, got %q", m.NetworkName)
	}

	if _, err := st.UpdateNetwork(ctx, narrow.ID, store.NetworkInput{Enabled: ptr(false)}); err != nil {
		t.Fatalf("UpdateNetwork: %v", err)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// The disabled /16 no longer claims the client; the enclosing /8 does.
	if m := e.MatchClient(netip.MustParseAddr("10.42.1.10")); m.NetworkID != broad.ID {
		t.Errorf("client of a disabled network attributed to %q, want the enclosing /8", m.NetworkName)
	}
}

func TestAnUnmatchedClientLandsOnTheCatchAll(t *testing.T) {
	e, st, _ := newEngine(t, nil)

	addNetwork(t, st, e, "Broad", "p_monitor", "10.0.0.0/8", "192.0.2.123/32")
	addNetwork(t, st, e, "Narrow", "p_strict", "10.42.0.0/16")

	for _, ip := range []string{"203.0.113.9", "192.0.2.124", "2001:db8::1"} {
		m := e.MatchClient(netip.MustParseAddr(ip))
		if m.NetworkID != "n_default" {
			t.Errorf("%s attributed to %q, want the catch-all n_default", ip, m.NetworkID)
		}
	}
}

func TestTheCatchAllsPolicyIsTheFallbackPolicy(t *testing.T) {
	e, st, _ := newEngine(t, nil)
	ctx := context.Background()

	addNetwork(t, st, e, "Broad", "p_monitor", "10.0.0.0/8")

	if _, err := st.UpdateNetwork(ctx, "n_default", store.NetworkInput{PolicyID: ptr("p_strict")}); err != nil {
		t.Fatalf("UpdateNetwork(n_default): %v", err)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	m := e.MatchClient(netip.MustParseAddr("203.0.113.9"))
	if m.NetworkID != "n_default" || m.PolicyID != "p_strict" {
		t.Errorf("unmatched client got %+v, want the catch-all with its p_strict policy", m)
	}
}

// The routing table order is what the correctness argument rests on, so it is
// pinned directly rather than only through the matches above.
func TestRoutesAreOrderedLongestPrefixFirstThenByName(t *testing.T) {
	e, st, _ := newEngine(t, nil)

	addNetwork(t, st, e, "Zulu", "p_monitor", "10.0.0.0/8", "10.9.0.0/16")
	addNetwork(t, st, e, "Alpha", "p_strict", "10.9.0.0/16", "192.0.2.1/32")

	snap := e.snap.Load()
	var got []string
	for _, r := range snap.routes {
		got = append(got, r.network.name+" "+r.prefix.String())
	}
	want := []string{
		"Alpha 192.0.2.1/32",
		"Alpha 10.9.0.0/16",
		"Zulu 10.9.0.0/16",
		"Zulu 10.0.0.0/8",
	}
	if len(got) != len(want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("route %d = %q, want %q (full table %v)", i, got[i], want[i], got)
		}
	}
}
