package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func seedNetworkMap(t *testing.T, st *Store) (time.Time, Network, Network) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	lan := mustCreateNetwork(t, st, NetworkInput{
		Name: ptr("LAN"), Enabled: ptr(true), AllowResolver: ptr(true),
		CIDRs: ptr([]string{"10.0.0.0/24"}),
	})
	guest := mustCreateNetwork(t, st, NetworkInput{
		Name: ptr("Guest"), Enabled: ptr(true), AllowResolver: ptr(true),
		CIDRs: ptr([]string{"10.1.0.0/24"}),
	})

	ev := func(ago time.Duration, ip, name, net, domain, action, category, qtype string) QueryEvent {
		return QueryEvent{
			Time: now.Add(-ago), ClientIP: ip, ClientName: name, NetworkID: net,
			Domain: domain, QType: qtype, Action: action, Category: category,
		}
	}
	events := []QueryEvent{
		ev(5*time.Minute, "10.0.0.1", "laptop", lan.ID, "evil.example", ActionBlocked, "malware", "A"),
		ev(4*time.Minute, "10.0.0.1", "laptop", lan.ID, "evil.example", ActionBlocked, "malware", "AAAA"),
		ev(3*time.Minute, "10.0.0.1", "laptop", lan.ID, "news.example", ActionAllowed, "", "A"),
		ev(2*time.Minute, "10.0.0.2", "forwarder", lan.ID, "evil.example", ActionAllowed, "", "A"),
		ev(2*time.Minute, "10.0.0.2", "forwarder", lan.ID, "ads.example", ActionBlocked, "ads", "A"),
		ev(90*time.Second, "10.1.0.5", "phone", guest.ID, "evil.example", ActionBlocked, "malware", "A"),
		ev(60*time.Second, "10.1.0.5", "phone", guest.ID, "cdn.example", ActionError, "", "A"),
		ev(30*time.Second, "", "", lan.ID, "anon.example", ActionAllowed, "", "A"),
		ev(48*time.Hour, "10.0.0.9", "old", lan.ID, "stale.example", ActionBlocked, "malware", "A"),
		ev(20*time.Second, "10.0.0.3", "<img src=x onerror=alert(1)>", lan.ID, "\"><svg/onload=alert(1)>.example", ActionAllowed, "", "A"),
	}
	if err := st.InsertQueryBatch(ctx, events, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}
	if err := st.InsertFindings(ctx, []Finding{
		{
			ID: "f-evil", Time: now.Add(-3 * time.Minute), EventType: "dns.tunnel.suspected",
			Severity: "medium", Confidence: 0.6, Score: 0.5, ClientIP: "10.0.0.1", NetworkID: lan.ID,
			Domain: "evil.example", Detector: "fixture", Title: "Suspicious volume", Summary: "fixture",
			Detail: `{"schemaVersion":1}`,
		},
		{
			ID: "f-orphan", Time: now.Add(-2 * time.Minute), EventType: "dns.nxdomain.burst",
			Severity: "low", ClientIP: "10.0.0.99", NetworkID: lan.ID, Domain: "missing.example",
			Detector: "fixture", Title: "Orphan finding", Summary: "no matching query edge",
			Detail: `{"schemaVersion":1}`,
		},
	}); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}
	return now, lan, guest
}

func TestBuildNetworkMapAggregatesWithoutFindingJoinInflation(t *testing.T) {
	st := newTestStore(t)
	now, lan, guest := seedNetworkMap(t, st)
	ctx := context.Background()

	networks, err := st.ListNetworks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	findings, _, err := st.ListFindings(ctx, FindingFilter{Since: now.Add(-time.Hour), Limit: 50})
	if err != nil {
		t.Fatal(err)
	}

	g, err := st.BuildNetworkMap(ctx, NetworkMapFilter{
		Since: now.Add(-time.Hour), Until: now.Add(time.Minute),
		MaxClients: 50, MaxDomains: 50, MaxEdges: 100, MaxSourceRows: 1000,
	}, networks, findings)
	if err != nil {
		t.Fatalf("BuildNetworkMap: %v", err)
	}

	var laptop *NetworkMapClient
	for i := range g.Clients {
		if g.Clients[i].ClientIP == "10.0.0.1" && g.Clients[i].NetworkID == lan.ID {
			laptop = &g.Clients[i]
		}
	}
	if laptop == nil {
		t.Fatalf("laptop missing: %+v", g.Clients)
	}
	if laptop.Queries != 3 || laptop.Blocked != 2 || laptop.Allowed != 1 {
		t.Fatalf("laptop outcomes = %+v, want 3 queries / 2 blocked / 1 allowed", laptop)
	}

	var evilEdge *NetworkMapEdge
	for i := range g.Edges {
		if g.Edges[i].ClientID == laptop.ID && strings.Contains(g.Edges[i].DomainID, "evil.example") {
			evilEdge = &g.Edges[i]
		}
	}
	if evilEdge == nil || evilEdge.Queries != 2 || evilEdge.Blocked != 2 {
		t.Fatalf("evil edge = %+v", evilEdge)
	}
	if !strings.Contains(evilEdge.Meaning, "not proof") {
		t.Errorf("edge meaning missing honesty: %q", evilEdge.Meaning)
	}

	var sawLAN, sawGuest bool
	for _, n := range g.Networks {
		if n.ID == lan.ID {
			sawLAN = true
		}
		if n.ID == guest.ID {
			sawGuest = true
		}
	}
	if !sawLAN || !sawGuest {
		t.Fatalf("networks = %+v", g.Networks)
	}

	var linked, orphanAttached bool
	for _, f := range g.Findings {
		if f.ID == "f-evil" && f.ClientID == laptop.ID && f.DomainID != "" {
			linked = true
		}
		if f.ID == "f-orphan" {
			orphanAttached = true
			for _, e := range g.Edges {
				if e.DomainID == domainNodeID("missing.example") {
					t.Fatal("orphan finding invented a queried edge")
				}
			}
		}
	}
	if !linked {
		t.Fatalf("finding not linked to laptop: %+v", g.Findings)
	}
	if !orphanAttached {
		t.Fatal("orphan finding dropped entirely")
	}
	if g.Totals.UnattributedQueries < 1 {
		t.Errorf("expected unattributed count, got %+v", g.Totals)
	}
}

func TestBuildNetworkMapDoesNotGuessAmbiguousFindingNetwork(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	a := mustCreateNetwork(t, st, NetworkInput{
		Name: ptr("A"), Enabled: ptr(true), AllowResolver: ptr(true),
		CIDRs: ptr([]string{"10.0.0.0/24"}),
	})
	b := mustCreateNetwork(t, st, NetworkInput{
		Name: ptr("B"), Enabled: ptr(true), AllowResolver: ptr(true),
		CIDRs: ptr([]string{"10.2.0.0/24"}),
	})
	if err := st.InsertQueryBatch(ctx, []QueryEvent{
		{Time: now.Add(-time.Minute), ClientIP: "10.0.0.50", NetworkID: a.ID, Domain: "one.example", QType: "A", Action: ActionAllowed},
		{Time: now.Add(-time.Minute), ClientIP: "10.0.0.50", NetworkID: b.ID, Domain: "two.example", QType: "A", Action: ActionAllowed},
	}, true); err != nil {
		t.Fatal(err)
	}
	networks, _ := st.ListNetworks(ctx)
	g, err := st.BuildNetworkMap(ctx, NetworkMapFilter{
		Since: now.Add(-time.Hour), Until: now.Add(time.Minute),
		MaxClients: 10, MaxDomains: 10, MaxEdges: 20, MaxSourceRows: 100,
	}, networks, []Finding{{
		ID: "f-ambiguous", Time: now, EventType: "dns.tunnel.suspected", Severity: "low",
		ClientIP: "10.0.0.50", Domain: "one.example", Detector: "fixture",
		Title: "Ambiguous", Summary: "no network id", Detail: `{}`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var found *NetworkMapFinding
	for i := range g.Findings {
		if g.Findings[i].ID == "f-ambiguous" {
			found = &g.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("finding missing")
	}
	if found.ClientID != "" || found.NetworkID != "" {
		t.Fatalf("ambiguous finding must not invent a network context: %+v", found)
	}
	if found.DomainID == "" {
		t.Fatal("domain link should still attach")
	}
}

func TestBuildNetworkMapKeepsNewestClientNameAndBlockCategory(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	lan := mustCreateNetwork(t, st, NetworkInput{
		Name: ptr("LAN"), Enabled: ptr(true), AllowResolver: ptr(true),
		CIDRs: ptr([]string{"10.0.0.0/24"}),
	})
	if err := st.InsertQueryBatch(ctx, []QueryEvent{
		{Time: now.Add(-10 * time.Minute), ClientIP: "10.0.0.7", ClientName: "old-name", NetworkID: lan.ID, Domain: "a.example", QType: "A", Action: ActionBlocked, Category: "ads"},
		{Time: now.Add(-2 * time.Minute), ClientIP: "10.0.0.7", ClientName: "new-name", NetworkID: lan.ID, Domain: "b.example", QType: "A", Action: ActionBlocked, Category: "malware"},
		{Time: now.Add(-time.Minute), ClientIP: "10.0.0.7", ClientName: "new-name", NetworkID: lan.ID, Domain: "c.example", QType: "A", Action: ActionAllowed},
	}, true); err != nil {
		t.Fatal(err)
	}
	networks, _ := st.ListNetworks(ctx)
	g, err := st.BuildNetworkMap(ctx, NetworkMapFilter{
		Since: now.Add(-time.Hour), Until: now.Add(time.Minute),
		MaxClients: 10, MaxDomains: 10, MaxEdges: 20, MaxSourceRows: 100,
	}, networks, nil)
	if err != nil {
		t.Fatal(err)
	}
	var client *NetworkMapClient
	for i := range g.Clients {
		if g.Clients[i].ClientIP == "10.0.0.7" {
			client = &g.Clients[i]
		}
	}
	if client == nil || client.ClientName != "new-name" {
		t.Fatalf("client name = %+v, want newest new-name", client)
	}
	var domain *NetworkMapDomain
	for i := range g.Domains {
		if g.Domains[i].Domain == "a.example" || g.Domains[i].Domain == "b.example" {
			if g.Domains[i].Domain == "b.example" {
				domain = &g.Domains[i]
			}
		}
	}
	if domain == nil || domain.Category != "malware" {
		t.Fatalf("newest blocked domain category = %+v, want malware", domain)
	}
	// Domain a.example only saw ads; that remains its category.
	for _, d := range g.Domains {
		if d.Domain == "a.example" && d.Category != "ads" {
			t.Fatalf("a.example category = %q, want ads", d.Category)
		}
	}
}

func TestBuildNetworkMapRespectsNetworkAndActionFilters(t *testing.T) {
	st := newTestStore(t)
	now, lan, _ := seedNetworkMap(t, st)
	ctx := context.Background()
	networks, _ := st.ListNetworks(ctx)

	g, err := st.BuildNetworkMap(ctx, NetworkMapFilter{
		Since: now.Add(-time.Hour), Until: now.Add(time.Minute),
		NetworkID: lan.ID, Action: ActionBlocked,
		MaxClients: 50, MaxDomains: 50, MaxEdges: 100, MaxSourceRows: 1000,
	}, networks, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range g.Clients {
		if c.NetworkID != lan.ID {
			t.Fatalf("client outside filter: %+v", c)
		}
		if c.Allowed != 0 || c.Errors != 0 {
			t.Fatalf("non-blocked outcomes leaked under action=blocked: %+v", c)
		}
	}
	for _, e := range g.Edges {
		if e.Allowed != 0 || e.Errors != 0 || e.Blocked == 0 {
			t.Fatalf("edge outcomes under blocked filter: %+v", e)
		}
	}
}

func TestBuildNetworkMapDoesNotMergeSameIPAcrossNetworks(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	a := mustCreateNetwork(t, st, NetworkInput{
		Name: ptr("A"), Enabled: ptr(true), AllowResolver: ptr(true),
		CIDRs: ptr([]string{"10.0.0.0/24"}),
	})
	b := mustCreateNetwork(t, st, NetworkInput{
		Name: ptr("B"), Enabled: ptr(true), AllowResolver: ptr(true),
		CIDRs: ptr([]string{"10.2.0.0/24"}),
	})
	if err := st.InsertQueryBatch(ctx, []QueryEvent{
		{Time: now.Add(-time.Minute), ClientIP: "10.0.0.50", NetworkID: a.ID, Domain: "one.example", QType: "A", Action: ActionAllowed},
		{Time: now.Add(-time.Minute), ClientIP: "10.0.0.50", NetworkID: b.ID, Domain: "two.example", QType: "A", Action: ActionAllowed},
	}, true); err != nil {
		t.Fatal(err)
	}
	networks, _ := st.ListNetworks(ctx)
	g, err := st.BuildNetworkMap(ctx, NetworkMapFilter{
		Since: now.Add(-time.Hour), Until: now.Add(time.Minute),
		MaxClients: 10, MaxDomains: 10, MaxEdges: 20, MaxSourceRows: 100,
	}, networks, nil)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, c := range g.Clients {
		if c.ClientIP == "10.0.0.50" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("expected two client nodes for same IP in different networks, got %d: %+v", n, g.Clients)
	}
}

func TestBuildNetworkMapTruncationIsReported(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	net := mustCreateNetwork(t, st, NetworkInput{
		Name: ptr("Busy"), Enabled: ptr(true), AllowResolver: ptr(true),
		CIDRs: ptr([]string{"10.0.0.0/8"}),
	})
	events := make([]QueryEvent, 0, 12)
	for i := 1; i <= 12; i++ {
		events = append(events, QueryEvent{
			Time:     now.Add(-time.Duration(i) * time.Second),
			ClientIP: fmt.Sprintf("10.0.0.%d", i), NetworkID: net.ID,
			Domain: fmt.Sprintf("host%d.example", i), QType: "A", Action: ActionAllowed,
		})
	}
	if err := st.InsertQueryBatch(ctx, events, true); err != nil {
		t.Fatal(err)
	}
	networks, _ := st.ListNetworks(ctx)
	g, err := st.BuildNetworkMap(ctx, NetworkMapFilter{
		Since: now.Add(-time.Hour), Until: now.Add(time.Minute),
		MaxClients: 5, MaxDomains: 5, MaxEdges: 5, MaxSourceRows: 1000,
	}, networks, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Limits.TruncatedClients || !g.Limits.TruncatedDomains {
		t.Fatalf("expected client/domain truncation flags: %+v", g.Limits)
	}
	if len(g.Clients) != 5 || len(g.Domains) != 5 {
		t.Fatalf("display sizes = %d/%d (edges %d)", len(g.Clients), len(g.Domains), len(g.Edges))
	}
	// Edges are capped after client/domain keep-sets; with one domain per
	// kept client there may be no further edge truncation to report.
	if len(g.Edges) == 0 || len(g.Edges) > 5 {
		t.Fatalf("edges = %d, want 1..5", len(g.Edges))
	}
}

func BenchmarkBuildNetworkMap(b *testing.B) {
	st, err := Open(b.TempDir() + "/bench.db")
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	net, err := st.CreateNetwork(ctx, NetworkInput{
		Name: ptr("Bench"), Enabled: ptr(true), AllowResolver: ptr(true),
		CIDRs: ptr([]string{"10.0.0.0/8"}),
	})
	if err != nil {
		b.Fatal(err)
	}
	events := make([]QueryEvent, 0, 5000)
	for i := 0; i < 5000; i++ {
		events = append(events, QueryEvent{
			Time:      now.Add(-time.Duration(i) * time.Second),
			ClientIP:  fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256),
			NetworkID: net.ID,
			Domain:    fmt.Sprintf("n%d.example", i%400),
			QType:     "A",
			Action:    []string{ActionAllowed, ActionBlocked, ActionError}[i%3],
			Category:  "malware",
		})
	}
	if err := st.InsertQueryBatch(ctx, events, true); err != nil {
		b.Fatal(err)
	}
	networks, _ := st.ListNetworks(ctx)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.BuildNetworkMap(ctx, NetworkMapFilter{
			Since: now.Add(-2 * time.Hour), Until: now.Add(time.Minute),
			MaxClients: 80, MaxDomains: 70, MaxEdges: 300, MaxSourceRows: 50000,
		}, networks, nil); err != nil {
			b.Fatal(err)
		}
	}
}
