package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func seedMapAPI(t *testing.T, h *harness) (store.Network, store.Network) {
	t.Helper()
	ctx := context.Background()
	h.api.Config.Log.QueryLog = true
	h.api.Config.Log.LogClientIP = true
	now := time.Now().UTC()
	lan, err := h.store.CreateNetwork(ctx, store.NetworkInput{
		Name: ptr("LAN"), Enabled: ptr(true), AllowResolver: ptr(true),
		CIDRs: ptr([]string{"10.0.0.0/24"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	guest, err := h.store.CreateNetwork(ctx, store.NetworkInput{
		Name: ptr("Guest"), Enabled: ptr(true), AllowResolver: ptr(true),
		CIDRs: ptr([]string{"10.1.0.0/24"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	events := []store.QueryEvent{
		{Time: now.Add(-5 * time.Minute), ClientIP: "10.0.0.1", ClientName: "laptop", NetworkID: lan.ID, Domain: "evil.example", QType: "A", Action: store.ActionBlocked, Category: "malware"},
		{Time: now.Add(-4 * time.Minute), ClientIP: "10.0.0.1", ClientName: "laptop", NetworkID: lan.ID, Domain: "news.example", QType: "A", Action: store.ActionAllowed},
		{Time: now.Add(-3 * time.Minute), ClientIP: "10.0.0.2", ClientName: "forwarder", NetworkID: lan.ID, Domain: "evil.example", QType: "A", Action: store.ActionAllowed},
		{Time: now.Add(-2 * time.Minute), ClientIP: "10.1.0.5", ClientName: "phone", NetworkID: guest.ID, Domain: "evil.example", QType: "A", Action: store.ActionBlocked, Category: "malware"},
		{Time: now.Add(-time.Minute), ClientIP: "10.0.0.3", ClientName: "<script>x</script>", NetworkID: lan.ID, Domain: "safe.example", QType: "A", Action: store.ActionError},
	}
	if err := h.store.InsertQueryBatch(ctx, events, true); err != nil {
		t.Fatal(err)
	}
	if err := h.store.InsertFindings(ctx, []store.Finding{{
		ID: "f1", Time: now.Add(-4 * time.Minute), EventType: "dns.tunnel.suspected", Severity: "medium",
		ClientIP: "10.0.0.1", NetworkID: lan.ID, Domain: "evil.example",
		Detector: "fixture", Title: "Finding", Summary: "fixture", Detail: `{}`,
	}}); err != nil {
		t.Fatal(err)
	}
	return lan, guest
}

func TestNetworkMapRequiresAuthAndValidatesInput(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(http.MethodGet, "/api/v1/network-map", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d", resp.StatusCode)
	}
	h.login()
	resp, raw := h.do(http.MethodGet, "/api/v1/network-map?hours=9999", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad hours = %d %s", resp.StatusCode, raw)
	}
	resp, raw = h.do(http.MethodGet, "/api/v1/network-map?action=explode", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad action = %d %s", resp.StatusCode, raw)
	}
	resp, raw = h.do(http.MethodGet, "/api/v1/network-map?client=not-an-ip", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad client = %d %s", resp.StatusCode, raw)
	}
}

func TestNetworkMapReturnsGraphWithHonestSemantics(t *testing.T) {
	h := newHarness(t)
	h.login()
	lan, _ := seedMapAPI(t, h)

	resp, raw := h.do(http.MethodGet, "/api/v1/network-map?hours=1", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	var out networkMapResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Available || out.SchemaVersion != store.NetworkMapSchemaVersion {
		t.Fatalf("available/schema = %+v", out)
	}
	if !strings.Contains(out.EdgeMeaning, "not proof") {
		t.Errorf("edge meaning: %q", out.EdgeMeaning)
	}
	if out.ResolverStatus == nil || !strings.Contains(out.ResolverStatus.Note, "Current runtime") {
		t.Errorf("resolver status note missing: %+v", out.ResolverStatus)
	}
	if len(out.Clients) < 2 || len(out.Domains) < 2 || len(out.Edges) < 2 {
		t.Fatalf("graph too small: clients=%d domains=%d edges=%d", len(out.Clients), len(out.Domains), len(out.Edges))
	}
	var sawLAN bool
	for _, n := range out.Networks {
		if n.ID == lan.ID {
			sawLAN = true
		}
	}
	if !sawLAN {
		t.Fatalf("LAN missing: %+v", out.Networks)
	}
	// Hostile labels remain data. Go's JSON encoder may escape < as \u003c.
	blob := string(raw)
	if !strings.Contains(blob, "script") || !strings.Contains(blob, "x") {
		t.Error("hostile client name missing from payload")
	}
	var sawHostile bool
	for _, c := range out.Clients {
		if strings.Contains(c.ClientName, "script") {
			sawHostile = true
		}
	}
	if !sawHostile {
		t.Fatalf("hostile name not present on a client node: %+v", out.Clients)
	}
}

func TestNetworkMapPrivacyLimitedWhenClientIPLoggingOff(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedMapAPI(t, h)
	h.api.Config.Log.LogClientIP = false

	resp, raw := h.do(http.MethodGet, "/api/v1/network-map?hours=1", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	var out networkMapResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Available || out.Unavailable == "" || len(out.Clients) != 0 {
		t.Fatalf("expected privacy-limited empty map: %+v", out)
	}
}

func TestNetworkMapUnavailableWhenQueryLoggingOff(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedMapAPI(t, h)
	h.api.Config.Log.QueryLog = false

	resp, raw := h.do(http.MethodGet, "/api/v1/network-map?hours=1", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	var out networkMapResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Available || !strings.Contains(out.Unavailable, "Query logging") || len(out.Edges) != 0 {
		t.Fatalf("expected logging-off empty map: %+v", out)
	}
}

func TestNetworkMapDoesNotWriteOnRead(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedMapAPI(t, h)
	before, err := h.store.CountQueryLogRows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := h.do(http.MethodGet, "/api/v1/network-map?hours=1&action=blocked", nil)
	resp.Body.Close()
	after, err := h.store.CountQueryLogRows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("map read changed query_log size %d → %d", before, after)
	}
}

func TestNetworkMapNetworkFilter(t *testing.T) {
	h := newHarness(t)
	h.login()
	lan, guest := seedMapAPI(t, h)
	resp, raw := h.do(http.MethodGet, "/api/v1/network-map?hours=1&networkId="+lan.ID, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	var out networkMapResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	for _, c := range out.Clients {
		if c.NetworkID != lan.ID {
			t.Fatalf("client from other network: %+v (guest=%s)", c, guest.ID)
		}
	}
}

func ptr[T any](v T) *T { return &v }
