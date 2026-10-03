package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/setupguide"
)

func TestSetupRequiresAuthentication(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/setup"}, {"POST", "/api/v1/setup/preview"}, {"PUT", "/api/v1/setup/address"},
	} {
		resp, _ := h.do(tc.method, tc.path, map[string]any{})
		if resp.StatusCode != 401 {
			t.Fatalf("%s %s: %d", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestSetupPreviewDoesNotGrantAccessOrSaveAnAddress(t *testing.T) {
	h := newHarness(t)
	h.login()
	ctx := context.Background()
	before, err := h.store.ListNetworks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resp, raw := h.do("POST", "/api/v1/setup/preview", setupguide.Input{
		Preset: "vps", ServerIP: "203.0.113.53", Clients: "198.51.100.9", DNSPort: 53,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
	var plan setupguide.Plan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	if !plan.PublicAckRequired || len(plan.CIDRs) != 1 || plan.CIDRs[0] != "198.51.100.9/32" {
		t.Fatalf("bad source plan: %+v", plan)
	}
	after, err := h.store.ListNetworks(ctx)
	if err != nil || len(before) != len(after) {
		t.Fatalf("preview changed networks: %v", err)
	}
	if h.acl.Allows(netip.MustParseAddr("198.51.100.9")) {
		t.Fatal("preview granted client access")
	}
	if value, _, err := h.api.setupAddress(ctx); err != nil || value != "" {
		t.Fatalf("preview saved an endpoint: %q %v", value, err)
	}
	// The write path still requires the actual public-address acknowledgement.
	resp, _ = h.do("POST", "/api/v1/networks", map[string]any{
		"name": "Public preview", "cidrs": plan.CIDRs, "allowResolver": true,
	})
	if resp.StatusCode != 409 {
		t.Fatalf("public grant without acknowledgement = %d", resp.StatusCode)
	}
}

func TestSetupAddressUpdatesOverviewWithoutChangingPermissions(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, raw := h.do("PUT", "/api/v1/setup/address", map[string]any{
		"serverIp": "203.0.113.53", "dnsPort": 53, "previous": "",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
	resp, raw = h.do("GET", "/api/v1/server-addresses", nil)
	var addresses ServerAddressesResponse
	if err := json.Unmarshal(raw, &addresses); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || addresses.Advertised == nil || addresses.Advertised.Address != "203.0.113.53" || addresses.Advertised.Verified {
		t.Fatalf("address did not reach the existing Overview API: %d %s", resp.StatusCode, raw)
	}
	if h.api.Config.DNS.AdvertisedEndpoint != "" {
		t.Fatal("saving display state mutated shared runtime configuration")
	}
	if h.acl.Allows(netip.MustParseAddr("203.0.113.53")) {
		t.Fatal("a display address became a resolver-access grant")
	}
	events, _, err := h.store.ListConfigChanges(context.Background(), 0, 10)
	if err != nil || len(events) != 1 || events[0].Status != "complete" || events[0].Target != "settings/advertised_dns" {
		t.Fatalf("address write was not journalled: %+v %v", events, err)
	}
}

func TestSetupAddressRejectsStaleWritesAndCanBeCleared(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, raw := h.do("PUT", "/api/v1/setup/address", map[string]any{"serverIp": "2001:db8::53", "dnsPort": 5353, "previous": ""})
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
	resp, _ = h.do("PUT", "/api/v1/setup/address", map[string]any{"serverIp": "203.0.113.53", "dnsPort": 53, "previous": ""})
	if resp.StatusCode != 409 {
		t.Fatal("stale address update was accepted")
	}
	resp, raw = h.do("PUT", "/api/v1/setup/address", map[string]any{"clear": true, "previous": "[2001:db8::53]:5353"})
	if resp.StatusCode != 200 {
		t.Fatalf("clear: %d %s", resp.StatusCode, raw)
	}
	if value, _, _ := h.api.setupAddress(context.Background()); value != "" {
		t.Fatal("clear did not remove the dashboard override")
	}
}

func TestSetupConfigAddressRemainsAuthoritative(t *testing.T) {
	h := newHarness(t)
	h.api.Config.DNS.AdvertisedEndpoint = "198.51.100.53:53"
	h.login()
	resp, raw := h.do("PUT", "/api/v1/setup/address", map[string]any{"serverIp": "203.0.113.53", "dnsPort": 53})
	if resp.StatusCode != 409 || !strings.Contains(string(raw), "DNSDADDY_ADVERTISED_DNS") {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
	if value, locked, err := h.api.setupAddress(context.Background()); err != nil || !locked || value != "198.51.100.53:53" {
		t.Fatalf("%q %v %v", value, locked, err)
	}
}

func TestSetupAddressKeepsSameOriginProtection(t *testing.T) {
	h := newHarness(t)
	h.login()
	r, err := http.NewRequest("PUT", h.server.URL+"/api/v1/setup/address", strings.NewReader(`{"serverIp":"203.0.113.53","dnsPort":53}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", "https://attacker.example")
	r.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-origin setup write: %d", resp.StatusCode)
	}
}

func TestSetupNativeStartersLoadWithTheActualConfigParser(t *testing.T) {
	for _, preset := range setupguide.Presets() {
		for _, mode := range []string{"off", "observe", "enforce"} {
			t.Run(preset.ID+"/"+mode, func(t *testing.T) {
				server, clients := "192.168.1.2", "192.168.1.50"
				switch preset.ID {
				case "local":
					server, clients = "127.0.0.1", "127.0.0.1"
				case "vps":
					server, clients = "203.0.113.53", "198.51.100.9"
				case "roaming":
					server, clients = "203.0.113.53", ""
				}
				plan, err := setupguide.Build(setupguide.Input{Preset: preset.ID, ServerIP: server, Clients: clients, Mode: mode})
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "config.yaml")
				if err := os.WriteFile(path, []byte(plan.NativeYAML), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg, err := config.Load(path)
				if err != nil {
					t.Fatalf("generated configuration rejected: %v\n%s", err, plan.NativeYAML)
				}
				if cfg.DNS.AllowPublicResolver || cfg.DNS.LocalDNSSECValidation != mode || cfg.DNS.AdvertisedEndpoint != plan.Endpoint {
					t.Fatal("generated configuration changed its intended safety/mode/address contract")
				}
			})
		}
	}
}
