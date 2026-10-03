package api

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestInstallerHintPrefillsSetupWithoutLockingOrGrantingAccess(t *testing.T) {
	t.Setenv("DNSDADDY_DEPLOYMENT_DNS", "203.0.113.53:53")
	h := newHarness(t)
	h.login()
	resp, raw := h.do("GET", "/api/v1/setup", nil)
	var got struct {
		ServerIP      string `json:"serverIp"`
		Endpoint      string `json:"endpoint"`
		AddressSource string `json:"addressSource"`
		AddressLocked bool   `json:"addressLocked"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || got.ServerIP != "203.0.113.53" || got.Endpoint != "203.0.113.53:53" || got.AddressSource != "installation_hint" || got.AddressLocked {
		t.Fatalf("installer handoff = %d %s", resp.StatusCode, raw)
	}
	resp, raw = h.do("GET", "/api/v1/server-addresses", nil)
	var addresses ServerAddressesResponse
	if err := json.Unmarshal(raw, &addresses); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || addresses.Advertised == nil || addresses.Advertised.Address != "203.0.113.53" || addresses.Advertised.Verified {
		t.Fatalf("Overview handoff = %d %s", resp.StatusCode, raw)
	}
	if h.api.Config.DNS.AdvertisedEndpoint != "" || h.acl.Allows(netip.MustParseAddr("203.0.113.53")) {
		t.Fatal("a display hint mutated runtime configuration or granted resolver access")
	}
	// An operator can correct the hint through the same audited write as
	// before. The installer is not a new configuration lock.
	resp, raw = h.do("PUT", "/api/v1/setup/address", map[string]any{
		"serverIp": "198.51.100.53", "dnsPort": 5353, "previous": got.Endpoint,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("correcting the hint = %d %s", resp.StatusCode, raw)
	}
	value, locked, source, err := h.api.setupAddressInfo(context.Background())
	if err != nil || locked || source != "dashboard" || value != "198.51.100.53:5353" {
		t.Fatalf("saved correction = %q %t %q %v", value, locked, source, err)
	}
}

func TestInstallerHintCannotOverrideSavedOrPinnedAddresses(t *testing.T) {
	t.Setenv("DNSDADDY_DEPLOYMENT_DNS", "[2001:db8::53]:53")
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.SetSetting(ctx, setupAddressSetting, "192.168.1.53:53"); err != nil {
		t.Fatal(err)
	}
	value, locked, source, err := h.api.setupAddressInfo(ctx)
	if err != nil || value != "192.168.1.53:53" || locked || source != "dashboard" {
		t.Fatalf("saved choice changed: %q %t %q %v", value, locked, source, err)
	}
	h.api.Config.DNS.AdvertisedEndpoint = "198.51.100.53:53"
	value, locked, source, err = h.api.setupAddressInfo(ctx)
	if err != nil || value != "198.51.100.53:53" || !locked || source != "configuration" {
		t.Fatalf("pinned choice changed: %q %t %q %v", value, locked, source, err)
	}
	h.api.Config.DNS.AdvertisedEndpoint = ""
	if err := h.store.SetSetting(ctx, setupAddressSetting, ""); err != nil {
		t.Fatal(err)
	}
	value, locked, source, err = h.api.setupAddressInfo(ctx)
	if err != nil || value != "[2001:db8::53]:53" || locked || source != "installation_hint" {
		t.Fatalf("cleared override did not reveal the hint: %q %t %q %v", value, locked, source, err)
	}
}

func TestInvalidInstallerHintIsNotReplacedByAContainerAddress(t *testing.T) {
	for _, hint := range []string{"0.0.0.0:53", "https://example.test", "203.0.113.53:0", "[fe80::1%eth0]:53", "203.0.113.53:53\nOTHER=true", strings.Repeat("1", 81)} {
		t.Run(hint, func(t *testing.T) {
			t.Setenv("DNSDADDY_DEPLOYMENT_DNS", hint)
			h := newHarness(t)
			h.login()
			for _, path := range []string{"/api/v1/setup", "/api/v1/server-addresses"} {
				resp, raw := h.do("GET", path, nil)
				if resp.StatusCode != 503 {
					t.Fatalf("%s accepted bad hint: %d %s", path, resp.StatusCode, raw)
				}
			}
		})
	}
}

func TestInstallerAddressRemainsBehindAuthentication(t *testing.T) {
	t.Setenv("DNSDADDY_DEPLOYMENT_DNS", "203.0.113.53:53")
	h := newHarness(t)
	for _, path := range []string{"/api/v1/setup", "/api/v1/server-addresses"} {
		resp, raw := h.do("GET", path, nil)
		if resp.StatusCode != 401 || strings.Contains(string(raw), "203.0.113.53") {
			t.Fatalf("unauthenticated address response: %d %s", resp.StatusCode, raw)
		}
	}
	_, raw := h.do("GET", "/api/v1/health", nil)
	if strings.Contains(string(raw), "203.0.113.53") {
		t.Fatal("the deployment address leaked through public health")
	}
}
