package api

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/diag"
	"gopkg.in/yaml.v3"
)

func TestAdvertisedAddressIsSeparateFromProcessInterfacesAndNeverVerified(t *testing.T) {
	cfg := config.DNS{ListenUDP: ":5353", AdvertisedEndpoint: "203.0.113.53:53"}
	out := withServerDeployment(serverAddresses(cfg, serverInterfaceSnapshot{}), cfg, diag.RuntimeContainer)
	if out.Runtime != diag.RuntimeContainer || out.Advertised == nil || out.Advertised.Address != "203.0.113.53" || out.Advertised.Port != 53 || out.Advertised.Verified || out.Advertised.Source != "configuration" {
		t.Fatalf("advertised endpoint: %+v", out)
	}
	if out.PreferredAddress != nil || len(out.Addresses) != 0 || *out.Listeners[0].Port != 5353 {
		t.Fatal("advertising changed observed interfaces or listener ports")
	}
	var spec map[string]any
	if err := yaml.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatal(err)
	}
	properties := spec["components"].(map[string]any)["schemas"].(map[string]any)["ServerAddressesResponse"].(map[string]any)["properties"].(map[string]any)
	raw, _ := json.Marshal(out)
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	for field := range fields {
		if _, exists := properties[field]; !exists {
			t.Errorf("undocumented address property %q", field)
		}
	}
}

func TestConfiguredEndpointSurvivesUnavailableInterfaceEnumeration(t *testing.T) {
	a := New(Deps{Config: config.Config{DNS: config.DNS{ListenUDP: ":5353", AdvertisedEndpoint: "[2001:db8::53]:53"}}})
	a.serverInterfaces = func() (serverInterfaceSnapshot, error) { return serverInterfaceSnapshot{}, errors.New("denied") }
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/server-addresses", nil)
	r.Host = "attacker.example"
	r.Header.Set("X-Forwarded-Host", "198.51.100.17")
	a.handleServerAddresses(w, r)
	if w.Code != 200 {
		t.Fatalf("configured endpoint lost: %d %s", w.Code, w.Body.String())
	}
	var out ServerAddressesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Source != "configuration_only" || !out.Partial || out.Advertised == nil || out.Advertised.Address != "2001:db8::53" || len(out.Addresses) != 0 {
		t.Fatalf("invented observation: %+v", out)
	}
	if strings.Contains(w.Body.String(), "attacker") || strings.Contains(w.Body.String(), "198.51.100.17") {
		t.Fatal("header became address evidence")
	}
}
