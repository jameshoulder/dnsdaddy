package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
)

type transportControlStub struct {
	modeControlStub
	transport DNSTransportState
	writes    int
}

func (s *transportControlStub) TransportState() DNSTransportState { return s.transport }
func (s *transportControlStub) SetTransport(_ context.Context, mode string, endpoints []resolver.EncryptedEndpoint) error {
	s.writes++
	s.transport.Transport, s.transport.Endpoints = mode, endpoints
	s.transport.EncryptedOnly = mode == config.ResolutionEncrypted
	s.state.Transport = mode
	return nil
}

func TestDNSTransportWritesRequireAuthenticationOriginConsentAndValidEndpoints(t *testing.T) {
	h := newHarness(t)
	c := &transportControlStub{transport: DNSTransportState{Transport: config.ResolutionNative}}
	h.api.DNSSECControl = c
	valid := map[string]any{"transport": "encrypted", "acknowledgeForwarding": true,
		"endpoints": []map[string]any{{"protocol": "doq", "address": "127.0.0.1:65354", "serverName": "resolver.invalid"}}}
	for _, request := range []struct{ method, path string }{{"GET", "/api/v1/dns/transport"}, {"PUT", "/api/v1/dns/transport"}, {"POST", "/api/v1/dns/transport/test"}} {
		resp, _ := h.do(request.method, request.path, valid)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated transport access: %s %d", request.path, resp.StatusCode)
		}
	}
	h.login()
	resp, _ := h.doWithHeaders("PUT", "/api/v1/dns/transport", valid, map[string]string{"Origin": "https://other.invalid"})
	if resp.StatusCode != http.StatusForbidden || c.writes != 0 {
		t.Fatal("cross-origin transport change accepted")
	}
	for _, body := range []map[string]any{
		{"transport": "encrypted", "endpoints": valid["endpoints"]},
		{"transport": "encrypted", "acknowledgeForwarding": true, "endpoints": []map[string]any{{"protocol": "udp", "address": "127.0.0.1:53"}}},
		{"transport": "encrypted", "acknowledgeForwarding": true, "endpoints": []map[string]any{{"protocol": "doh2", "address": "https://resolver.invalid/dns-query"}}},
	} {
		resp, _ := h.do("PUT", "/api/v1/dns/transport", body)
		if resp.StatusCode != http.StatusBadRequest || c.writes != 0 {
			t.Fatalf("invalid/unconsented configuration accepted: %#v %d", body, resp.StatusCode)
		}
	}
	resp, raw := h.do("PUT", "/api/v1/dns/transport", valid)
	if resp.StatusCode != http.StatusOK || c.writes != 1 {
		t.Fatalf("explicit configuration failed: %d %s", resp.StatusCode, raw)
	}
	resp, _ = h.do("PUT", "/api/v1/dns/transport", map[string]any{"transport": "native"})
	if resp.StatusCode != http.StatusBadRequest || c.writes != 1 {
		t.Fatal("encrypted profile switched to native without acknowledgement")
	}
	c.transport.Locked = true
	resp, _ = h.do("PUT", "/api/v1/dns/transport", valid)
	if resp.StatusCode != http.StatusConflict || c.writes != 1 {
		t.Fatal("pinned transport change accepted")
	}
}

func TestEncryptedStatusAndModeDoNotClaimNativePort53OrProviderValidation(t *testing.T) {
	h := newHarness(t)
	h.login()
	c := &transportControlStub{modeControlStub: modeControlStub{state: DNSSECRuntimeState{Transport: config.ResolutionEncrypted, Effective: config.LocalDNSSECOff}},
		transport: DNSTransportState{Transport: config.ResolutionEncrypted, EncryptedOnly: true, Stats: &resolver.EncryptedStats{Queries: 7, Failovers: 2,
			Endpoints: []resolver.EncryptedEndpointStats{{Protocol: "doh3", Address: "https://private-config.invalid/account-path", Attempts: 7}}}}}
	h.api.DNSSECControl = c
	resp, raw := h.do("PUT", "/api/v1/dnssec/mode", map[string]any{"mode": "enforce"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("encrypted Live incorrectly requires native disclosure: %s", raw)
	}
	resp, raw = h.do("GET", "/api/v1/dnssec/status", nil)
	var status dnssecStatus
	if resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &status) != nil || status.Transport != "encrypted" || status.Resolution.Source != "encrypted_forwarded" || !status.Enforcing {
		t.Fatalf("local validation transport misreported: %s", raw)
	}
	if strings.Contains(status.Resolution.Transport, "plaintext DNS") || !strings.Contains(status.Resolution.ClientPath, "locally validates the exact answer") {
		t.Fatal("transport was confused with DNSSEC authentication")
	}
	metrics := h.getMetrics()
	if !strings.Contains(metrics, `dnsdaddy_dns_transport{transport="encrypted"} 1`) || !strings.Contains(metrics, "dnsdaddy_dns_encrypted_queries_total 7") || strings.Contains(metrics, "private-config.invalid") || strings.Contains(metrics, "account-path") {
		t.Fatal("encrypted metrics are absent or reveal endpoint configuration")
	}
}

func TestEncryptedEndpointTestRequiresConsentAndBoundedAdmission(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, _ := h.do("POST", "/api/v1/dns/transport/test", map[string]any{"endpoints": []any{}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("endpoint test accepted without consent")
	}
	h.api.transportTests <- struct{}{}
	resp, _ = h.do("POST", "/api/v1/dns/transport/test", map[string]any{"acknowledgeForwarding": true, "endpoints": []any{}})
	<-h.api.transportTests
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatal("parallel endpoint tests were not bounded")
	}
	if route, ok := auditedManagementRoute(&http.Request{Method: http.MethodPut, URL: &url.URL{Path: "/api/v1/dns/transport"}}); !ok || route.scope.ID != DNSTransportSetting {
		t.Fatal("transport changes are missing from configuration history")
	}
}
