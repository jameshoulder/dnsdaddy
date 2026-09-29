package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/jameshoulder/dnsdaddy/internal/webhook"
)

type failingProviderTransport struct{}

func (failingProviderTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("TLS failed for " + r.URL.String())
}

func TestTransportFailureIsRedactedInTestsSavedResultsAndHealth(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)
	h.api.Intel.Transport = failingProviderTransport{}
	config := map[string]string{"url": "https://fixture-provider.example/lookup?domain={subject}", "auth_query": "apikey"}
	id := createProvider(t, h, map[string]any{"name": "Error fixture", "kind": "customhttp", "enabled": true, "config": config, "secret": theCredential, "capabilities": []string{"reputation"}})
	h.api.Providers.Consult(context.Background(), "p_standard", "private.example")
	deadline := time.Now().Add(time.Second)
	for h.api.Providers.Stats().Completed == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.api.Providers.Stats().Completed == 0 {
		t.Fatal("transport error fixture did not complete")
	}
	calls := []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/v1/integrations/providers/" + id + "/test", map[string]any{"consent": true}},
		{"POST", "/api/v1/integrations/providers/test", map[string]any{"kind": "customhttp", "config": config, "secret": theCredential, "consent": true}},
		{"GET", "/api/v1/integrations/providers/" + id, nil},
		{"GET", "/api/v1/integrations/providers/" + id + "/health", nil},
		{"GET", "/api/v1/integrations/providers", nil},
	}
	for _, call := range calls {
		resp, raw := h.do(call.method, call.path, call.body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", call.path, resp.StatusCode, raw)
		}
		if strings.Contains(string(raw), theCredential) || strings.Contains(string(raw), "apikey=") {
			t.Fatalf("credential leaked through %s: %s", call.path, raw)
		}
	}
	stored, err := h.store.GetSetting(context.Background(), "integrations.provider_test."+id)
	if err != nil || strings.Contains(stored, theCredential) || strings.Contains(stored, "apikey=") {
		t.Fatalf("unsafe saved test result: %q %v", stored, err)
	}
}

func TestIntegrationSettingsAreLocalOptInAndPersist(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)
	resp, body := h.do("GET", "/api/v1/integrations/settings", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"available":true`) || !strings.Contains(string(body), `"restartRequired":false`) {
		t.Fatalf("settings unavailable: %d %s", resp.StatusCode, body)
	}
	resp, body = h.do("PUT", "/api/v1/integrations/settings", map[string]any{"reputationMode": "cache_only", "enrichmentEnabled": true})
	if resp.StatusCode != 400 || h.api.Providers.Mode() != apiprovider.ModeOff || h.api.Providers.EnrichmentEnabled() {
		t.Fatalf("missing consent changed settings: %d %s", resp.StatusCode, body)
	}
	resp, body = h.do("PUT", "/api/v1/integrations/settings", map[string]any{"reputationMode": "cache_only", "enrichmentEnabled": true, "consent": true})
	if resp.StatusCode != 200 {
		t.Fatalf("consented save: %d %s", resp.StatusCode, body)
	}
	if EffectiveReputationMode(context.Background(), h.store, "off") != apiprovider.ModeCacheOnly || !EffectiveEnrichment(context.Background(), h.store, false) {
		t.Fatal("UI settings did not survive startup resolution")
	}
	bootMode, bootEnrichment, err := InitializeIntegrationSettings(context.Background(), h.store, false, "off", false)
	if err != nil || bootMode != apiprovider.ModeCacheOnly || !bootEnrichment {
		t.Fatalf("new consented UI settings did not survive disabled legacy YAML on restart: %s,%v,%v", bootMode, bootEnrichment, err)
	}
	resp, body = h.do("PUT", "/api/v1/integrations/settings", map[string]any{"reputationMode": "off", "enrichmentEnabled": false})
	if resp.StatusCode != 200 || h.api.Providers.EnrichmentEnabled() {
		t.Fatalf("disable should not require consent: %d %s", resp.StatusCode, body)
	}
}

func TestProviderTestsAndEnableNeedConsentAndReadsNeverContactProvider(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{"score":0}`)) }))
	defer upstream.Close()
	id := createProvider(t, h, map[string]any{"name": "Fixture API", "kind": "customhttp", "enabled": false, "config": map[string]string{"url": upstream.URL + "/?domain={subject}"}, "secret": theCredential, "capabilities": []string{"reputation"}})
	for _, path := range []string{"/integrations/providers", "/integrations/providers/" + id, "/integrations/providers/" + id + "/health", "/integrations/templates", "/integrations/settings"} {
		resp, body := h.do("GET", "/api/v1"+path, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
		}
	}
	resp, body := h.do("POST", "/api/v1/integrations/providers/"+id+"/test", map[string]any{"consent": false})
	if resp.StatusCode != 400 || calls.Load() != 0 {
		t.Fatalf("unconsented provider request happened: %d %s, calls=%d", resp.StatusCode, body, calls.Load())
	}
	resp, body = h.do("PATCH", "/api/v1/integrations/providers/"+id, map[string]any{"enabled": true})
	if resp.StatusCode != 400 {
		t.Fatalf("provider enabled without consent: %d %s", resp.StatusCode, body)
	}
	resp, body = h.do("POST", "/api/v1/integrations/providers/"+id+"/test", map[string]any{"consent": true})
	if resp.StatusCode != 200 || calls.Load() != 1 {
		t.Fatalf("explicit test: %d %s, calls=%d", resp.StatusCode, body, calls.Load())
	}
	_, body = h.do("GET", "/api/v1/integrations/providers/"+id, nil)
	var view struct {
		LastTest     *providerTestRecord `json:"lastTest"`
		LiveVerified bool                `json:"liveVerified"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if view.LastTest == nil || !view.LastTest.OK || view.LiveVerified {
		t.Fatalf("account test was confused with adapter verification: %s", body)
	}
	if strings.Contains(string(body), theCredential) {
		t.Fatal("saved test exposed credential")
	}
	resp, body = h.do("POST", "/api/v1/integrations/providers/"+id+"/secret", map[string]any{"secret": "rotated-fixture-key-abcdef1234567890"})
	if resp.StatusCode != 200 {
		t.Fatalf("rotate: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), `"lastTest"`) {
		t.Fatalf("old key verification survived rotation: %s", body)
	}
}

func TestProviderCreateRejectsUnsafeSettingsBeforePersistence(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)
	for _, cfg := range []map[string]string{
		{"url": "http://public.example/lookup"},
		{"url": "https://127.0.0.1/lookup", "allow_private": "true"},
		{"url": "https://[::ffff:169.254.169.254]/"},
		{"url": "https://{subject}.example/lookup"},
		{"url": "https://service.example/lookup?api_key=plaintext"},
		{"url": "https://user:password@service.example/lookup"},
		{"url": "https://service.example/lookup", "secret": "unprotected"},
		{"url": "https://service.example/lookup", "auth_header": "Host"},
		{"url": "https://service.example/lookup", "auth_header": "Authorization\r\nX:evil"},
	} {
		resp, body := h.do("POST", "/api/v1/integrations/providers", map[string]any{"name": "Unsafe", "kind": "customhttp", "config": cfg})
		if resp.StatusCode != 400 {
			t.Errorf("unsafe settings accepted: %v => %d %s", cfg, resp.StatusCode, body)
		}
	}
	rows, err := h.store.ListAPIProviders(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatalf("invalid input left rows: %d %v", len(rows), err)
	}
}

func TestWebhookManagementRedactsKeysAndRequiresExplicitSharing(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)
	h.api.Webhooks = webhook.New(webhook.Options{Store: h.store, Keyring: h.api.Intel.Keyring})
	defer h.api.Webhooks.Stop()
	const secret = "fixture-webhook-secret-that-never-returns-1234567890"
	resp, body := h.do("PUT", "/api/v1/integrations/webhook", map[string]any{"url": "https://receiver.example/events", "secret": secret, "enabled": false})
	if resp.StatusCode != 200 || strings.Contains(string(body), secret) {
		t.Fatalf("save/redaction: %d %s", resp.StatusCode, body)
	}
	for _, path := range []string{"/api/v1/integrations/webhook", "/api/v1/config"} {
		_, body = h.do("GET", path, nil)
		if strings.Contains(string(body), secret) {
			t.Fatal("GET exposed webhook signing key")
		}
	}
	resp, body = h.do("PUT", "/api/v1/integrations/webhook", map[string]any{"enabled": true})
	if resp.StatusCode != 400 {
		t.Fatalf("webhook enabled without consent: %d %s", resp.StatusCode, body)
	}
	resp, body = h.do("POST", "/api/v1/integrations/webhook/test", map[string]any{"consent": false})
	if resp.StatusCode != 400 {
		t.Fatalf("webhook test accepted without consent: %d %s", resp.StatusCode, body)
	}
	resp, body = h.do("PUT", "/api/v1/integrations/webhook", map[string]any{"enabled": true, "consent": true})
	if resp.StatusCode != 200 {
		t.Fatalf("enable: %d %s", resp.StatusCode, body)
	}
	resp, body = h.do("DELETE", "/api/v1/integrations/webhook/secret", nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete secret: %d %s", resp.StatusCode, body)
	}
	cfg, err := h.store.GetWebhookConfig(context.Background())
	if err != nil || cfg.Enabled || cfg.SecretSet {
		t.Fatalf("secret removal did not disable receiver: %+v %v", cfg, err)
	}
}

func TestManagedProviderLimitIsAtomic(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 64; i++ {
		if _, err := h.store.CreateManagedAPIProvider(context.Background(), store.APIProvider{Name: "Fixture", Kind: "customhttp"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.store.CreateManagedAPIProvider(context.Background(), store.APIProvider{Name: "Overflow", Kind: "customhttp"}); err != store.ErrProviderLimit {
		t.Fatalf("provider limit missing: %v", err)
	}
}
