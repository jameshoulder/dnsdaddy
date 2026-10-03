package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"
)

func authenticatedHealth(t *testing.T, h *harness) map[string]any {
	t.Helper()
	token, err := h.store.CreateAPIToken(context.Background(), "health-test")
	if err != nil {
		t.Fatal(err)
	}
	return getHealth(t, h, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token.Secret) })
}

func TestHeaderlessLoopbackProxyCannotReadHealthDetail(t *testing.T) {
	h := newHarness(t)
	var relayed atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayed.Store(true)
		for _, name := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "Forwarded", "Via"} {
			if len(r.Header.Values(name)) != 0 {
				t.Errorf("test relay unexpectedly sent %s", name)
			}
		}
		h.api.handleHealth(w, r)
	}))
	defer backend.Close()
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(&httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(target) // Deliberately no SetXForwarded.
	}})
	defer proxy.Close()
	resp, err := proxy.Client().Get(proxy.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !relayed.Load() || resp.StatusCode != http.StatusOK || len(body) != 1 || body["status"] != "ok" {
		t.Fatalf("unauthenticated proxy got non-minimal health: status=%d body=%v", resp.StatusCode, body)
	}
}

func TestLocalInvalidCredentialCannotReadHealthDetail(t *testing.T) {
	h := newHarness(t)
	for _, peer := range []string{"127.0.0.1:1234", "[::1]:1234", "172.18.0.1:1234"} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		r.RemoteAddr = peer
		r.Header.Set("Authorization", "Bearer dnsd_invalid")
		body := recordHealth(h.api, r)
		if len(body) != 1 || body["status"] != "ok" {
			t.Fatalf("peer %s got %v", peer, body)
		}
	}
}
