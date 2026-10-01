package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/diag"
	"github.com/jameshoulder/dnsdaddy/internal/httpx"
)

func TestProxyDiagnosticUsesActualPeerAndDoesNotTrustSpoofedHeaders(t *testing.T) {
	trusted, err := httpx.ParseTrustedProxies([]string{"172.23.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	a := New(Deps{TrustedProxies: trusted})
	for _, tc := range []struct {
		peer string
		want diag.Status
	}{
		{"172.23.0.1:1234", diag.StatusPass}, {"172.24.0.1:1234", diag.StatusWarn}, {"192.0.2.40:1234", diag.StatusWarn},
	} {
		r := httptest.NewRequest("GET", "/api/v1/diagnostics", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", "172.23.0.1, secret-client-identifier")
		r.Header.Set("X-Forwarded-Proto", "https")
		c, ok := a.proxyRequestCheck(r)
		if !ok || c.Status != tc.want {
			t.Fatalf("peer %s: %+v", tc.peer, c)
		}
		if strings.Contains(strings.Join(c.Evidence, " "), "secret-client") {
			t.Fatal("header contents leaked into evidence")
		}
		if tc.want == diag.StatusWarn && trusted.Trusts(httpx.PeerAddr(r)) {
			t.Fatal("diagnostics granted trust")
		}
	}
	r := httptest.NewRequest("GET", "/api/v1/diagnostics", nil)
	if _, ok := a.proxyRequestCheck(r); ok {
		t.Fatal("a direct request was misidentified as a proxy")
	}
}

func TestProxyDiagnosticRemainsBehindManagementAuthentication(t *testing.T) {
	h := newHarness(t)
	r := httptest.NewRequest("GET", "/api/v1/diagnostics", nil)
	r.RemoteAddr = "172.24.0.1:3456"
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	h.api.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "actual connection peer") {
		t.Fatalf("diagnostic exposed before authentication: %d %s", w.Code, w.Body.String())
	}
}
