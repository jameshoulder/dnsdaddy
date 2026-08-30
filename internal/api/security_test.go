package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/httpx"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// doWithHeaders is h.do with control over request headers, which is what the
// CSRF tests need — the browser attaches Origin, so a test must too.
func (h *harness) doWithHeaders(method, path string, body any, headers map[string]string) (*http.Response, []byte) {
	h.t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read body: %v", err)
	}
	return resp, raw
}

// The session cookie is SameSite=Lax, which does not protect a cross-site POST
// in every browser. A strict Origin check does.
func TestCrossOriginStateChangeIsRejected(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.doWithHeaders("POST", "/api/v1/feeds/refresh", nil,
		map[string]string{"Origin": "https://evil.example"})

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a cross-origin POST (body: %s)", resp.StatusCode, raw)
	}
}

func TestCrossOriginRefererIsRejected(t *testing.T) {
	h := newHarness(t)
	h.login()

	// Some browsers send Referer but not Origin on form navigations.
	resp, raw := h.doWithHeaders("POST", "/api/v1/feeds/refresh", nil,
		map[string]string{"Referer": "https://evil.example/attack.html"})

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a cross-origin Referer (body: %s)", resp.StatusCode, raw)
	}
}

func TestSameOriginStateChangeIsAllowed(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.doWithHeaders("POST", "/api/v1/feeds/refresh", nil,
		map[string]string{"Origin": h.server.URL})

	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("a same-origin POST was rejected as cross-origin (body: %s)", raw)
	}
}

// A GET cannot change state, and blocking cross-origin reads here would break
// nothing an attacker could not already do.
func TestCrossOriginSafeMethodIsAllowed(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.doWithHeaders("GET", "/api/v1/feeds", nil,
		map[string]string{"Origin": "https://evil.example"})

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 for a cross-origin GET (body: %s)", resp.StatusCode, raw)
	}
}

// Bearer tokens are never attached by a browser on a cross-site request, so
// CSRF does not apply to them. Applying the origin check anyway would break
// every legitimate API client that sets no Origin — or sets its own.
func TestBearerTokenIsExemptFromOriginCheck(t *testing.T) {
	h := newHarness(t)

	tok, err := h.store.CreateAPIToken(context.Background(), "test-client")
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	resp, raw := h.doWithHeaders("POST", "/api/v1/feeds/refresh", nil, map[string]string{
		"Authorization": "Bearer " + tok.Secret,
		"Origin":        "https://some-other-tool.example",
	})

	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("a bearer-token request was rejected by the origin check (body: %s)", raw)
	}
}

func TestUnauthenticatedStateChangeStillRequiresAuth(t *testing.T) {
	h := newHarness(t)

	resp, _ := h.doWithHeaders("POST", "/api/v1/feeds/refresh", nil,
		map[string]string{"Origin": h.server.URL})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 without credentials", resp.StatusCode)
	}
}

// An unconditional Secure flag makes login impossible on a plain-HTTP LAN
// deployment: the browser accepts the cookie and then never sends it back.
// "auto" is what makes self-hosting on HTTP work without giving up the flag
// for everyone who does terminate TLS.
func TestSecureCookieModes(t *testing.T) {
	tests := []struct {
		mode       string
		tls        bool
		wantSecure bool
	}{
		{"auto", false, false},
		{"auto", true, true},
		{"always", false, true},
		{"always", true, true},
		{"never", false, false},
		{"never", true, false},
		{"", false, false}, // empty means auto
	}

	for _, tt := range tests {
		name := tt.mode
		if name == "" {
			name = "empty"
		}
		if tt.tls {
			name += "-tls"
		} else {
			name += "-plain"
		}

		t.Run(name, func(t *testing.T) {
			auth, err := NewAuth(newTestStore(t), t.TempDir(), AuthOptions{SecureCookies: tt.mode})
			if err != nil {
				t.Fatalf("NewAuth: %v", err)
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
			req.RemoteAddr = "192.168.1.10:5555"
			if tt.tls {
				req.TLS = &tlsState
			}
			auth.SetSessionCookie(rec, req, mustSession(t, auth))

			cookies := rec.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("got %d cookies, want 1", len(cookies))
			}
			if cookies[0].Secure != tt.wantSecure {
				t.Errorf("Secure = %v, want %v for secure_cookies=%q over TLS=%v",
					cookies[0].Secure, tt.wantSecure, tt.mode, tt.tls)
			}
			if !cookies[0].HttpOnly {
				t.Error("the session cookie is not HttpOnly")
			}
			if cookies[0].SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax", cookies[0].SameSite)
			}
		})
	}
}

// In "auto" mode the Secure flag follows X-Forwarded-Proto, which must only be
// believed from a configured proxy.
func TestSecureCookieAutoHonoursTrustedProxyOnly(t *testing.T) {
	trusted, err := httpx.ParseTrustedProxies([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	tests := []struct {
		name       string
		remote     string
		wantSecure bool
	}{
		{"trusted proxy reports https", "127.0.0.1:5555", true},
		{"untrusted peer claims https", "192.168.1.10:5555", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewAuth(newTestStore(t), t.TempDir(), AuthOptions{
				SecureCookies: "auto", TrustedProxies: trusted,
			})
			if err != nil {
				t.Fatalf("NewAuth: %v", err)
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
			req.RemoteAddr = tt.remote
			req.Header.Set("X-Forwarded-Proto", "https")
			auth.SetSessionCookie(rec, req, mustSession(t, auth))

			if got := rec.Result().Cookies()[0].Secure; got != tt.wantSecure {
				t.Errorf("Secure = %v, want %v", got, tt.wantSecure)
			}
		})
	}
}

// The logout cookie must carry the same Secure attribute as the one it
// replaces, or the browser keeps the original and the user stays logged in.
func TestClearSessionCookieMatchesSetAttributes(t *testing.T) {
	auth, err := NewAuth(newTestStore(t), t.TempDir(), AuthOptions{SecureCookies: "always"})
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.RemoteAddr = "192.168.1.10:5555"

	set := httptest.NewRecorder()
	auth.SetSessionCookie(set, req, mustSession(t, auth))
	clear := httptest.NewRecorder()
	auth.ClearSessionCookie(clear, req)

	a, b := set.Result().Cookies()[0], clear.Result().Cookies()[0]
	if a.Secure != b.Secure || a.HttpOnly != b.HttpOnly || a.SameSite != b.SameSite || a.Path != b.Path {
		t.Errorf("logout cookie attributes differ from login:\n set   = %+v\n clear = %+v", a, b)
	}
	if b.MaxAge >= 0 {
		t.Errorf("logout cookie MaxAge = %d, want negative so the browser drops it", b.MaxAge)
	}
}

// tlsState stands in for a terminated TLS connection; only its presence
// matters to httpx.IsHTTPS.
var tlsState = tls.ConnectionState{Version: tls.VersionTLS13}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// mustSession issues a real session for tests that are about cookie
// attributes rather than session lifecycle.
func mustSession(t *testing.T, auth *Auth) string {
	t.Helper()
	token, err := auth.issueSession(context.Background(), "test")
	if err != nil {
		t.Fatalf("issueSession: %v", err)
	}
	return token
}
