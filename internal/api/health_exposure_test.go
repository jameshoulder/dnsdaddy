package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/httpx"
)

// /api/v1/health is the one management path that is deliberately
// unauthenticated, which makes it the one path the HTTPS deployment publishes
// to the internet. What it says to a stranger is therefore a security
// property, and these tests are what fix it.

// publicHealthFields is the complete allowed vocabulary of the unauthenticated
// response. Adding to this list is a deliberate act with a security argument
// attached, which is the point of writing it down.
var publicHealthFields = map[string]bool{"status": true}

func getHealth(t *testing.T, h *harness, mutate func(*http.Request)) map[string]any {
	t.Helper()
	req, err := http.NewRequest("GET", h.server.URL+"/api/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(req)
	}
	// A bare client: no cookie jar, so this is a stranger unless the mutate
	// function makes it otherwise.
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health returned %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	return body
}

func TestHealthDetailIgnoresForwardedLoopbackClaims(t *testing.T) {
	// The attack the loopback tier invites: a request that arrived from the
	// internet asserting that it came from 127.0.0.1.
	//
	// The peer here is a public address, so the only way any of these could
	// work is if entitlement were decided from a header. Only a valid management credential grants access.
	//
	// A trusted proxy is configured deliberately, because that is the
	// deployment where this is reachable at all: in HTTPS mode Caddy's own
	// address is trusted, and the tempting "fix" of asking httpx.ClientAddr
	// instead of httpx.PeerAddr would start honouring the header for exactly
	// the requests that come from the internet.
	trusted, err := httpx.ParseTrustedProxies([]string{"172.17.0.0/16", "127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	hh := newHarness(t)
	hh.api.TrustedProxies = trusted

	for _, hdr := range []struct{ k, v string }{
		{"X-Forwarded-For", "127.0.0.1"},
		{"X-Forwarded-For", "::1"},
		{"X-Forwarded-For", "127.0.0.1, 172.17.0.1"},
		{"X-Real-IP", "127.0.0.1"},
		{"Forwarded", `for="127.0.0.1"`},
		{"X-Forwarded-Host", "localhost"},
		{"Host", "localhost"},
	} {
		req := httptest.NewRequest("GET", "/api/v1/health", nil)
		req.RemoteAddr = "203.0.113.9:44321" // from the internet
		req.Header.Set(hdr.k, hdr.v)

		if hh.api.healthDetailPermitted(req) {
			t.Errorf("%s: %s made an internet request entitled to internal state", hdr.k, hdr.v)
		}
		body := recordHealth(hh.api, req)
		for name := range body {
			if !publicHealthFields[name] {
				t.Errorf("%s: %s disclosed %q to an internet caller", hdr.k, hdr.v, name)
			}
		}
	}

	// The case that actually distinguishes PeerAddr from ClientAddr, and the
	// one that exists in the HTTPS deployment: the peer IS the trusted proxy.
	//
	// Every request from the internet arrives this way, so if entitlement were
	// resolved through the forwarding headers — which is what asking
	// httpx.ClientAddr would do — a browser that sent X-Forwarded-For:
	// 127.0.0.1 would be one Caddy header-handling change away from reading
	// internal state. Whether Caddy happens to append rather than replace is
	// not a property this codebase controls, so the decision does not depend
	// on it.
	viaProxy := httptest.NewRequest("GET", "/api/v1/health", nil)
	viaProxy.RemoteAddr = "172.17.0.1:44321" // the Docker bridge gateway: Caddy
	viaProxy.Header.Set("X-Forwarded-For", "127.0.0.1")
	viaProxy.Header.Set("X-Real-IP", "127.0.0.1")
	if hh.api.healthDetailPermitted(viaProxy) {
		t.Error("a request forwarded by the trusted proxy claimed loopback and was believed; " +
			"entitlement must come from authentication, not a peer address")
	}
	for name := range recordHealth(hh.api, viaProxy) {
		if !publicHealthFields[name] {
			t.Errorf("a proxied request claiming loopback was disclosed %q", name)
		}
	}

	// Loopback without authentication is also public: a headerless local
	// reverse proxy is indistinguishable from a direct local TCP client.
	local := httptest.NewRequest("GET", "/api/v1/health", nil)
	local.RemoteAddr = "127.0.0.1:44321"
	if hh.api.healthDetailPermitted(local) {
		t.Fatal("loopback must not grant health detail without authentication")
	}
}

func TestHealthDetailWithheldBehindALoopbackProxy(t *testing.T) {
	// The native HTTPS deployment in docs/deploy.md: Caddy on the same host,
	// reverse-proxying to 127.0.0.1:8080. Every request from the internet then
	// reaches this process with a loopback peer, so "the peer is loopback"
	// cannot by itself mean "this is the operator at the console" — and while
	// it did, that deployment published the version, the uptime and whether
	// filtering was on to anyone who asked.
	//
	// The earlier Docker test topology used a bridge gateway. Host-network
	// containers and headerless loopback proxies need their own coverage.
	//
	// Both proxy configurations are exercised: listed in trusted_proxy_cidrs as
	// the documentation asks, and not listed at all. An operator who forgets
	// that setting must not be the one whose health detail is public.
	loopbackTrusted, err := httpx.ParseTrustedProxies([]string{"127.0.0.1/32", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}

	for _, tp := range []struct {
		name    string
		trusted *httpx.TrustedProxies
	}{
		{"proxy listed in trusted_proxy_cidrs", loopbackTrusted},
		{"proxy not listed", &httpx.TrustedProxies{}},
	} {
		hh := newHarness(t)
		hh.api.TrustedProxies = tp.trusted

		for _, peer := range []string{"127.0.0.1:44321", "[::1]:44321"} {
			for _, hdr := range []struct{ k, v string }{
				// What Caddy sends for a browser on the internet.
				{"X-Forwarded-For", "203.0.113.9"},
				{"X-Forwarded-Proto", "https"},
				{"X-Forwarded-Host", "dns.example.co.uk"},
				{"X-Real-IP", "203.0.113.9"},
				{"Forwarded", "for=203.0.113.9;proto=https"},
				{"Via", "1.1 Caddy"},
				// And the claims a stranger might add in the hope that the value
				// is what gets read. It is not: presence is.
				{"X-Forwarded-For", "127.0.0.1"},
				{"X-Real-IP", "::1"},
				{"X-Forwarded-For", ""},
			} {
				req := httptest.NewRequest("GET", "/api/v1/health", nil)
				req.RemoteAddr = peer
				req.Header.Set(hdr.k, hdr.v)

				if hh.api.healthDetailPermitted(req) {
					t.Errorf("%s, peer %s: a request relayed with %s: %q was entitled to internal state",
						tp.name, peer, hdr.k, hdr.v)
				}
				for name := range recordHealth(hh.api, req) {
					if !publicHealthFields[name] {
						t.Errorf("%s, peer %s: a request relayed with %s: %q was disclosed %q",
							tp.name, peer, hdr.k, hdr.v, name)
					}
				}
			}

			// Headerless relays and direct local probes get the same minimal
			// response; liveness must not depend on a proxy adding a header.
			direct := httptest.NewRequest("GET", "/api/v1/health", nil)
			direct.RemoteAddr = peer
			if hh.api.healthDetailPermitted(direct) {
				t.Errorf("%s: unauthenticated peer %s got detail", tp.name, peer)
			}
			for name := range recordHealth(hh.api, direct) {
				if !publicHealthFields[name] {
					t.Errorf("%s: unauthenticated peer %s got %s", tp.name, peer, name)
				}
			}
		}
	}

	// A session still entitles a caller who arrives through that proxy, which
	// is how the dashboard itself reads this in the HTTPS deployment.
	hh := newHarness(t)
	hh.api.TrustedProxies = loopbackTrusted
	hh.login()
	var cookie *http.Cookie
	for _, c := range hh.client.Jar.Cookies(nil) {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie after login")
	}
	signedIn := httptest.NewRequest("GET", "/api/v1/health", nil)
	signedIn.RemoteAddr = "127.0.0.1:44321"
	signedIn.Header.Set("X-Forwarded-For", "203.0.113.9")
	signedIn.AddCookie(cookie)
	if !hh.api.healthDetailPermitted(signedIn) {
		t.Error("an authenticated operator behind the proxy was refused the detail")
	}
}

func TestHealthDetailFollowsAuthenticationForRemoteCallers(t *testing.T) {
	// The other way in. An operator with a session or an API token is
	// entitled wherever they are calling from, which is what makes the
	// dashboard able to show this and what keeps a remote monitor workable
	// once it holds a token.
	hh := newHarness(t)
	hh.login()

	var cookie *http.Cookie
	for _, c := range hh.client.Jar.Cookies(nil) {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie after login")
	}

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.RemoteAddr = "203.0.113.9:44321"
	req.AddCookie(cookie)
	if !hh.api.healthDetailPermitted(req) {
		t.Error("an authenticated remote caller was refused the detail")
	}

	// A forged cookie is not a session, so it changes nothing.
	forged := httptest.NewRequest("GET", "/api/v1/health", nil)
	forged.RemoteAddr = "203.0.113.9:44321"
	forged.AddCookie(&http.Cookie{Name: sessionCookie, Value: "not-a-session"})
	if hh.api.healthDetailPermitted(forged) {
		t.Error("a forged session cookie was accepted as entitlement")
	}
}

func TestHealthGivesAStrangerNothingButLiveness(t *testing.T) {
	// Public requests get the same minimal response regardless of peer address.
	api, req := unentitledHealthRequest(t)
	if api.healthDetailPermitted(req) {
		t.Fatal("a non-loopback unauthenticated request was treated as entitled")
	}
}

func TestHealthDetailForAnEntitledCaller(t *testing.T) {
	h := h(t)
	body := authenticatedHealth(t, h)

	for _, want := range []string{"version", "uptimeSeconds", "blocklistSize", "protecting", "clientAclStale"} {
		if _, ok := body[want]; !ok {
			t.Errorf("an entitled caller did not receive %q; doctor and healthcheck.sh need it", want)
		}
	}
	if body["protecting"] != true {
		t.Errorf("protecting = %v, want true (the test index is non-empty)", body["protecting"])
	}
}

func TestHealthStatusIsLivenessNotAProtectionVerdict(t *testing.T) {
	// It used to answer "degraded" to anyone who asked when the index was
	// empty, which told the internet that this resolver was filtering nothing.
	// That belongs in `protecting`, behind entitlement.
	h := h(t)
	h.lists.Store(emptyIndex())

	body := authenticatedHealth(t, h)
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok — status is liveness", body["status"])
	}
	if body["protecting"] != false {
		t.Errorf("protecting = %v, want false with an empty index", body["protecting"])
	}
}

func TestPublicHealthVocabularyIsClosed(t *testing.T) {
	// A field added to HealthResponse without a pointer joins the body every
	// stranger receives. This is the list that has to be edited on purpose.
	api, req := unentitledHealthRequest(t)
	rec := recordHealth(api, req)

	for name := range rec {
		if !publicHealthFields[name] {
			t.Errorf("the unauthenticated health response now discloses %q; if that is "+
				"intended, add it to publicHealthFields with a reason", name)
		}
	}
	if len(rec) == 0 {
		t.Error("the unauthenticated health response is empty; a monitor needs status")
	}
}

// --- helpers ----------------------------------------------------------------

// h is newHarness under a shorter name; these tests build several.
func h(t *testing.T) *harness { return newHarness(t) }

// unentitledHealthRequest returns an API and a request whose peer is a public
// address — the view from the internet, which is the one that matters.
func unentitledHealthRequest(t *testing.T) (*API, *http.Request) {
	t.Helper()
	hh := newHarness(t)
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.RemoteAddr = "203.0.113.9:44321"
	return hh.api, req
}

// recordHealth runs the handler and returns the decoded body.
func recordHealth(api *API, req *http.Request) map[string]any {
	rec := httptest.NewRecorder()
	api.handleHealth(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body
}

// emptyIndex is a blocklist index with nothing in it, which is what a fresh
// install looks like before the first feed download finishes.
func emptyIndex() *blocklist.Index {
	return blocklist.NewBuilder(1).Build()
}
