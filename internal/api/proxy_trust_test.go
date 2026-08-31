package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/httpx"
)

// The trust model is:
//
//	internet → Caddy → loopback → DNS Daddy
//
// Only a peer the operator has listed may supply forwarded information. These
// tests are the ones that check the rule holds at each place a forwarded value
// could change a decision, rather than only inside internal/httpx where it is
// implemented.

func trustedProxies(t *testing.T, cidrs ...string) *httpx.TrustedProxies {
	t.Helper()
	tp, err := httpx.ParseTrustedProxies(cidrs)
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	return tp
}

func TestLoginRateLimitKeyIsPerClientBehindAProxy(t *testing.T) {
	// The bug this pins: keying on r.RemoteAddr put every request behind a
	// reverse proxy into one bucket, so one attacker's failed guesses locked
	// out the operator — a denial of service that looked like a forgotten
	// password.
	trusted := trustedProxies(t, "172.17.0.0/16")

	mk := func(peer, xff string) *http.Request {
		r := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		r.RemoteAddr = peer
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	a := clientKey(mk("172.17.0.1:5555", "203.0.113.9"), trusted)
	b := clientKey(mk("172.17.0.1:5555", "198.51.100.4"), trusted)
	if a == b {
		t.Errorf("two different clients behind the proxy share a rate-limit bucket (%q); "+
			"one attacker would lock everybody out", a)
	}
	if a != "203.0.113.9" {
		t.Errorf("clientKey = %q, want the forwarded client 203.0.113.9", a)
	}
}

func TestLoginRateLimitKeyCannotBeChosenByAnUntrustedClient(t *testing.T) {
	// The same header from a peer that is not a configured proxy must change
	// nothing, or an attacker rotates their own key and the limiter is
	// decorative.
	trusted := trustedProxies(t, "172.17.0.0/16")

	mk := func(xff string) *http.Request {
		r := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		r.RemoteAddr = "203.0.113.9:5555" // direct, not the proxy
		r.Header.Set("X-Forwarded-For", xff)
		return r
	}

	first := clientKey(mk("10.0.0.1"), trusted)
	second := clientKey(mk("10.0.0.2"), trusted)
	if first != second {
		t.Errorf("an untrusted client changed its own rate-limit key by sending a header: %q vs %q",
			first, second)
	}
	if first != "203.0.113.9" {
		t.Errorf("clientKey = %q, want the real peer 203.0.113.9", first)
	}
}

func TestNoProxyConfiguredMeansNoHeaderIsBelieved(t *testing.T) {
	// The default. Empty trusted set, so every forwarding header is inert
	// everywhere it could matter.
	none := trustedProxies(t)

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	r.Header.Set("X-Real-IP", "127.0.0.1")
	r.Header.Set("X-Forwarded-Proto", "https")

	if got := httpx.ClientAddr(r, none).String(); got != "203.0.113.9" {
		t.Errorf("ClientAddr = %q, want the peer 203.0.113.9", got)
	}
	if httpx.IsHTTPS(r, none) {
		t.Error("X-Forwarded-Proto from an untrusted peer convinced the server the request was TLS")
	}
	if clientKey(r, none) != "203.0.113.9" {
		t.Error("the rate-limit key followed an untrusted header")
	}
}

func TestForwardedProtoCannotMakeAPlaintextRequestLookSecure(t *testing.T) {
	// The consequence if this were wrong: the session cookie is issued with
	// Secure in "auto" mode, the browser then refuses to send it back over the
	// plaintext connection it actually has, and login silently stops working —
	// or, in the other direction, the exposure watch stops recording a
	// dashboard genuinely being served in the clear.
	trusted := trustedProxies(t, "172.17.0.0/16")

	direct := httptest.NewRequest("GET", "/", nil)
	direct.RemoteAddr = "203.0.113.9:5555"
	direct.Header.Set("X-Forwarded-Proto", "https")
	if httpx.IsHTTPS(direct, trusted) {
		t.Error("a direct plaintext client asserted https and was believed")
	}

	viaProxy := httptest.NewRequest("GET", "/", nil)
	viaProxy.RemoteAddr = "172.17.0.1:5555"
	viaProxy.Header.Set("X-Forwarded-Proto", "https")
	if !httpx.IsHTTPS(viaProxy, trusted) {
		t.Error("the configured proxy reported https and was not believed")
	}
}

func TestRFC7239ForwardedHeaderIsNotHonoured(t *testing.T) {
	// DNS Daddy does not parse RFC 7239 `Forwarded`. That is a deliberate
	// omission rather than an oversight, and it is safe in this direction:
	// an unparsed header is an ignored header. This test exists so that a
	// future decision to support it is made on purpose, with the trust check
	// applied — adding a parser that reads it unconditionally would reopen
	// exactly the spoofing this file is about.
	trusted := trustedProxies(t, "172.17.0.0/16")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.17.0.1:5555" // even from the trusted proxy
	r.Header.Set("Forwarded", `for=203.0.113.9;proto=https`)

	if got := httpx.ClientAddr(r, trusted).String(); got == "203.0.113.9" {
		t.Error("Forwarded is now parsed; make sure the trusted-peer check covers it " +
			"and update this test")
	}
	if httpx.IsHTTPS(r, trusted) {
		t.Error("Forwarded's proto parameter was honoured for the scheme decision")
	}
}

func TestXForwardedForIsReadRightToLeft(t *testing.T) {
	// A client can prepend anything it likes to X-Forwarded-For, so the
	// left-most entry is attacker-controlled. Only the entries our own
	// infrastructure appended are meaningful, and those are on the right.
	trusted := trustedProxies(t, "172.17.0.0/16", "10.1.0.0/16")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.17.0.1:5555"
	// The client claimed to be 127.0.0.1; the real client is 203.0.113.9;
	// 10.1.0.5 is a second hop of our own.
	r.Header.Set("X-Forwarded-For", "127.0.0.1, 203.0.113.9, 10.1.0.5")

	if got := httpx.ClientAddr(r, trusted).String(); got != "203.0.113.9" {
		t.Errorf("ClientAddr = %q, want 203.0.113.9 — the right-most entry that is not our own hop", got)
	}
}
