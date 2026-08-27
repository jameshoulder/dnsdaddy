package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/httpx"
)

func request(t *testing.T, path, remoteAddr string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = remoteAddr
	return r
}

// The one dangerous misconfiguration of the management port: reachable from
// the internet, in plaintext. The process cannot see its own port publishing,
// so a request actually arriving from a public address is the only evidence it
// ever gets — and it is conclusive.
func TestExposureWatchRecordsPublicPlaintextAccess(t *testing.T) {
	var e exposureWatch
	e.observe(request(t, "/api/v1/overview", "203.0.113.9:51000"), &httpx.TrustedProxies{})

	count, last := e.snapshot()
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
	if last != "203.0.113.9" {
		t.Errorf("lastAddr = %q, want the public source address", last)
	}
}

// A LAN dashboard over plain HTTP is a supported deployment. Reporting it
// would be a false alarm, and a diagnostic that cries wolf gets ignored on the
// day it is right.
func TestExposureWatchIgnoresPrivateAndLoopbackSources(t *testing.T) {
	var e exposureWatch
	for _, addr := range []string{
		"127.0.0.1:51000",      // loopback
		"192.168.1.20:51000",   // RFC 1918
		"10.4.4.4:51000",       // RFC 1918
		"172.17.0.1:51000",     // Docker bridge
		"100.100.0.5:51000",    // carrier-grade NAT — Tailscale hands these out
		"[fd00::1]:51000",      // IPv6 unique-local
		"[fe80::1%eth0]:51000", // IPv6 link-local, with a scope zone
	} {
		e.observe(request(t, "/api/v1/overview", addr), &httpx.TrustedProxies{})
	}

	if count, _ := e.snapshot(); count != 0 {
		t.Errorf("count = %d after %d private sources; a LAN dashboard is not an exposure", count, 7)
	}
}

// /dns-query is a resolver endpoint. It is supposed to face the world, and
// counting it would make this check fire on every correctly-deployed DoH
// install.
func TestExposureWatchIgnoresTheResolverEndpoint(t *testing.T) {
	var e exposureWatch
	e.observe(request(t, "/dns-query", "203.0.113.9:51000"), &httpx.TrustedProxies{})
	e.observe(request(t, "/dns-query/abc123token", "203.0.113.9:51000"), &httpx.TrustedProxies{})

	if count, _ := e.snapshot(); count != 0 {
		t.Errorf("count = %d; DoH is meant to be publicly reachable", count)
	}
}

// TLS is the fix this check recommends, so a request that already arrived over
// TLS is not evidence of a problem.
func TestExposureWatchIgnoresTLS(t *testing.T) {
	var e exposureWatch

	direct := request(t, "/api/v1/overview", "203.0.113.9:51000")
	direct.TLS = &tlsState
	e.observe(direct, &httpx.TrustedProxies{})

	// Behind a trusted proxy that terminated TLS.
	trusted, err := httpx.ParseTrustedProxies([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	proxied := request(t, "/api/v1/overview", "203.0.113.9:51000")
	proxied.Header.Set("X-Forwarded-Proto", "https")
	e.observe(proxied, trusted)

	if count, _ := e.snapshot(); count != 0 {
		t.Errorf("count = %d; a request over TLS is not plaintext exposure", count)
	}
}

// A forwarding header from an untrusted peer must not be able to hide a real
// exposure by claiming the request was private or HTTPS.
func TestExposureWatchIgnoresUntrustedForwardingHeaders(t *testing.T) {
	var e exposureWatch

	r := request(t, "/api/v1/overview", "203.0.113.9:51000")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-For", "192.168.1.5")
	e.observe(r, &httpx.TrustedProxies{}) // nothing is trusted

	count, last := e.snapshot()
	if count != 1 {
		t.Fatalf("count = %d; a spoofed header suppressed a real exposure", count)
	}
	if last != "203.0.113.9" {
		t.Errorf("lastAddr = %q, want the real peer address, not the forwarded one", last)
	}
}

// A trusted proxy reporting X-Forwarded-Proto: http is telling us it served
// the dashboard publicly in the clear. Checking the proxy's own private
// address there would discard the one report that identifies both the public
// client and the insecure scheme — and it would go unnoticed precisely because
// a reverse proxy, the arrangement this check recommends, is in front of it.
func TestExposureWatchReportsPlaintextBehindATrustedProxy(t *testing.T) {
	trusted, err := httpx.ParseTrustedProxies([]string{"172.17.0.0/16"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	var e exposureWatch
	r := request(t, "/api/v1/overview", "172.17.0.1:51000") // the proxy
	r.Header.Set("X-Forwarded-Proto", "http")               // it did NOT terminate TLS
	r.Header.Set("X-Forwarded-For", "203.0.113.9")          // and the client is public
	e.observe(r, trusted)

	count, last := e.snapshot()
	if count != 1 {
		t.Fatalf("count = %d; a proxy serving the dashboard publicly in the clear was not reported", count)
	}
	if last != "203.0.113.9" {
		t.Errorf("lastAddr = %q, want the forwarded public client", last)
	}
}

// The same proxy doing its job — terminating TLS — is not an exposure, and a
// private client through it is not one either.
func TestExposureWatchStaysSilentForACorrectlyConfiguredProxy(t *testing.T) {
	trusted, err := httpx.ParseTrustedProxies([]string{"172.17.0.0/16"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	var e exposureWatch

	tls := request(t, "/api/v1/overview", "172.17.0.1:51000")
	tls.Header.Set("X-Forwarded-Proto", "https")
	tls.Header.Set("X-Forwarded-For", "203.0.113.9")
	e.observe(tls, trusted)

	lan := request(t, "/api/v1/overview", "172.17.0.1:51000")
	lan.Header.Set("X-Forwarded-Proto", "http")
	lan.Header.Set("X-Forwarded-For", "192.168.1.20")
	e.observe(lan, trusted)

	if count, _ := e.snapshot(); count != 0 {
		t.Errorf("count = %d; a TLS-terminating proxy and a LAN client are both supported deployments", count)
	}
}
