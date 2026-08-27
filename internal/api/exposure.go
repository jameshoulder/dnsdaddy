package api

import (
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/jameshoulder/dnsdaddy/internal/httpx"
)

// exposureWatch records evidence that the management surface is reachable from
// somewhere it should not be.
//
// The dashboard and management API are authenticated but travel in plaintext
// unless TLS is in front. Whether that matters depends entirely on who can
// reach the port, and the process cannot see its own Docker port publishing or
// the host firewall — from inside the container it is always bound to
// 0.0.0.0:8080.
//
// What it can see is who actually turns up. A management request arriving over
// plain HTTP from a public address is not a guess about configuration: it is
// proof that the port is reachable from the internet and that credentials and
// session cookies are crossing it in the clear. That is the one dangerous
// misconfiguration of this port, and this is the only evidence of it the
// process ever gets.
//
// Deliberately not counted: loopback, private and carrier-grade-NAT sources
// (a LAN dashboard is a supported deployment), anything over TLS, and
// /dns-query, which is a resolver endpoint and is meant to face the world.
type exposureWatch struct {
	mu sync.Mutex
	// count is how many plaintext management requests arrived from a public
	// address.
	count uint64
	// lastAddr is the most recent such address, kept because "that is my
	// office" and "that is not me" are very different conclusions and only
	// the operator can tell them apart. Shown to an authenticated admin only.
	lastAddr string
}

// observe records one request against the management surface.
func (e *exposureWatch) observe(r *http.Request, trusted *httpx.TrustedProxies) {
	// The resolver endpoint is supposed to be public.
	if strings.HasPrefix(r.URL.Path, "/dns-query") {
		return
	}
	if httpx.IsHTTPS(r, trusted) {
		return
	}

	// The peer, not the forwarded client: a forwarding header is only believed
	// from a trusted proxy, and a trusted proxy in front is the arrangement
	// this check exists to recommend.
	addr := httpx.PeerAddr(r)
	if !addr.IsValid() || !isPublicAddr(addr) {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.count++
	e.lastAddr = addr.String()
}

// snapshot returns the evidence gathered so far.
func (e *exposureWatch) snapshot() (count uint64, lastAddr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.count, e.lastAddr
}

// isPublicAddr reports whether addr is routable on the public internet.
//
// Everything a self-hosted resolver is normally reached from is excluded:
// loopback, the RFC 1918 ranges, carrier-grade NAT (which is what Tailscale
// and many ISPs hand out), link-local, and the IPv6 equivalents. What is left
// is an address that could only have arrived across the internet.
func isPublicAddr(addr netip.Addr) bool {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	addr = addr.WithZone("")

	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	// netip.Addr.IsPrivate covers RFC 1918 and RFC 4193 but not carrier-grade
	// NAT, which is ordinary private space from a deployment's point of view.
	if addr.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(addr) {
		return false
	}
	return true
}

// withExposureWatch records plaintext management access from public addresses.
func (a *API) withExposureWatch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.exposure.observe(r, a.TrustedProxies)
		next.ServeHTTP(w, r)
	})
}
