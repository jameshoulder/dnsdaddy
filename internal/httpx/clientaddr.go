// Package httpx resolves the true client address and scheme of an HTTP
// request, honouring forwarding headers only from proxies the operator has
// explicitly trusted.
//
// This lives in its own package because the same answer is needed in three
// places that must never disagree: DNS-over-HTTPS client attribution (which
// selects a filtering policy), login rate limiting (which decides whether to
// throttle a guess), and the session cookie's Secure flag. If those three
// disagreed about who the client is, an attacker could pick whichever view
// suited them.
package httpx

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedProxies is the set of peer addresses whose forwarding headers are
// believed. An empty set means no header is ever trusted, which is the safe
// default for a resolver reachable directly.
type TrustedProxies struct {
	prefixes []netip.Prefix
}

// ParseTrustedProxies compiles a list of CIDRs (or bare addresses, treated as
// single-host prefixes).
func ParseTrustedProxies(cidrs []string) (*TrustedProxies, error) {
	t := &TrustedProxies{}
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy address %q: %w", raw, err)
			}
			t.prefixes = append(t.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", raw, err)
		}
		t.prefixes = append(t.prefixes, p.Masked())
	}
	return t, nil
}

// Empty reports whether any proxy is trusted at all.
func (t *TrustedProxies) Empty() bool { return t == nil || len(t.prefixes) == 0 }

// Trusts reports whether addr is one of the configured proxies.
func (t *TrustedProxies) Trusts(addr netip.Addr) bool {
	if t == nil || !addr.IsValid() {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, p := range t.prefixes {
		if p.Addr().Is4() != addr.Is4() {
			continue
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// PeerAddr returns the address of the machine that actually opened the
// connection, ignoring every forwarding header.
func PeerAddr(r *http.Request) netip.Addr {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	// A netip.Addr parsed from a connection can carry a zone (fe80::1%eth0);
	// drop it so comparisons against configured prefixes behave.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr
}

// ClientAddr returns the address to attribute a request to.
//
// When the immediate peer is a trusted proxy, the right-most X-Forwarded-For
// entry that is *not* itself a trusted proxy is used. Walking from the right
// matters: a client can prepend arbitrary values to X-Forwarded-For, so the
// left-most entry is attacker-controlled. Only the entries appended by
// infrastructure we trust are meaningful, and those are at the right.
//
// When the peer is not trusted, headers are ignored entirely.
func ClientAddr(r *http.Request, trusted *TrustedProxies) netip.Addr {
	peer := PeerAddr(r)
	if !trusted.Trusts(peer) {
		return peer
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			addr, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				continue
			}
			if addr.Is4In6() {
				addr = addr.Unmap()
			}
			if trusted.Trusts(addr) {
				continue // another hop in our own proxy chain
			}
			return addr
		}
	}

	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		if addr, err := netip.ParseAddr(xrip); err == nil {
			if addr.Is4In6() {
				addr = addr.Unmap()
			}
			return addr
		}
	}

	return peer
}

// IsHTTPS reports whether the request reached the client over TLS.
//
// X-Forwarded-Proto is only believed from a trusted proxy. Believing it from
// anyone would let a client on a plaintext connection assert "https" and
// change how the session cookie is issued.
func IsHTTPS(r *http.Request, trusted *TrustedProxies) bool {
	if r.TLS != nil {
		return true
	}
	if trusted.Trusts(PeerAddr(r)) {
		return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
	}
	return false
}
