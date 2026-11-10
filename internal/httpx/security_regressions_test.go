package httpx

import (
	"net/netip"
	"testing"
)

// TestSecurityIPv4MappedTrustedProxyMatchesIPv4Peer matches equivalent mapped and canonical proxy addresses without broadening trust.
func TestSecurityIPv4MappedTrustedProxyMatchesIPv4Peer(t *testing.T) {
	trusted, err := ParseTrustedProxies([]string{"::ffff:192.0.2.0/120"})
	if err != nil {
		t.Fatal(err)
	}
	if !trusted.Trusts(netip.MustParseAddr("192.0.2.42")) {
		t.Fatal("an IPv4 peer must match an equivalent mapped /120 proxy CIDR")
	}
	if trusted.Trusts(netip.MustParseAddr("192.0.3.42")) {
		t.Fatal("the mapped CIDR must not trust unrelated peers")
	}
	if _, err := ParseTrustedProxies([]string{"::ffff:192.0.2.0/95"}); err == nil {
		t.Fatal("mapped prefixes broader than /96 cannot be represented safely")
	}
}
