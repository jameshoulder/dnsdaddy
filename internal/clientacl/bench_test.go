package clientacl

import (
	"context"
	"net/netip"
	"testing"
)

// Admission runs before every query, ahead of the cache and the policy engine,
// so it is on the hot path by definition. What it must not do is allocate: a
// resolver at a few thousand queries a second would otherwise spend its GC
// budget deciding who is allowed to ask.
//
// The shapes below are the ones that actually occur. A hit on the first prefix
// is the loopback health check; a hit late in the list is a LAN client under
// the shipped default; a miss is the scanner the ACL exists to turn away, and
// is the case that scans the whole list.

var benchSet = Compute(
	[]string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"100.64.0.0/10", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	},
	false,
	[]Network{
		{ID: "n1", Name: "HQ", Enabled: true, AllowResolver: true, CIDRs: []string{"203.0.113.0/24"}},
		{ID: "n2", Name: "Branch", Enabled: true, AllowResolver: true, CIDRs: []string{"198.51.100.10/32"}},
	},
)

var benchSink bool

func benchAllows(b *testing.B, addr netip.Addr) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = benchSet.Allows(addr)
	}
}

func BenchmarkAllowsFirstPrefix(b *testing.B) {
	benchAllows(b, netip.MustParseAddr("127.0.0.1"))
}

func BenchmarkAllowsLatePrefix(b *testing.B) {
	benchAllows(b, netip.MustParseAddr("192.168.1.50"))
}

// The full scan: no prefix matches, so every one is examined.
func BenchmarkAllowsRefused(b *testing.B) {
	benchAllows(b, netip.MustParseAddr("8.8.8.8"))
}

// A v4 client arriving over a dual-stack socket needs unmapping first, which
// is the common case on a Linux box with a single :53 listener.
func BenchmarkAllowsMappedV4(b *testing.B) {
	benchAllows(b, netip.MustParseAddr("::ffff:192.168.1.50"))
}

// A link-local peer carries a scope zone that has to be stripped. This is the
// only shape that touches WithZone, so it is worth separating.
func BenchmarkAllowsZonedIPv6(b *testing.B) {
	benchAllows(b, netip.MustParseAddr("fe80::1%eth0"))
}

// What the handler actually calls: one atomic load, then the scan above. The
// gap between this and BenchmarkAllowsLatePrefix is the cost of making the ACL
// changeable at runtime.
func BenchmarkControllerAllows(b *testing.B) {
	c := NewController(benchSet.Bootstrap(), false, func(context.Context) ([]Network, error) {
		return nil, nil
	})
	addr := netip.MustParseAddr("192.168.1.50")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = c.Allows(addr)
	}
}
