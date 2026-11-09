package clientacl

import (
	"net/netip"
	"testing"
)

func TestSecurityCoverageMergesWithoutPairwiseRescans(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		full   bool
	}{
		{"IPv4 halves", []string{"0.0.0.0/1", "128.0.0.0/1"}, true},
		{"IPv4 quarters", []string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"}, true},
		{"missing quarter", []string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2"}, false},
		{"IPv6 halves", []string{"::/1", "8000::/1"}, true},
		{"mixed families not full", []string{"0.0.0.0/1", "8000::/1"}, false},
		{"redundant subset", []string{"0.0.0.0/1", "10.0.0.0/8", "128.0.0.0/1"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefixes := make([]netip.Prefix, 0, len(tc.values))
			for _, raw := range tc.values {
				prefixes = append(prefixes, netip.MustParsePrefix(raw))
			}
			if got := CoversEntireFamily(prefixes); got != tc.full {
				t.Fatalf("CoversEntireFamily(%v) = %v, want %v", tc.values, got, tc.full)
			}
		})
	}
}

func TestSecurityCoverageLargeNonUniversalInput(t *testing.T) {
	prefixes := make([]netip.Prefix, 0, 4096)
	for i := 0; i < 4096; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		prefixes = append(prefixes, netip.PrefixFrom(a, 32))
	}
	if CoversEntireFamily(prefixes) {
		t.Fatal("disjoint /32 ranges must not authorize the entire internet")
	}
}
