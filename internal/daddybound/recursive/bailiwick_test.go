package recursive

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestBailiwickIsLabelAligned(t *testing.T) {
	for _, tc := range []struct {
		zone, name string
		want       bool
	}{
		{".", "example.com.", true},
		{"com.", "example.com.", true},
		{"com.", "com.", true},
		{"example.com.", "www.example.com.", true},
		{"example.com.", "example.com.", true},

		{"example.com.", "example.org.", false},
		{"example.com.", "com.", false},
		{"example.com.", ".", false},
		// The one that matters. "notexample.com." ends with the string
		// "example.com." and is somebody else's zone; a server for
		// example.com. must not be able to speak about it, or registering a
		// lookalike would be enough to poison the real name.
		{"example.com.", "notexample.com.", false},
		{"ample.com.", "example.com.", false},
	} {
		if got := inBailiwick(tc.zone, tc.name); got != tc.want {
			t.Errorf("inBailiwick(%q, %q) = %v, want %v", tc.zone, tc.name, got, tc.want)
		}
	}
}

func TestAReferralMustGoDownwards(t *testing.T) {
	for _, tc := range []struct {
		parent, child string
		want          bool
	}{
		{".", "com.", true},
		{"com.", "example.com.", true},
		{"com.", "a.b.example.com.", true},

		{"com.", "com.", false},         // to itself: a loop
		{"example.com.", "com.", false}, // upwards: a loop
		{".", ".", false},
		{"com.", "example.org.", false}, // sideways
		{"com.", "notcom.", false},      // string suffix, different zone
	} {
		if got := strictlyBelow(tc.parent, tc.child); got != tc.want {
			t.Errorf("strictlyBelow(%q, %q) = %v, want %v", tc.parent, tc.child, got, tc.want)
		}
	}
}

func a(name, addr string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   netip.MustParseAddr(addr).AsSlice(),
	}
}

// Glue is the classic cache-poisoning vector: a server answers the question it
// was asked and slips records for somebody else's zone into the Additional
// section. Nothing here is accepted on the strength of having appeared.
func TestGlueIsFilteredToTheDelegationBeingFollowed(t *testing.T) {
	nsNames := map[string]bool{
		"ns1.example.com.": true,
		"ns1.example.org.": true, // a legitimate out-of-bailiwick nameserver
	}
	extra := []dns.RR{
		a("ns1.example.com.", "192.0.2.1"),   // in-bailiwick: the only reason to trust it
		a("ns1.example.org.", "192.0.2.2"),   // out-of-bailiwick: resolve it separately instead
		a("www.bank.example.", "192.0.2.66"), // not a nameserver here at all
		a("example.com.", "192.0.2.99"),      // in-bailiwick but not a named nameserver
	}

	got := acceptableGlue("example.com.", nsNames, extra)

	if len(got) != 1 {
		t.Fatalf("accepted glue for %d names, want 1: %v", len(got), got)
	}
	if _, ok := got["ns1.example.com."]; !ok {
		t.Fatal("the in-bailiwick nameserver address was rejected")
	}
	for _, poison := range []string{"www.bank.example.", "ns1.example.org.", "example.com."} {
		if _, ok := got[poison]; ok {
			t.Errorf("accepted glue for %q from a delegation that had no business supplying it", poison)
		}
	}
}

// A hostile public delegation must not become a way to find out what is
// listening inside the network DNS Daddy runs on.
func TestNonGlobalAddressesAreNotContactedAsAuthoritativeServers(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.1", "172.16.0.1", "192.168.1.1", // RFC 1918
		"169.254.1.1", "fe80::1", // link-local
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", "ff02::1", // multicast
		"fd00::1",      // unique-local
		"100.64.0.1",   // CGNAT
		"192.0.2.1",    // TEST-NET-1
		"198.51.100.1", // TEST-NET-2
		"203.0.113.1",  // TEST-NET-3
		"198.18.0.1",   // benchmarking
		"240.0.0.1",    // reserved
		"255.255.255.255",
		"2001:db8::1",      // documentation
		"64:ff9b::1.2.3.4", // NAT64 of a v4 address
	} {
		if usableTarget(netip.MustParseAddr(addr)) {
			t.Errorf("%s was accepted as an authoritative server address", addr)
		}
	}

	// And the check is not simply refusing everything.
	for _, addr := range []string{"198.41.0.4", "8.8.8.8", "2001:503:ba3e::2:30", "2606:4700::1"} {
		if !usableTarget(netip.MustParseAddr(addr)) {
			t.Errorf("%s was refused; it is an ordinary global address", addr)
		}
	}
}
