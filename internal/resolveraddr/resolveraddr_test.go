package resolveraddr_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/resolveraddr"
)

func addrs(ss ...string) func() ([]netip.Addr, error) {
	return func() ([]netip.Addr, error) {
		out := make([]netip.Addr, 0, len(ss))
		for _, s := range ss {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}
}

// What the operator configured wins.
//
// Nobody on the machine knows better than the person who set it up, and on a
// VPS nothing on the machine knows at all: the NIC holds a private address and
// the provider applies a public one by NAT.
func TestAConfiguredAddressIsAuthoritative(t *testing.T) {
	got := resolveraddr.Discover(resolveraddr.Options{
		Configured: []string{"203.0.113.10"},
		Interfaces: addrs("10.0.0.5", "127.0.0.1"),
	})
	if len(got) == 0 {
		t.Fatal("no addresses at all")
	}
	if got[0].Address != "203.0.113.10" {
		t.Errorf("first address = %q, want the configured one", got[0].Address)
	}
	if got[0].Source != resolveraddr.SourceConfigured {
		t.Errorf("source = %q, want configured", got[0].Source)
	}
	if !got[0].Recommended {
		t.Error("the configured address is not the recommended one")
	}
	// The interface addresses are still listed — an operator may want the LAN
	// address too — just not first.
	if len(got) != 3 {
		t.Errorf("got %d addresses, want the configured one plus the two discovered", len(got))
	}
}

// The NAT warning is attached, not smoothed over.
//
// The failure this prevents is a dashboard confidently telling a VPS operator
// to configure 10.0.0.5 on their router. Nothing on the box can tell that the
// address is unreachable from outside, so the honest thing is to show it with
// the caveat rather than to show it as an answer.
func TestADiscoveredPrivateAddressCarriesTheNATCaveat(t *testing.T) {
	got := resolveraddr.Discover(resolveraddr.Options{
		Interfaces: addrs("10.0.0.5"),
	})
	if len(got) != 1 {
		t.Fatalf("got %d addresses, want 1", len(got))
	}
	if got[0].Source != resolveraddr.SourceInterface {
		t.Errorf("source = %q, want interface", got[0].Source)
	}
	if got[0].Kind != resolveraddr.KindPrivate {
		t.Errorf("kind = %q, want private", got[0].Kind)
	}
	if got[0].Note == "" {
		t.Error("a private address discovered on an interface carries no caveat; " +
			"on a cloud host this is not how clients reach the machine and the " +
			"dashboard would be telling the operator to configure a dead address")
	}
}

// Loopback is listed and never recommended.
//
// It is worth listing — "how do I test this from the host" is a real question —
// and recommending it would send somebody to configure 127.0.0.1 on their
// router.
func TestLoopbackIsListedButNeverRecommended(t *testing.T) {
	got := resolveraddr.Discover(resolveraddr.Options{
		Interfaces: addrs("127.0.0.1", "192.168.1.10"),
	})
	var loopback, recommended string
	for _, a := range got {
		if a.Kind == resolveraddr.KindLoopback {
			loopback = a.Address
			if a.Recommended {
				t.Error("loopback was recommended as the address to configure on clients")
			}
		}
		if a.Recommended {
			recommended = a.Address
		}
	}
	if loopback == "" {
		t.Error("loopback was not listed at all; testing from the host is a real need")
	}
	if recommended != "192.168.1.10" {
		t.Errorf("recommended = %q, want the LAN address", recommended)
	}
}

// A machine with nothing usable gets no recommendation rather than a bad one.
//
// The dashboard then asks the operator for an advertised address, which is the
// honest outcome. Recommending link-local would be inventing an answer.
func TestNothingUsableProducesNoRecommendation(t *testing.T) {
	got := resolveraddr.Discover(resolveraddr.Options{
		Interfaces: addrs("127.0.0.1", "fe80::1"),
	})
	for _, a := range got {
		if a.Recommended {
			t.Errorf("%s (%s) was recommended; neither loopback nor link-local is "+
				"an address a client on the network can use", a.Address, a.Kind)
		}
	}
}

// Interfaces that cannot be read do not blank the page.
//
// A machine mid-reconfiguration still has whatever the operator configured, and
// failing the whole status endpoint because a network interface was being
// brought up would be worse than showing less.
func TestAnInterfaceFailureStillReportsWhatWasConfigured(t *testing.T) {
	got := resolveraddr.Discover(resolveraddr.Options{
		Configured: []string{"203.0.113.10"},
		Interfaces: func() ([]netip.Addr, error) { return nil, errors.New("no interfaces today") },
	})
	if len(got) != 1 || got[0].Address != "203.0.113.10" {
		t.Fatalf("got %v, want the configured address alone", got)
	}
	if !got[0].Recommended {
		t.Error("the configured address is not recommended")
	}
}

// A malformed configured address is skipped rather than blanking the list.
func TestAMalformedConfiguredAddressIsSkipped(t *testing.T) {
	got := resolveraddr.Discover(resolveraddr.Options{
		Configured: []string{"not-an-address", "203.0.113.10", ""},
		Interfaces: addrs(),
	})
	if len(got) != 1 || got[0].Address != "203.0.113.10" {
		t.Fatalf("got %v, want only the one valid address", got)
	}
}

// An address with a port is accepted, because an operator copying from their
// configuration will include one.
func TestAConfiguredAddressMayCarryAPort(t *testing.T) {
	got := resolveraddr.Discover(resolveraddr.Options{
		Configured: []string{"203.0.113.10:53", "[2001:db8::1]:53"},
		Interfaces: addrs(),
	})
	if len(got) != 2 {
		t.Fatalf("got %d addresses, want 2", len(got))
	}
	if got[0].Address != "203.0.113.10" {
		t.Errorf("address = %q, want the port stripped", got[0].Address)
	}
}

// IPv6 is classified properly: unique-local is the IPv6 RFC 1918 and netip
// does not fold it into IsPrivate.
func TestIPv6IsClassifiedCorrectly(t *testing.T) {
	got := resolveraddr.Discover(resolveraddr.Options{
		Interfaces: addrs("fd00::1", "2606:4700:4700::1111", "fe80::1"),
	})
	kinds := map[string]resolveraddr.Kind{}
	for _, a := range got {
		kinds[a.Address] = a.Kind
		if a.Family != "ipv6" {
			t.Errorf("%s family = %q, want ipv6", a.Address, a.Family)
		}
	}
	if kinds["fd00::1"] != resolveraddr.KindPrivate {
		t.Errorf("fd00::1 = %q, want private (unique-local is the IPv6 RFC 1918)", kinds["fd00::1"])
	}
	if kinds["2606:4700:4700::1111"] != resolveraddr.KindPublic {
		t.Errorf("2606:4700:4700::1111 = %q, want public", kinds["2606:4700:4700::1111"])
	}
	if kinds["fe80::1"] != resolveraddr.KindLinkLocal {
		t.Errorf("fe80::1 = %q, want link-local", kinds["fe80::1"])
	}
}

// Carrier-grade NAT reads as private, because an operator seeing it needs the
// same warning: nothing outside the carrier's network reaches it.
func TestCarrierGradeNATIsTreatedAsPrivate(t *testing.T) {
	got := resolveraddr.Discover(resolveraddr.Options{Interfaces: addrs("100.64.1.5")})
	if len(got) != 1 {
		t.Fatalf("got %d addresses", len(got))
	}
	if got[0].Kind != resolveraddr.KindPrivate {
		t.Errorf("100.64.1.5 = %q, want private — a CGNAT address is not reachable "+
			"from outside the carrier and the operator needs the same caveat",
			got[0].Kind)
	}
}

func TestThePortIsReadFromTheListenAddress(t *testing.T) {
	for _, tc := range []struct {
		listen string
		want   int
	}{
		{"0.0.0.0:53", 53},
		{":5353", 5353},
		{"[::]:53", 53},
		{"127.0.0.1:15353", 15353},
		{"", 0},
		{"nonsense", 0},
		{"0.0.0.0:0", 0},
		{"0.0.0.0:99999", 0},
	} {
		if got := resolveraddr.Port(tc.listen); got != tc.want {
			t.Errorf("Port(%q) = %d, want %d", tc.listen, got, tc.want)
		}
	}
}
