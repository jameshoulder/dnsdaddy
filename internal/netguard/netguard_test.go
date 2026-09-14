package netguard

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// TestTheMetadataServiceIsRefusedUnderEveryPolicy.
//
// This is the address that matters most. Every major cloud puts its instance
// metadata service on 169.254.169.254, and it hands out credentials for the
// host — strictly more authority than administering this dashboard. Somebody
// who can type a URL into the management API must not thereby become an admin
// of the account the VM runs in.
func TestTheMetadataServiceIsRefusedUnderEveryPolicy(t *testing.T) {
	for _, raw := range []string{
		"169.254.169.254",        // every major cloud
		"::ffff:169.254.169.254", // the same address, written as 4-in-6
		"169.254.0.1",            // the rest of link-local
		"fe80::1",                // IPv6 link-local
		"fd00:ec2::254",          // AWS's IPv6 metadata endpoint
	} {
		addr := netip.MustParseAddr(raw)
		for _, p := range []Policy{AllowPrivate, PublicOnly} {
			if err := Check(addr, p); err == nil {
				t.Errorf("%s was allowed under policy %d", raw, p)
			} else if !errors.Is(err, ErrBlocked) {
				t.Errorf("%s: error %v does not wrap ErrBlocked", raw, err)
			}
		}
	}
}

// TestAllowPrivateStillReachesAnOperatorsOwnNetwork.
//
// The narrow policy exists so a self-hosted vendor appliance on 10.0.0.0/8 —
// a stated use case for threat-intelligence providers — stays reachable.
// Tightening it here would silently break that feature, which is why the two
// postures are separate rather than one list that drifted.
func TestAllowPrivateStillReachesAnOperatorsOwnNetwork(t *testing.T) {
	for _, raw := range []string{
		"10.0.0.1", "192.168.1.10", "172.16.0.1",
		"127.0.0.1", "::1",
		"fd00::1", // unique-local, where an operator's own services live
		"8.8.8.8",
	} {
		if err := Check(netip.MustParseAddr(raw), AllowPrivate); err != nil {
			t.Errorf("%s was refused under AllowPrivate: %v", raw, err)
		}
	}
}

// TestPublicOnlyRefusesEverythingThatIsNotTheInternet.
//
// A findings webhook goes to Slack, Teams or a chat tool. One pointed at
// 127.0.0.1 or 10.0.0.1 is either a mistake or somebody using the management
// API to make this process probe its own host and LAN, which is the textbook
// shape of a server-side request forgery.
func TestPublicOnlyRefusesEverythingThatIsNotTheInternet(t *testing.T) {
	for _, tc := range []struct{ raw, because string }{
		{"127.0.0.1", "this machine"},
		{"127.0.0.53", "this machine"},
		{"::1", "this machine"},
		{"0.0.0.0", "not a destination"},
		{"::", "not a destination"},
		{"10.0.0.1", "private network"},
		{"192.168.1.10", "private network"},
		{"172.16.0.1", "private network"},
		{"fd00::1", "unique-local"},
		{"100.64.0.1", "carrier-grade NAT"},
		// 224.0.0.1 is deliberately NOT here: it is inside 224.0.0.0/24,
		// which is link-local multicast, and the link-local arm catches it
		// first with an accurate message. It is covered above instead.
		{"239.255.255.250", "multicast"},
		{"ff02::1", "link-local"},
	} {
		err := Check(netip.MustParseAddr(tc.raw), PublicOnly)
		if err == nil {
			t.Errorf("%s was allowed under PublicOnly", tc.raw)
			continue
		}
		if !strings.Contains(err.Error(), tc.because) {
			t.Errorf("%s: refused with %q, which does not say it is %q",
				tc.raw, err, tc.because)
		}
	}
}

// TestPublicOnlyStillAllowsTheInternet, so the strict policy is a filter
// rather than a wall.
func TestPublicOnlyStillAllowsTheInternet(t *testing.T) {
	for _, raw := range []string{
		"1.1.1.1",
		"104.16.0.1",   // a CDN, where a webhook endpoint really lives
		"2606:4700::1", // and its IPv6
		"93.184.216.34",
	} {
		if err := Check(netip.MustParseAddr(raw), PublicOnly); err != nil {
			t.Errorf("%s was refused under PublicOnly: %v", raw, err)
		}
	}
}

// TestAnUnparseableAddressIsRefusedRatherThanAllowed.
//
// The only safe direction for a check whose whole job is to say no. A control
// that allowed what it could not parse would be defeated by anything that
// produced an address shape it did not expect.
func TestAnUnparseableAddressIsRefusedRatherThanAllowed(t *testing.T) {
	if err := Check(netip.Addr{}, PublicOnly); err == nil {
		t.Error("the zero address was allowed")
	}
	if err := Check(netip.Addr{}, AllowPrivate); err == nil {
		t.Error("the zero address was allowed under the narrow policy")
	}

	control := Control(PublicOnly)
	for _, address := range []string{"", "not-a-host-port", "nonsense:port", "1.2.3.4"} {
		if err := control("tcp", address, nil); err == nil {
			t.Errorf("Control allowed %q", address)
		}
	}
	// And a well-formed public address passes, so this is not refusing
	// everything.
	if err := control("tcp", "1.1.1.1:443", nil); err != nil {
		t.Errorf("Control refused a public address: %v", err)
	}
}

// TestCheckURLHostOnlyJudgesLiterals.
//
// It exists for the proxied case, where the dialer never sees the real
// destination. A hostname is left to the dialer deliberately: resolving it
// here would cost a DNS lookup per check and still not help through a proxy,
// where the proxy does the resolving and nothing on this side sees the answer.
func TestCheckURLHostOnlyJudgesLiterals(t *testing.T) {
	if err := CheckURLHost("169.254.169.254", PublicOnly); err == nil {
		t.Error("the metadata address was allowed as a URL host")
	}
	if err := CheckURLHost("169.254.169.254", AllowPrivate); err == nil {
		t.Error("the metadata address was allowed under the narrow policy")
	}
	if err := CheckURLHost("10.0.0.1", PublicOnly); err == nil {
		t.Error("a private address was allowed as a webhook host")
	}
	if err := CheckURLHost("10.0.0.1", AllowPrivate); err != nil {
		t.Errorf("a private address was refused under the narrow policy: %v", err)
	}
	// Hostnames pass here and are judged by the dialer.
	for _, host := range []string{"hooks.slack.com", "example.com", "localhost"} {
		if err := CheckURLHost(host, PublicOnly); err != nil {
			t.Errorf("the hostname %q was refused before it was resolved: %v", host, err)
		}
	}
}

// TestTheTwoPoliciesGenuinelyDiffer, so a future edit that collapsed them into
// one would fail here rather than silently loosening the webhook or breaking
// internal providers.
func TestTheTwoPoliciesGenuinelyDiffer(t *testing.T) {
	private := netip.MustParseAddr("10.0.0.1")
	if Check(private, AllowPrivate) != nil {
		t.Fatal("AllowPrivate refuses a private address")
	}
	if Check(private, PublicOnly) == nil {
		t.Fatal("PublicOnly allows a private address")
	}
}
