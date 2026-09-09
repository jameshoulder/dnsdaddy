package clientacl

import (
	"context"
	"net/netip"
	"testing"
)

func TestDefaultNetworkGatesBootstrapAdHocAccess(t *testing.T) {
	networks := []Network{{
		ID:            defaultNetworkID,
		Name:          "Default",
		Enabled:       true,
		AllowResolver: false,
	}}
	load := func(context.Context) ([]Network, error) {
		return append([]Network(nil), networks...), nil
	}
	c := NewController([]string{
		"127.0.0.0/8",
		"192.168.0.0/16",
		"fc00::/7",
	}, false, load)

	if err := c.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.Allows(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback must remain available while ad-hoc access is off")
	}
	if c.Allows(netip.MustParseAddr("192.168.1.20")) {
		t.Fatal("unmatched LAN client was admitted while Default ad-hoc access was off")
	}
	if c.Allows(netip.MustParseAddr("fd00::20")) {
		t.Fatal("unmatched ULA client was admitted while Default ad-hoc access was off")
	}

	networks[0].AllowResolver = true
	if err := c.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.Allows(netip.MustParseAddr("192.168.1.20")) {
		t.Fatal("Default ad-hoc access did not activate the configured bootstrap pool")
	}
	if !c.Allows(netip.MustParseAddr("fd00::20")) {
		t.Fatal("Default ad-hoc access did not activate the IPv6 bootstrap pool")
	}
}

func TestExplicitNetworkStillWorksWithDefaultAccessOff(t *testing.T) {
	load := func(context.Context) ([]Network, error) {
		return []Network{
			{ID: defaultNetworkID, Name: "Default", Enabled: true, AllowResolver: false},
			{
				ID:            "n_lab",
				Name:          "Lab",
				Enabled:       true,
				AllowResolver: true,
				CIDRs:         []string{"10.23.0.0/24"},
			},
		}, nil
	}
	c := NewController([]string{"10.0.0.0/8"}, false, load)
	if err := c.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !c.Allows(netip.MustParseAddr("10.23.0.15")) {
		t.Fatal("explicitly permitted Network should work independently of Default")
	}
	if c.Allows(netip.MustParseAddr("10.24.0.15")) {
		t.Fatal("unmatched client should not inherit the bootstrap pool while Default is off")
	}
}

func TestConfigOnlyControllerKeepsBootstrapBehaviour(t *testing.T) {
	c := NewController([]string{"192.168.0.0/16"}, false, nil)
	if !c.Allows(netip.MustParseAddr("192.168.50.10")) {
		t.Fatal("headless/config-only controller must keep using its configured ACL directly")
	}
}

func TestDefaultOffNeverTurnsAnEmptyFilteredACLIntoUnrestricted(t *testing.T) {
	load := func(context.Context) ([]Network, error) {
		return []Network{{ID: defaultNetworkID, Enabled: true, AllowResolver: false}}, nil
	}
	c := NewController([]string{"203.0.113.42/32"}, false, load)
	if err := c.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	if c.Current().Unrestricted() {
		t.Fatal("Default off must fail closed rather than turning an empty filtered ACL into unrestricted access")
	}
	if c.Allows(netip.MustParseAddr("203.0.113.42")) {
		t.Fatal("configured ad-hoc address was admitted while Default access was off")
	}
	if !c.Allows(netip.MustParseAddr("::1")) {
		t.Fatal("loopback fallback should remain available")
	}
}
