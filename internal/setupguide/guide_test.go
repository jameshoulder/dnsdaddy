package setupguide

import (
	"strings"
	"testing"
)

func TestSingleHostsAndSubnetsAreCanonical(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"192.168.1.50", "192.168.1.50/32"}, {"192.168.1.50/24", "192.168.1.0/24"},
		{"2001:db8::50", "2001:db8::50/128"}, {"::ffff:192.168.1.50/128", "192.168.1.50/32"},
	} {
		p, e := ParseClient(tc.raw)
		if e != nil || p.String() != tc.want {
			t.Errorf("%s: %v %v", tc.raw, p, e)
		}
	}
}

func TestInvalidInputsCannotBecomeBroadGrants(t *testing.T) {
	for _, s := range []string{"0.0.0.0/0", "::/0", "128.0.0.0/1", "192.168.1.1:53", "https://example.com", "192.168.1.1-192.168.1.10", "fe80::1%eth0", "224.0.0.1", "::ffff:192.168.1.1/80", "192.168.1.0/33"} {
		if _, e := ParseClient(s); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestEveryPresetBuildsBoundedReadyFiles(t *testing.T) {
	for _, tc := range []struct{ preset, server, clients string }{
		{"lan", "192.168.1.2", "192.168.1.0/24"}, {"device", "192.168.1.2", "192.168.1.50"},
		{"vps", "203.0.113.53", "198.51.100.9"}, {"vpn", "100.64.10.2", "100.64.10.20"},
		{"roaming", "203.0.113.53", ""}, {"local", "127.0.0.1", "127.0.0.1"},
	} {
		t.Run(tc.preset, func(t *testing.T) {
			p, e := Build(Input{Preset: tc.preset, ServerIP: tc.server, Clients: tc.clients})
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(p.Environment, "DNSDADDY_ALLOW_PUBLIC_RESOLVER=false") {
				t.Fatal("open resolver")
			}
			if !strings.Contains(p.ComposeOverride, "127.0.0.1:8080:8080") {
				t.Fatal("dashboard exposed")
			}
			if strings.Contains(p.Environment, "ADMIN_PASSWORD=") {
				t.Fatal("shared credential")
			}
			if tc.preset == "roaming" && (p.GrantSourceAccess || strings.Contains(p.ComposeOverride, "5353")) {
				t.Fatal("roaming opened plaintext DNS")
			}
			if tc.preset == "local" && !strings.Contains(p.ComposeOverride, "127.0.0.1:5353:5353") {
				t.Fatal("dev port not loopback 5353")
			}
			if p.PublicAckRequired != (tc.preset == "vps") {
				t.Fatalf("public ack %v", p.PublicAckRequired)
			}
		})
	}
}

func TestVPSExplainsPrivateSourceMistake(t *testing.T) {
	_, e := Build(Input{Preset: "vps", ServerIP: "203.0.113.53", Clients: "192.168.1.0/24"})
	if e == nil || !strings.Contains(e.Error(), "public egress") {
		t.Fatal(e)
	}
}

func TestDifferentSingleDeviceAndNetworkChoices(t *testing.T) {
	if _, e := Build(Input{Preset: "device", ServerIP: "192.168.1.2", Clients: "192.168.1.0/24"}); e == nil {
		t.Fatal("device accepted network")
	}
	p, e := Build(Input{Preset: "lan", ServerIP: "192.168.1.2", Clients: "192.168.1.50/24,192.168.1.0/24"})
	if e != nil || len(p.CIDRs) != 1 {
		t.Fatalf("%+v %v", p, e)
	}
}

func TestEndpointIsNotAnAddressFromUntrustedHeaders(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "::", "224.0.0.1", "http://192.168.1.1", "example.com", "192.168.1.2/24", "fe80::1%eth0", "192.168.1.1\nEVIL=true"} {
		if _, e := Endpoint(s, 53); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if got, e := Endpoint("2001:db8::53", 5353); e != nil || got != "[2001:db8::53]:5353" {
		t.Fatalf("%s %v", got, e)
	}
}

func TestWidePrefixIsNotMislabelledPrivate(t *testing.T) {
	p, e := Build(Input{Preset: "lan", ServerIP: "192.168.1.2", Clients: "192.168.0.0/8"})
	if e != nil || !p.PublicAckRequired {
		t.Fatalf("%+v %v", p, e)
	}
}

func TestModesAndIPv6PortMappings(t *testing.T) {
	for _, mode := range []string{"off", "observe", "enforce"} {
		p, e := Build(Input{Preset: "vpn", ServerIP: "fd00::53", Clients: "fd00::50", Mode: mode})
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(p.Environment, "VALIDATION="+mode) || !strings.Contains(p.ComposeOverride, "[fd00::53]:53:5353") {
			t.Fatal(p)
		}
	}
	if _, e := Build(Input{Preset: "lan", ServerIP: "192.168.1.2", Clients: "192.168.1.50", Mode: "magic"}); e == nil {
		t.Fatal("invalid mode")
	}
}
