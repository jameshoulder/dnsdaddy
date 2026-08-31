package config

import "testing"

// IPv6 is where an IPv4-only security assumption goes wrong quietly: "[::]"
// looks nothing like "0.0.0.0" but publishes just as much, and on a
// dual-stack host it also covers every IPv4 address through the v4-mapped
// range. These are the classifications that decide whether the management
// interface may bind at all, printed for the record.
func TestIPv6BindClassificationsAreExplicit(t *testing.T) {
	cases := []struct {
		listen string
		want   ManagementBindKind
		gated  bool
	}{
		{"[::]:8080", BindWildcard, true},               // every interface, v6 AND v4-mapped
		{"[::1]:8080", BindLoopback, false},             // this machine only
		{"::1", BindLoopback, false},                    // no port
		{"[fd00::1]:8080", BindPrivate, false},          // ULA — the v6 LAN deployment
		{"[fe80::1%eth0]:8080", BindPrivate, false},     // zoned link-local
		{"[2001:db8::1]:8080", BindPublic, true},        // globally routable
		{"[::ffff:203.0.113.9]:8080", BindPublic, true}, // v4-mapped public, judged on the v4 address
		{"[::ffff:127.0.0.1]:8080", BindLoopback, false},
	}

	for _, tc := range cases {
		got := ClassifyManagementBind(tc.listen)
		if got != tc.want {
			t.Errorf("ClassifyManagementBind(%q) = %v, want %v", tc.listen, got, tc.want)
		}
		if got.NeedsPublicBindAck() != tc.gated {
			t.Errorf("%q: NeedsPublicBindAck = %v, want %v", tc.listen, got.NeedsPublicBindAck(), tc.gated)
		}

		cfg := Default()
		cfg.HTTP.Listen = tc.listen
		err := cfg.validate()
		if tc.gated && err == nil {
			t.Errorf("%q was accepted without http.allow_public_bind", tc.listen)
		}
		if !tc.gated && err != nil {
			t.Errorf("%q was refused: %v", tc.listen, err)
		}
		t.Logf("  %-28s %-9s gated=%v", tc.listen, got, tc.gated)
	}
}
