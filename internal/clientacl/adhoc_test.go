package clientacl

import (
	"context"
	"net/netip"
	"testing"
)

// The tests in this file are about one question: who is admitted once the
// built-in Default row decides whether unmatched clients may resolve.
//
// They are deliberately written against the controller rather than Compute
// wherever a reload is involved, because "takes effect after a reload" is the
// property an operator actually depends on — the dashboard writes a row and
// expects the next query to be answered differently.

func defaultRow(allow bool) Network {
	return Network{ID: DefaultNetworkID, Name: "Default", Enabled: true, AllowResolver: allow}
}

// privatePool is the shipped bootstrap ACL in miniature: loopback, a LAN
// range and a ULA range.
var privatePool = []string{"127.0.0.0/8", "::1/128", "192.168.0.0/16", "fc00::/7"}

func TestAdHocAccessOffRefusesUnmatchedClientsButKeepsLoopback(t *testing.T) {
	set := Compute(privatePool, false, []Network{defaultRow(false)})

	if set.Unrestricted() {
		t.Fatal("ad-hoc access off produced an unrestricted ACL")
	}
	for _, addr := range []string{"127.0.0.1", "::1"} {
		if !set.Allows(netip.MustParseAddr(addr)) {
			t.Errorf("%s was refused; the resolver must stay usable from the machine it runs on", addr)
		}
	}
	for _, addr := range []string{"192.168.1.20", "fd00::20"} {
		if set.Allows(netip.MustParseAddr(addr)) {
			t.Errorf("%s was admitted while ad-hoc access was off", addr)
		}
	}
}

func TestAdHocAccessOnAdmitsTheConfiguredPoolAndNothingElse(t *testing.T) {
	set := Compute(privatePool, false, []Network{defaultRow(true)})

	for _, addr := range []string{"192.168.1.20", "fd00::20", "127.0.0.1"} {
		if !set.Allows(netip.MustParseAddr(addr)) {
			t.Errorf("%s was refused while ad-hoc access was on", addr)
		}
	}
	// The whole point of the switch is that it admits clients *within* the
	// configured boundary. Turning it on must never reach past that boundary.
	for _, addr := range []string{"203.0.113.9", "2001:db8::1", "8.8.8.8"} {
		if set.Allows(netip.MustParseAddr(addr)) {
			t.Errorf("%s was admitted; ad-hoc access must not widen dns.allowed_client_cidrs", addr)
		}
	}
}

// Closing the gate must not close it on localhost. The shipped ACL names both
// loopback ranges, so a stock install keeps `dig @127.0.0.1`, its health checks
// and any local stub resolver working while unmatched clients are refused.
func TestConfiguredLoopbackSurvivesBothAdHocStates(t *testing.T) {
	for _, adHoc := range []bool{false, true} {
		set := Compute(privatePool, false, []Network{defaultRow(adHoc)})
		for _, addr := range []string{"127.0.0.1", "::1"} {
			if !set.Allows(netip.MustParseAddr(addr)) {
				t.Errorf("ad-hoc=%v: %s was refused", adHoc, addr)
			}
		}
	}
}

// The other half, and the one that keeps the exception honest: loopback is
// carried through the gate because the operator configured it, not because the
// gate manufactures it.
//
// An operator who leaves loopback out of dns.allowed_client_cidrs has excluded
// it deliberately — CI does exactly this to prove a client outside the pool is
// refused — and inventing it back would widen the single list that decides who
// may query at all. That is the silent security fallback this design forbids.
func TestGatingOffDoesNotInventLoopback(t *testing.T) {
	pool := []string{"192.168.0.0/16"} // deliberately no loopback entry
	for _, adHoc := range []bool{false, true} {
		set := Compute(pool, false, []Network{defaultRow(adHoc)})
		for _, addr := range []string{"127.0.0.1", "::1"} {
			if set.Allows(netip.MustParseAddr(addr)) {
				t.Errorf("ad-hoc=%v: %s was admitted, and no configured range names it", adHoc, addr)
			}
		}
	}
}

// Whatever the gate admits when closed is a subset of what it admits when
// open, for any pool. Without that, toggling the switch could take access away
// instead of granting it — which is how the invented-loopback version behaved
// for a pool that did not name loopback.
func TestOpeningTheGateNeverRemovesAccess(t *testing.T) {
	pools := [][]string{
		privatePool,
		{"192.168.0.0/16"},
		{"127.0.0.0/8"},
		{"203.0.113.42/32"},
	}
	probes := []string{"127.0.0.1", "::1", "192.168.1.20", "fd00::20", "203.0.113.42", "8.8.8.8"}

	for _, pool := range pools {
		off := Compute(pool, false, []Network{defaultRow(false)})
		on := Compute(pool, false, []Network{defaultRow(true)})
		for _, addr := range probes {
			a := netip.MustParseAddr(addr)
			if off.Allows(a) && !on.Allows(a) {
				t.Errorf("pool %v: %s is admitted with ad-hoc off and refused with it on", pool, addr)
			}
		}
	}
}

// The configured list is what the operator wrote. Reporting the gate's decision
// in its place would make every diagnostic misdescribe the configuration file.
func TestTheConfiguredPoolIsStillReportedWhileGatedOff(t *testing.T) {
	set := Compute(privatePool, false, []Network{defaultRow(false)})

	if got := len(set.Bootstrap()); got != len(privatePool) {
		t.Fatalf("Bootstrap() reported %d ranges, want the %d the operator configured", got, len(privatePool))
	}
	if set.AdHocAccess() {
		t.Fatal("AdHocAccess() said the pool was in force while it was gated off")
	}
	if !set.AdHocAccessGated() {
		t.Fatal("AdHocAccessGated() did not report that a Default row made the decision")
	}
}

func TestAnExplicitNetworkResolvesWhileAdHocAccessIsOff(t *testing.T) {
	set := Compute(privatePool, false, []Network{
		defaultRow(false),
		{ID: "n_lab", Name: "Lab", Enabled: true, AllowResolver: true, CIDRs: []string{"10.23.0.0/24"}},
	})

	if !set.Allows(netip.MustParseAddr("10.23.0.15")) {
		t.Fatal("an explicitly permitted network was refused; a managed grant does not depend on the ad-hoc switch")
	}
	if set.Allows(netip.MustParseAddr("192.168.1.20")) {
		t.Fatal("an unmatched client inherited the bootstrap pool while ad-hoc access was off")
	}
}

// A network sitting inside a gated-off bootstrap range is refused, not
// shadowed. Telling an operator it is "reachable anyway" would be the exact
// opposite of what the resolver does.
func TestAGatedOffPoolDoesNotShadowNetworks(t *testing.T) {
	networks := []Network{
		defaultRow(false),
		{ID: "n_home", Name: "Home", Enabled: true, CIDRs: []string{"192.168.1.0/24"}},
	}
	if got := Compute(privatePool, false, networks).Shadowed(); len(got) != 0 {
		t.Fatalf("reported %d shadowed networks while the covering pool was gated off: %+v", len(got), got)
	}

	networks[0] = defaultRow(true)
	if got := Compute(privatePool, false, networks).Shadowed(); len(got) != 1 {
		t.Fatalf("reported %d shadowed networks with the pool in force, want 1", len(got))
	}
}

// The Default row is an invariant maintained by the store. If it is missing
// anyway, the gate does not apply and the pre-feature behaviour stands —
// failing to the old model rather than to no DNS at all.
func TestWithNoDefaultRowTheGateDoesNotApply(t *testing.T) {
	set := Compute(privatePool, false, []Network{
		{ID: "n_lab", Name: "Lab", Enabled: true, CIDRs: []string{"10.23.0.0/24"}},
	})

	if !set.Allows(netip.MustParseAddr("192.168.1.20")) {
		t.Fatal("the configured pool stopped admitting clients with no Default row to gate it")
	}
	if set.AdHocAccessGated() {
		t.Fatal("AdHocAccessGated() claimed a Default row decided when none was present")
	}
}

// A disabled Default row grants nothing, on the same principle as any other
// disabled network: "disabled" must not leave a hole open.
func TestADisabledDefaultRowDoesNotGrantAdHocAccess(t *testing.T) {
	set := Compute(privatePool, false, []Network{
		{ID: DefaultNetworkID, Name: "Default", Enabled: false, AllowResolver: true},
	})
	if set.Allows(netip.MustParseAddr("192.168.1.20")) {
		t.Fatal("a disabled Default row still admitted unmatched clients")
	}
}

// The trap this whole feature has to avoid: Compute reads an empty prefix list
// as "refuse nothing", so any code path that filters the pool down to nothing
// must never hand it an empty slice.
func TestGatingOffNeverProducesAnUnrestrictedACL(t *testing.T) {
	for _, pool := range [][]string{
		{"203.0.113.42/32"},        // no loopback, nothing left after gating
		{"192.168.0.0/16"},         // ordinary LAN pool
		{"127.0.0.0/8", "::1/128"}, // loopback only
	} {
		set := Compute(pool, false, []Network{defaultRow(false)})
		if set.Unrestricted() {
			t.Fatalf("pool %v became unrestricted when ad-hoc access was switched off", pool)
		}
		if set.Allows(netip.MustParseAddr("203.0.113.42")) && pool[0] == "203.0.113.42/32" {
			t.Fatalf("pool %v admitted its configured address while gated off", pool)
		}
	}
}

// An operator who configured no ACL has said "refuse nothing", and config
// validation only accepts that alongside loopback-only listeners or an explicit
// dns.allow_public_resolver. There is no boundary for the gate to govern, and
// inventing one would take DNS away from a deliberate public resolver the first
// time it was upgraded.
func TestADeliberatePublicResolverIsNotGatedIntoLoopbackOnly(t *testing.T) {
	set := Compute(nil, true, []Network{defaultRow(false)})

	if !set.Unrestricted() {
		t.Fatalf("an empty client ACL stopped being unrestricted; effective = %v", set.Effective())
	}
	if !set.Allows(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("a deliberately public resolver refused a public client")
	}
	if !set.AllowPublicResolver() {
		t.Fatal("the explicit public-resolver opt-in was lost")
	}
}

func TestEnablingAndRevokingAdHocAccessTakeEffectOnReload(t *testing.T) {
	networks := []Network{defaultRow(false)}
	c := NewController(privatePool, false, func(context.Context) ([]Network, error) {
		return append([]Network(nil), networks...), nil
	})

	client := netip.MustParseAddr("192.168.1.20")

	if err := c.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Allows(client) {
		t.Fatal("the first reload admitted an unmatched client with ad-hoc access off")
	}

	networks[0] = defaultRow(true)
	if err := c.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.Allows(client) {
		t.Fatal("enabling ad-hoc access did not take effect on reload")
	}

	networks[0] = defaultRow(false)
	if err := c.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Allows(client) {
		t.Fatal("revoking ad-hoc access did not take effect on reload")
	}
	if !c.Allows(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("revoking ad-hoc access took loopback away")
	}
}
