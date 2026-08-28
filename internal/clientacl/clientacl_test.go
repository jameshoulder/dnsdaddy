package clientacl

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func allows(t *testing.T, s *Set, addr string) bool {
	t.Helper()
	return s.Allows(netip.MustParseAddr(addr))
}

func permitted(id, name string, cidrs ...string) Network {
	return Network{ID: id, Name: name, Enabled: true, AllowResolver: true, CIDRs: cidrs}
}

func unpermitted(id, name string, cidrs ...string) Network {
	return Network{ID: id, Name: name, Enabled: true, AllowResolver: false, CIDRs: cidrs}
}

// The bug this whole package exists to fix: a network added in the dashboard
// and marked as permitted must be able to resolve, without anyone editing an
// environment variable.
func TestDashboardPermissionWidensTheBootstrapACL(t *testing.T) {
	bootstrap := []string{"127.0.0.0/8", "172.16.0.0/12"}

	before := Compute(bootstrap, false, nil)
	if allows(t, before, "203.0.113.25") {
		t.Fatal("the bootstrap ACL should not admit a public address on its own")
	}

	after := Compute(bootstrap, false, []Network{permitted("n1", "VPS client", "203.0.113.25/32")})
	if !allows(t, after, "203.0.113.25") {
		t.Error("a permitted network is still refused; adding it in the dashboard did nothing")
	}
	// Widening must not smuggle in the neighbours.
	if allows(t, after, "203.0.113.26") {
		t.Error("a /32 permission admitted an adjacent address")
	}
	if !allows(t, after, "127.0.0.1") {
		t.Error("the bootstrap ACL stopped applying once a dashboard permission existed")
	}
}

// Revocation is the other half, and the half that matters for security: an
// unticked box must permit nothing.
func TestRevokingAPermissionRefusesAgain(t *testing.T) {
	bootstrap := []string{"127.0.0.0/8"}
	granted := Compute(bootstrap, false, []Network{permitted("n1", "Home", "192.168.1.0/24")})
	if !allows(t, granted, "192.168.1.50") {
		t.Fatal("precondition: the permitted network should resolve")
	}

	revoked := Compute(bootstrap, false, []Network{unpermitted("n1", "Home", "192.168.1.0/24")})
	if allows(t, revoked, "192.168.1.50") {
		t.Error("a revoked network still resolves")
	}
}

// A disabled network permits nothing. "Disabled" that leaves a hole open is
// worse than no switch at all.
func TestDisabledNetworkPermitsNothing(t *testing.T) {
	s := Compute([]string{"127.0.0.0/8"}, false,
		[]Network{{ID: "n1", Name: "Old site", Enabled: false, AllowResolver: true, CIDRs: []string{"192.168.1.0/24"}}})
	if allows(t, s, "192.168.1.50") {
		t.Error("a disabled network still permits its range")
	}
}

// An empty bootstrap ACL means "refuse nothing". Adding the first dashboard
// permission must not silently convert that into "refuse everything except
// this range" — that would narrow a running deployment as a side effect of an
// unrelated click.
func TestEmptyBootstrapStaysUnrestricted(t *testing.T) {
	s := Compute(nil, false, []Network{permitted("n1", "Home", "192.168.1.0/24")})

	if !s.Unrestricted() {
		t.Fatal("an empty bootstrap ACL was narrowed by a dashboard permission")
	}
	for _, addr := range []string{"192.168.1.50", "203.0.113.9", "2001:db8::1"} {
		if !allows(t, s, addr) {
			t.Errorf("%s was refused by an ACL that refuses nothing", addr)
		}
	}
	// The permission is still recorded, so it takes effect the moment an ACL
	// is configured, and so the dashboard can show it.
	if len(s.Grants()) != 1 {
		t.Errorf("grants = %d, want the permission recorded for when an ACL exists", len(s.Grants()))
	}
}

// Existing deployments must keep working exactly as they did. A network that
// predates the feature has allow_resolver false, and the bootstrap list alone
// has to keep admitting whoever it admitted before.
func TestLegacyDeploymentIsUnchanged(t *testing.T) {
	bootstrap := []string{"127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"}
	legacy := []Network{unpermitted("n_default", "Default"), unpermitted("n1", "HQ", "10.1.0.0/16")}

	s := Compute(bootstrap, false, legacy)
	want := map[string]bool{"127.0.0.1": true, "10.1.2.3": true, "192.168.4.4": true, "203.0.113.1": false}
	for addr, ok := range want {
		if allows(t, s, addr) != ok {
			t.Errorf("Allows(%s) = %v, want %v — an upgrade changed who may resolve", addr, !ok, ok)
		}
	}
	if len(s.Effective()) != len(bootstrap) {
		t.Errorf("effective ACL = %v, want exactly the configured list", s.Effective())
	}
}

func TestIPv6(t *testing.T) {
	bootstrap := []string{"::1/128"}

	t.Run("public /128", func(t *testing.T) {
		s := Compute(bootstrap, false, []Network{permitted("n1", "Six", "2001:db8::5/128")})
		if !allows(t, s, "2001:db8::5") {
			t.Error("a permitted IPv6 host is refused")
		}
		if allows(t, s, "2001:db8::6") {
			t.Error("a /128 permission admitted its neighbour")
		}
	})

	t.Run("unique local", func(t *testing.T) {
		s := Compute(bootstrap, false, []Network{permitted("n1", "ULA", "fd00:1234::/32")})
		if !allows(t, s, "fd00:1234::99") {
			t.Error("a permitted unique-local range is refused")
		}
	})

	// Link-local is how a router advertises a resolver over RFC 8106 RDNSS, and
	// the peer address arrives carrying a scope zone that netip.Prefix.Contains
	// rejects outright. This is the fix from PR #33, asserted here so the move
	// into this package cannot lose it.
	t.Run("zoned link-local", func(t *testing.T) {
		s := Compute(bootstrap, false, []Network{permitted("n1", "LAN", "fe80::/10")})
		if !s.Allows(netip.MustParseAddr("fe80::1%eth0")) {
			t.Error("a zoned link-local address inside fe80::/10 was refused")
		}
		// And the zone must not become a way around the ACL.
		if s.Allows(netip.MustParseAddr("2001:db8::1%eth0")) {
			t.Error("a zoned address outside every permitted range was admitted")
		}
	})

	t.Run("v4 over a dual-stack socket", func(t *testing.T) {
		s := Compute([]string{"192.168.0.0/16"}, false, nil)
		if !s.Allows(netip.MustParseAddr("::ffff:192.168.1.5")) {
			t.Error("a v4 client arriving as ::ffff: was refused by a v4 prefix")
		}
	})

	t.Run("removing access", func(t *testing.T) {
		granted := Compute(bootstrap, false, []Network{permitted("n1", "Six", "2001:db8::/64")})
		if !allows(t, granted, "2001:db8::1") {
			t.Fatal("precondition")
		}
		revoked := Compute(bootstrap, false, []Network{unpermitted("n1", "Six", "2001:db8::/64")})
		if allows(t, revoked, "2001:db8::1") {
			t.Error("a revoked IPv6 permission still resolves")
		}
	})

	t.Run("overlapping prefixes", func(t *testing.T) {
		s := Compute(bootstrap, false, []Network{
			permitted("n1", "Site", "2001:db8::/48"),
			unpermitted("n2", "Guest", "2001:db8:0:1::/64"),
		})
		// The union has no deny rules, so the narrower unpermitted range is
		// still inside the wider permitted one. That is the documented model,
		// and it is reported rather than silently true.
		if !allows(t, s, "2001:db8:0:1::9") {
			t.Error("the union model should still admit an address inside a permitted /48")
		}
		if len(s.Shadowed()) != 1 {
			t.Fatalf("shadowed = %d, want the overlap reported", len(s.Shadowed()))
		}
		if s.Shadowed()[0].NetworkName != "Guest" {
			t.Errorf("shadow names %q, want Guest", s.Shadowed()[0].NetworkName)
		}
	})
}

// Overlap in v4, including the case where the wider range is the configured
// bootstrap list rather than another network — that is the one an operator is
// least likely to be looking at, so it must be named.
func TestOverlappingIPv4IsReportedNotSilent(t *testing.T) {
	s := Compute([]string{"10.0.0.0/8"}, false, []Network{unpermitted("n1", "Lab", "10.50.0.0/16")})

	if !allows(t, s, "10.50.0.1") {
		t.Error("an address inside a configured range was refused because a network did not permit it")
	}
	shadows := s.Shadowed()
	if len(shadows) != 1 {
		t.Fatalf("shadowed = %d, want 1", len(shadows))
	}
	if shadows[0].Source != SourceBootstrap {
		t.Errorf("source = %q, want the configuration named as the cause", shadows[0].Source)
	}
	if shadows[0].CoveredBy != "10.0.0.0/8" {
		t.Errorf("coveredBy = %q, want 10.0.0.0/8", shadows[0].CoveredBy)
	}
}

// A permitted network is not shadowed by anything: it is permitted in its own
// right, and reporting it would be noise on a correct configuration.
func TestPermittedNetworkIsNotReportedAsShadowed(t *testing.T) {
	s := Compute([]string{"10.0.0.0/8"}, false, []Network{permitted("n1", "Lab", "10.50.0.0/16")})
	if len(s.Shadowed()) != 0 {
		t.Errorf("shadowed = %v, want none for a network that carries its own permission", s.Shadowed())
	}
}

func TestPrefixIsPublic(t *testing.T) {
	tests := map[string]bool{
		"203.0.113.25/32": true, // documentation range: public space, and what the docs use
		"8.8.8.8/32":      true,
		"198.51.100.0/24": true,
		"10.0.0.0/8":      false,
		"10.1.2.3/32":     false,
		"172.16.0.0/12":   false,
		"172.32.0.0/12":   true, // just outside RFC 1918
		"192.168.1.0/24":  false,
		"127.0.0.1/32":    false,
		"100.64.0.0/10":   false, // CGNAT, what Tailscale hands out
		"169.254.1.1/32":  false,
		"2001:db8::/32":   true,
		"fd00::/8":        false,
		"fe80::/10":       false,
		"::1/128":         false,
		"0.0.0.0/0":       true, // contains all of it
		"::/0":            true,
		// A prefix that straddles private and public space is public: part of
		// it is reachable, and that is the part worth asking about.
		"10.0.0.0/7": true,
	}
	for cidr, want := range tests {
		p := netip.MustParsePrefix(cidr)
		if got := PrefixIsPublic(p); got != want {
			t.Errorf("PrefixIsPublic(%s) = %v, want %v", cidr, got, want)
		}
	}
}

func TestIsUniversal(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		if !IsUniversal(netip.MustParsePrefix(cidr)) {
			t.Errorf("%s is not recognised as a default route", cidr)
		}
	}
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1", "10.0.0.0/8", "::/1"} {
		if IsUniversal(netip.MustParsePrefix(cidr)) {
			t.Errorf("%s was wrongly treated as a default route", cidr)
		}
	}
}

// Splitting the default route in two is the obvious way to try to get an open
// resolver past a /0 check. It is not blocked here — a union of two halves is
// two permissions, each legal on its own — but both halves are public, so both
// require the operator's affirmation and both are reported. That is the
// designed answer: the control is the acknowledgement, and IsUniversal only
// stops the one-click version.
func TestSplitDefaultRouteIsStillFlaggedPublic(t *testing.T) {
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if !PrefixIsPublic(netip.MustParsePrefix(half)) {
			t.Errorf("%s is not flagged as public, so it would need no acknowledgement", half)
		}
	}
}

func TestParsePrefix(t *testing.T) {
	tests := map[string]string{
		"10.0.0.0/8":          "10.0.0.0/8",
		"10.1.2.3/8":          "10.0.0.0/8", // masked
		"192.168.1.7":         "192.168.1.7/32",
		"2001:db8::1":         "2001:db8::1/128",
		"::ffff:10.0.0.0/104": "10.0.0.0/8", // v4-mapped is unmapped, or it matches nothing
		"::ffff:192.168.1.5":  "192.168.1.5/32",
		" 172.16.0.0/12 ":     "172.16.0.0/12",
	}
	for in, want := range tests {
		p, err := ParsePrefix(in)
		if err != nil {
			t.Errorf("ParsePrefix(%q): %v", in, err)
			continue
		}
		if p.String() != want {
			t.Errorf("ParsePrefix(%q) = %s, want %s", in, p, want)
		}
	}

	for _, bad := range []string{"", "not-an-address", "10.0.0.0/33", "10.0.0.0/-1", "::/200"} {
		if _, err := ParsePrefix(bad); err == nil {
			t.Errorf("ParsePrefix(%q) accepted an invalid value", bad)
		}
	}
}

// A typo in the ACL has to be reported, not silently dropped: permitting less
// than the operator wrote is the failure mode this whole audit started with.
func TestInvalidEntriesAreReported(t *testing.T) {
	s := Compute([]string{"127.0.0.0/8", "192.168.0.0/33"}, false,
		[]Network{permitted("n1", "Bad", "not-a-cidr")})

	invalid := s.Invalid()
	sort.Strings(invalid)
	if len(invalid) != 2 {
		t.Fatalf("invalid = %v, want both bad entries reported", invalid)
	}
	if !allows(t, s, "127.0.0.1") {
		t.Error("a valid entry stopped working because another one was malformed")
	}
}

func TestPublicGrants(t *testing.T) {
	s := Compute([]string{"127.0.0.0/8"}, false, []Network{
		permitted("n1", "Home", "192.168.1.0/24"),
		permitted("n2", "VPS", "203.0.113.25/32"),
	})
	public := s.PublicGrants()
	if len(public) != 1 {
		t.Fatalf("public grants = %d, want 1", len(public))
	}
	if public[0].CIDR != "203.0.113.25/32" || public[0].NetworkName != "VPS" {
		t.Errorf("public grant = %+v, want the VPS /32", public[0])
	}
}

func TestUnrestrictedDistinguishesPublicResolverFromLoopbackOnly(t *testing.T) {
	if !Compute(nil, true, nil).AllowPublicResolver() {
		t.Error("a deliberate public resolver is not reported as one")
	}
	if Compute(nil, false, nil).AllowPublicResolver() {
		t.Error("a loopback-only deployment was reported as a deliberate public resolver")
	}
}

// An invalid address is admitted: that only happens on transports where the
// peer is identified another way, and failing them closed would break roaming
// clients for no security gain.
func TestInvalidAddressIsAdmitted(t *testing.T) {
	s := Compute([]string{"127.0.0.0/8"}, false, nil)
	if !s.Allows(netip.Addr{}) {
		t.Error("an unparsed peer address was refused")
	}
}

func TestEffectiveDeduplicates(t *testing.T) {
	s := Compute([]string{"10.0.0.0/8"}, false, []Network{
		permitted("n1", "A", "10.0.0.0/8"),
		permitted("n2", "B", "10.0.0.0/8"),
	})
	if got := s.Effective(); len(got) != 1 {
		t.Errorf("effective = %v, want one entry after deduplication", got)
	}
}

// --- controller -------------------------------------------------------------

// The runtime requirement: a permission granted through the API is in force on
// the next query, with no restart.
func TestControllerReloadTakesEffectImmediately(t *testing.T) {
	var (
		mu       sync.Mutex
		networks []Network
	)
	c := NewController([]string{"127.0.0.0/8"}, false, func(context.Context) ([]Network, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]Network(nil), networks...), nil
	})

	addr := netip.MustParseAddr("192.168.1.50")
	if c.Allows(addr) {
		t.Fatal("precondition: nothing permits this address yet")
	}

	mu.Lock()
	networks = []Network{permitted("n1", "Home", "192.168.1.0/24")}
	mu.Unlock()
	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !c.Allows(addr) {
		t.Error("a granted permission is not in force after a reload")
	}

	mu.Lock()
	networks = []Network{unpermitted("n1", "Home", "192.168.1.0/24")}
	mu.Unlock()
	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if c.Allows(addr) {
		t.Error("a revoked permission is still in force after a reload")
	}
}

// A transient load failure must leave the previous ACL standing: dropping
// every permission on a momentary database error would be an outage, and
// widening on one would be a hole.
func TestControllerKeepsThePreviousSetOnError(t *testing.T) {
	fail := false
	c := NewController([]string{"127.0.0.0/8"}, false, func(context.Context) ([]Network, error) {
		if fail {
			return nil, context.DeadlineExceeded
		}
		return []Network{permitted("n1", "Home", "192.168.1.0/24")}, nil
	})
	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	fail = true
	if err := c.Reload(context.Background()); err == nil {
		t.Fatal("a load failure was not reported")
	}
	if !c.Allows(netip.MustParseAddr("192.168.1.50")) {
		t.Error("a failed reload dropped a permission that was already in force")
	}
}

// The controller is read from the DNS hot path while the API reloads it.
// Run with -race.
func TestControllerIsSafeUnderConcurrentReload(t *testing.T) {
	c := NewController([]string{"127.0.0.0/8"}, false, func(context.Context) ([]Network, error) {
		return []Network{permitted("n1", "Home", "192.168.1.0/24")}, nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c.Allows(netip.MustParseAddr("192.168.1.50"))
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if err := c.Reload(context.Background()); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// Before the first reload the controller must already enforce the bootstrap
// ACL: a startup ordering slip must not leave a window with no ACL at all.
func TestControllerEnforcesBootstrapBeforeFirstReload(t *testing.T) {
	c := NewController([]string{"127.0.0.0/8"}, false, nil)
	if c.Allows(netip.MustParseAddr("203.0.113.1")) {
		t.Error("a fresh controller admitted an address the bootstrap ACL excludes")
	}
	if !c.Allows(netip.MustParseAddr("127.0.0.1")) {
		t.Error("a fresh controller refused an address the bootstrap ACL includes")
	}
}

// The private list gates a security prompt, so it must not drift away from the
// shipped default ACL without somebody noticing. Not an equality assertion:
// the two answer different questions and are allowed to differ, but a
// difference should be a decision rather than an accident.
func TestPrivateRangesCoverTheShippedDefaults(t *testing.T) {
	// Kept as literals rather than importing internal/config, which imports
	// nothing from here and should stay that way.
	shipped := []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"100.64.0.0/10", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	}
	for _, cidr := range shipped {
		if PrefixIsPublic(netip.MustParsePrefix(cidr)) {
			t.Errorf("%s ships in the default client ACL but is classified as public, so a "+
				"stock LAN install would ask the operator to acknowledge it", cidr)
		}
	}
}

func TestSourceBootstrapNamesSomethingAnOperatorCanFind(t *testing.T) {
	if !strings.Contains(SourceBootstrap, "allowed_client_cidrs") {
		t.Errorf("SourceBootstrap = %q, which does not name the setting to go and edit", SourceBootstrap)
	}
}

// A nil Set is what a caller holding an unconfigured controller gets. Every
// accessor has to tolerate it: a dashboard handler or a diagnostic panicking
// on the way to explaining a misconfiguration is the worst possible moment for
// it. Nil reads as "nothing configured", which is what Allows already did.
func TestNilSetIsSafeToRead(t *testing.T) {
	var s *Set
	if !s.Allows(netip.MustParseAddr("203.0.113.1")) {
		t.Error("a nil Set refused an address; it should restrict nothing")
	}
	if s.Unrestricted() {
		t.Error("a nil Set reported itself as an unrestricted ACL")
	}
	if s.AllowPublicResolver() {
		t.Error("a nil Set reported a deliberate public resolver")
	}
	// None of these may panic.
	_ = s.Bootstrap()
	_ = s.Grants()
	_ = s.Shadowed()
	_ = s.Invalid()
	_ = s.Effective()
	_ = s.PublicGrants()
}

// The same for a nil controller, which is what a Deps built without one holds.
func TestNilControllerIsSafeToRead(t *testing.T) {
	var c *Controller
	if !c.Allows(netip.MustParseAddr("203.0.113.1")) {
		t.Error("a nil Controller refused an address")
	}
	if c.Current() != nil {
		t.Error("a nil Controller returned a non-nil snapshot")
	}
	if err := c.Reload(context.Background()); err != nil {
		t.Errorf("Reload on a nil Controller: %v", err)
	}
}

// --- Codex review regressions -------------------------------------------------

// A headless deployment that permits a public client through the environment
// is exposed to the internet exactly as much as one that ticks a box in the
// dashboard. Scanning only the dashboard half reported no public exposure at
// all — a false negative on the one check that exists to catch this.
func TestPublicGrantsIncludeTheBootstrapHalf(t *testing.T) {
	s := Compute([]string{"127.0.0.0/8", "203.0.113.42/32"}, false, nil)

	public := s.PublicGrants()
	if len(public) != 1 {
		t.Fatalf("public grants = %+v, want the configured public range reported", public)
	}
	if public[0].CIDR != "203.0.113.42/32" {
		t.Errorf("CIDR = %q, want 203.0.113.42/32", public[0].CIDR)
	}
	if public[0].Source != SourceBootstrap {
		t.Errorf("Source = %q, want the configuration named so the operator knows where to look",
			public[0].Source)
	}
	// It must not be mistaken for a dashboard permission: Grants() is what the
	// "from the dashboard" evidence and the permitted-network count read.
	if len(s.Grants()) != 0 {
		t.Errorf("Grants = %+v, want none — nothing was permitted in the dashboard", s.Grants())
	}
}

func TestPublicGrantsReportBothHalvesTogether(t *testing.T) {
	s := Compute([]string{"127.0.0.0/8", "203.0.113.42/32"}, false,
		[]Network{permitted("n1", "Branch", "198.51.100.10/32")})

	got := map[string]string{}
	for _, g := range s.PublicGrants() {
		got[g.CIDR] = g.Source
	}
	if got["203.0.113.42/32"] != SourceBootstrap {
		t.Errorf("bootstrap range = %q, want %q", got["203.0.113.42/32"], SourceBootstrap)
	}
	if got["198.51.100.10/32"] != `network "Branch"` {
		t.Errorf("dashboard range = %q, want the network named", got["198.51.100.10/32"])
	}
}

// Sampling a prefix's base address said "permitted" for a network that starts
// at a permitted address and is almost entirely refused after that.
func TestCoverRejectsAPartiallyPermittedNetwork(t *testing.T) {
	s := Compute([]string{"10.0.0.0/16"}, false, nil)

	if got := s.Cover(netip.MustParsePrefix("10.0.0.0/8")); got != CoverPartial {
		t.Errorf("Cover(10.0.0.0/8) with an ACL of 10.0.0.0/16 = %v, want CoverPartial — "+
			"the base address is permitted and almost nothing else in the range is", got)
	}
	if got := s.Cover(netip.MustParsePrefix("10.0.5.0/24")); got != CoverFull {
		t.Errorf("Cover(10.0.5.0/24) = %v, want CoverFull", got)
	}
	if got := s.Cover(netip.MustParsePrefix("192.168.1.0/24")); got != CoverNone {
		t.Errorf("Cover(192.168.1.0/24) = %v, want CoverNone", got)
	}
}

func TestCoverIsFullWhenNothingIsRestricted(t *testing.T) {
	s := Compute(nil, false, nil)
	if got := s.Cover(netip.MustParsePrefix("203.0.113.0/24")); got != CoverFull {
		t.Errorf("Cover on an unrestricted ACL = %v, want CoverFull", got)
	}
	var nilSet *Set
	if got := nilSet.Cover(netip.MustParsePrefix("203.0.113.0/24")); got != CoverFull {
		t.Errorf("Cover on a nil Set = %v, want CoverFull", got)
	}
}

// The one state in which "no client can use this resolver" is a measurement.
// It is deliberately not "no network carries a permission": a stock LAN
// install has none and serves every private range perfectly well.
func TestServesOnlyLoopback(t *testing.T) {
	tests := []struct {
		name      string
		bootstrap []string
		networks  []Network
		want      bool
	}{
		{"loopback only", []string{"127.0.0.0/8", "::1/128"}, nil, true},
		{"the shipped LAN default", []string{"127.0.0.0/8", "192.168.0.0/16"}, nil, false},
		{"loopback plus a dashboard grant", []string{"127.0.0.0/8"},
			[]Network{permitted("n1", "Home", "192.168.1.0/24")}, false},
		{"unrestricted", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Compute(tt.bootstrap, false, tt.networks).ServesOnlyLoopback(); got != tt.want {
				t.Errorf("ServesOnlyLoopback = %v, want %v", got, tt.want)
			}
		})
	}
}

// One range permitted from both sources is two things to tell an operator and
// one exposure. PublicGrants says both, because closing it means removing it
// from both places; PublicPrefixes counts one, because that is what the gauge
// means.
func TestPublicPrefixesAreDistinctAcrossSources(t *testing.T) {
	s := Compute([]string{"127.0.0.0/8", "203.0.113.42/32"}, false,
		[]Network{permitted("n1", "Branch", "203.0.113.42/32")})

	if got := len(s.PublicGrants()); got != 2 {
		t.Errorf("PublicGrants = %d, want both sources named so either can be found", got)
	}
	prefixes := s.PublicPrefixes()
	if len(prefixes) != 1 || prefixes[0] != "203.0.113.42/32" {
		t.Errorf("PublicPrefixes = %v, want exactly one distinct range — a gauge that "+
			"doubled here would report exposure growing when nothing changed", prefixes)
	}
}

func TestPublicPrefixesIsEmptyWhenNothingPublicIsPermitted(t *testing.T) {
	s := Compute([]string{"127.0.0.0/8", "192.168.0.0/16"}, false,
		[]Network{permitted("n1", "Home", "10.0.0.0/8")})
	if got := s.PublicPrefixes(); len(got) != 0 {
		t.Errorf("PublicPrefixes = %v, want none for an entirely private ACL", got)
	}
}

// A failed reload has to outlive the request that caused it.
//
// The caller who could act on the error is often gone by the time it matters,
// and after a delete there is no network row left for anything else to notice
// the stale grant against. This flag is what lets the diagnostics keep saying
// so until a reload succeeds.
func TestStaleIsRecordedAndCleared(t *testing.T) {
	fail := false
	c := NewController([]string{"127.0.0.0/8"}, false, func(context.Context) ([]Network, error) {
		if fail {
			return nil, context.DeadlineExceeded
		}
		return []Network{permitted("n1", "Home", "192.168.1.0/24")}, nil
	})

	if c.Stale() {
		t.Error("a fresh controller reports itself stale")
	}
	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if c.Stale() {
		t.Error("a successful reload left the controller stale")
	}

	fail = true
	if err := c.Reload(context.Background()); err == nil {
		t.Fatal("a load failure was not reported")
	}
	if !c.Stale() {
		t.Error("a failed reload was not recorded; nothing downstream can know the ACL is old")
	}
	// The previous snapshot is still in force, which is the safe failure — but
	// it is now known to be possibly out of date.
	if !c.Allows(netip.MustParseAddr("192.168.1.50")) {
		t.Error("a failed reload dropped a permission that was already in force")
	}

	fail = false
	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if c.Stale() {
		t.Error("a later successful reload did not clear the stale flag")
	}
}

func TestNilControllerIsNotStale(t *testing.T) {
	var c *Controller
	if c.Stale() {
		t.Error("a nil Controller reported itself stale")
	}
}

// Load, compute and publish must be serialised.
//
// Without it two concurrent writes can publish out of order: request A reads
// the database, request B reads it, commits and publishes, and then A
// publishes the snapshot it read *before* B's change. B's revocation is
// silently absent from the live ACL and the stale flag is clear, so everything
// downstream reports it as current.
//
// Asserted as the invariant rather than by racing two reloads and hoping they
// interleave the wrong way: overlapping loads are what makes the reordering
// possible, so "no two loads overlap" fails reliably when the lock is missing
// where a timing race would only fail sometimes.
func TestReloadsDoNotOverlap(t *testing.T) {
	var (
		inFlight   atomic.Int32
		overlapped atomic.Bool
		loads      atomic.Int32
	)
	c := NewController([]string{"127.0.0.0/8"}, false, func(context.Context) ([]Network, error) {
		if inFlight.Add(1) > 1 {
			overlapped.Store(true)
		}
		// Wide enough that unsynchronised callers will certainly be inside
		// this window together.
		time.Sleep(2 * time.Millisecond)
		inFlight.Add(-1)
		loads.Add(1)
		return []Network{permitted("n1", "Home", "192.168.1.0/24")}, nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Reload(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	if overlapped.Load() {
		t.Error("two reloads read the database at once; the later one can be overwritten by " +
			"the earlier one's snapshot, losing a grant or a revocation silently")
	}
	if got := loads.Load(); got != 16 {
		t.Errorf("loads = %d, want 16 — every reload must actually re-read", got)
	}
	if !c.Allows(netip.MustParseAddr("192.168.1.50")) {
		t.Error("the final published snapshot does not reflect the loader's state")
	}
}

// The ordering that matters, stated directly: whatever the loader returned
// last is what ends up in force.
func TestTheLastReloadWins(t *testing.T) {
	var (
		mu      sync.Mutex
		granted = true
	)
	c := NewController([]string{"127.0.0.0/8"}, false, func(context.Context) ([]Network, error) {
		mu.Lock()
		defer mu.Unlock()
		if !granted {
			return []Network{unpermitted("n1", "Home", "192.168.1.0/24")}, nil
		}
		return []Network{permitted("n1", "Home", "192.168.1.0/24")}, nil
	})

	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !c.Allows(netip.MustParseAddr("192.168.1.50")) {
		t.Fatal("precondition: the permitted network should resolve")
	}

	mu.Lock()
	granted = false
	mu.Unlock()
	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if c.Allows(netip.MustParseAddr("192.168.1.50")) {
		t.Error("the revocation is not in force after the reload that followed it")
	}
}

// A rename cannot change who is admitted, so a failure to apply it must not
// raise the standing "a revocation may not have taken" warning — which nothing
// clears until an unrelated write succeeds or the daemon restarts.
func TestMetadataReloadFailureDoesNotMarkStale(t *testing.T) {
	fail := true
	c := NewController([]string{"127.0.0.0/8"}, false, func(context.Context) ([]Network, error) {
		if fail {
			return nil, context.DeadlineExceeded
		}
		return nil, nil
	})

	if err := c.ReloadMetadata(context.Background()); err == nil {
		t.Fatal("the failure was not reported to the caller")
	}
	if c.Stale() {
		t.Error("a metadata reload failure marked the ACL stale; admission is unchanged, so " +
			"that is a false alarm and a persistent one")
	}

	// The strict path still does, on the same failure.
	if err := c.Reload(context.Background()); err == nil {
		t.Fatal("the failure was not reported to the caller")
	}
	if !c.Stale() {
		t.Error("an access-relevant reload failure was not recorded")
	}

	// And any successful publish clears it, whichever path did it.
	fail = false
	if err := c.ReloadMetadata(context.Background()); err != nil {
		t.Fatalf("ReloadMetadata: %v", err)
	}
	if c.Stale() {
		t.Error("a successful metadata reload did not clear the stale flag; the snapshot in " +
			"force was still rebuilt from the current database")
	}
}
