package diag

import (
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
)

// find returns the first check whose Name contains sub.
func refusals(n uint64) *uint64 { return &n }

func find(t *testing.T, checks []Check, sub string) Check {
	t.Helper()
	for _, c := range checks {
		if strings.Contains(c.Name, sub) {
			return c
		}
	}
	t.Fatalf("no check matching %q in %d checks", sub, len(checks))
	return Check{}
}

// The failure the maintainer hit: a resolver that reports itself healthy while
// every client on the LAN is REFUSED, because .env narrowed the ACL to
// loopback and the Docker bridge and the dashboard network was never in it.
//
// This is the check that would have said so.
func TestClientAccessFailsWhenNetworkIsOutsideTheACL(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{
		ACL: clientacl.Compute([]string{"127.0.0.0/8", "172.16.0.0/12"}, false, nil),
		Networks: []Network{{
			ID: "n_home", Name: "Home", PolicyName: "Standard",
			Enabled: true, CIDRs: []string{"192.168.1.0/24"},
		}},
		RefusedQueries: nil,
	})

	c := find(t, checks, `Network "Home"`)
	if c.Status != StatusFail {
		t.Fatalf("status = %s, want fail — the network cannot resolve", c.Status)
	}
	if !strings.Contains(c.Summary, "REFUSED") {
		t.Errorf("summary does not say the queries are refused: %q", c.Summary)
	}
	// The operator has to be able to check our working.
	joined := strings.Join(c.Evidence, "\n")
	for _, want := range []string{"192.168.1.0/24", "127.0.0.0/8", "172.16.0.0/12", "Standard"} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence is missing %q:\n%s", want, joined)
		}
	}
	if !strings.Contains(c.Action, "does not by itself permit it to resolve") {
		t.Errorf("action does not correct the misconception that adding a network grants access: %q", c.Action)
	}
	// The remedy has to be the one the operator can actually reach: a tick-box
	// in the dashboard, not an environment variable and a container restart.
	if !strings.Contains(c.Action, "Allow this network to use DNS Daddy") {
		t.Errorf("action does not point at the dashboard permission: %q", c.Action)
	}
	if Worst(checks) != StatusFail {
		t.Error("Worst did not report the failure")
	}
}

func TestClientAccessPassesWhenNetworkIsInsideTheACL(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{
		ACL: clientacl.Compute([]string{"192.168.0.0/16"}, false, nil),
		Networks: []Network{{
			Name: "Home", PolicyName: "Standard", Enabled: true, CIDRs: []string{"192.168.1.0/24"},
		}},
		RefusedQueries: nil,
	})

	if c := find(t, checks, `Network "Home"`); c.Status != StatusPass {
		t.Fatalf("status = %s (%s), want pass", c.Status, c.Summary)
	}
	if Worst(checks) != StatusPass {
		t.Errorf("Worst = %s, want pass", Worst(checks))
	}
}

// A network half inside the ACL is the subtlest version of this bug: some
// clients work and some do not, which reads as an intermittent fault.
func TestClientAccessWarnsOnPartialCoverage(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{
		ACL: clientacl.Compute([]string{"192.168.1.0/24"}, false, nil),
		Networks: []Network{{
			Name: "Home", Enabled: true, CIDRs: []string{"192.168.0.0/16"},
		}},
		RefusedQueries: nil,
	})

	c := find(t, checks, `Network "Home"`)
	if c.Status != StatusWarn {
		t.Fatalf("status = %s, want warn — only part of the network may resolve", c.Status)
	}
	if !strings.Contains(c.Summary, "Only part") {
		t.Errorf("summary = %q", c.Summary)
	}
}

// A disabled network is not a live problem, and a catch-all network has no
// address range to compare. Neither should produce noise.
func TestClientAccessIgnoresDisabledAndCatchAllNetworks(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{
		ACL: clientacl.Compute([]string{"10.0.0.0/8"}, false, nil),
		Networks: []Network{
			{Name: "Retired", Enabled: false, CIDRs: []string{"192.168.1.0/24"}},
			{Name: "Default", Enabled: true, CIDRs: nil},
		},
		RefusedQueries: nil,
	})

	for _, c := range checks {
		if strings.Contains(c.Name, "Retired") || strings.Contains(c.Name, "Default") {
			t.Errorf("unexpected check for a %s network: %s", c.Name, c.Summary)
		}
	}
	if Worst(checks) != StatusPass {
		t.Errorf("Worst = %s, want pass", Worst(checks))
	}
}

func TestClientAccessReportsAnUnparseableEntry(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{
		ACL: clientacl.Compute([]string{"192.168.1.0/24", "192.168.2.0/33"}, false, nil),
	})

	c := find(t, checks, "Client ACL parses")
	if c.Status != StatusFail {
		t.Fatalf("status = %s, want fail", c.Status)
	}
	if !strings.Contains(c.Summary, "192.168.2.0/33") {
		t.Errorf("summary does not name the bad entry: %q", c.Summary)
	}
}

func TestClientAccessWarnsAboutAnOpenResolver(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{
		ACL: clientacl.Compute(nil, true, nil),
	})

	c := find(t, checks, "Client ACL configured")
	if c.Status != StatusWarn {
		t.Fatalf("status = %s, want warn for an open resolver", c.Status)
	}
	if !strings.Contains(c.Action, "amplification") {
		t.Errorf("action does not explain the risk: %q", c.Action)
	}
}

// The refusal counter is the hard evidence that the ACL is the problem, as
// opposed to a firewall, a port conflict or a routing fault. Before this it
// was collected and never shown to anybody.
func TestClientAccessReportsObservedRefusals(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{
		ACL:            clientacl.Compute([]string{"10.0.0.0/8"}, false, nil),
		RefusedQueries: refusals(1240),
	})

	c := find(t, checks, "Queries refused")
	if c.Status != StatusWarn {
		t.Fatalf("status = %s, want warn", c.Status)
	}
	if !strings.Contains(c.Summary, "1240") {
		t.Errorf("summary does not carry the count: %q", c.Summary)
	}

	quiet := ClientAccess(ClientAccessInput{ACL: clientacl.Compute([]string{"10.0.0.0/8"}, false, nil), RefusedQueries: refusals(0)})
	for _, c := range quiet {
		if strings.Contains(c.Name, "Queries refused") {
			t.Error("reported refusals when none have happened")
		}
	}
}

// IPv6 and IPv4 prefixes must not be compared against each other: a v6 network
// is not covered by 0.0.0.0/0 and a v4 one is not covered by ::/0.
func TestClientAccessDoesNotMixAddressFamilies(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{
		ACL:            clientacl.Compute([]string{"10.0.0.0/8"}, false, nil),
		Networks:       []Network{{Name: "v6", Enabled: true, CIDRs: []string{"fd00::/64"}}},
		RefusedQueries: nil,
	})

	if c := find(t, checks, `Network "v6"`); c.Status != StatusFail {
		t.Fatalf("status = %s, want fail — an IPv6 network is not covered by an IPv4 ACL", c.Status)
	}
}

func TestFailuresSelectsOnlyFailures(t *testing.T) {
	checks := []Check{
		{Section: "B", Status: StatusWarn},
		{Section: "A", Status: StatusFail, Name: "first"},
		{Section: "C", Status: StatusPass},
		{Section: "B", Status: StatusFail, Name: "second"},
	}
	got := Failures(checks)
	if len(got) != 2 {
		t.Fatalf("got %d failures, want 2", len(got))
	}
	if got[0].Name != "first" || got[1].Name != "second" {
		t.Errorf("failures out of section order: %v", got)
	}
}

// A caveat that qualifies a passing verdict has to live in the summary. The
// renderer only prints actions for checks that did not pass, so a caveat
// carried in Action would silently vanish from exactly the output it matters
// in.
func TestPassingChecksCarryTheirCaveatInTheSummary(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{ACL: clientacl.Compute(nil, false, nil)})

	for _, c := range checks {
		if c.Status == StatusPass && c.Action != "" {
			t.Errorf("passing check %q carries an action the renderer will not print: %q", c.Name, c.Action)
		}
	}

	c := find(t, checks, "Client ACL configured")
	if !strings.Contains(c.Summary, "loopback-only") {
		t.Errorf("summary lost the condition the verdict depends on: %q", c.Summary)
	}
}

// An empty ACL refuses nothing: Handler.clientAllowed returns true as soon as
// len(allowedClients) == 0, whatever the source address. Comparing configured
// networks against an empty prefix list therefore reports every one of them as
// REFUSED when in fact every one of them is permitted.
//
// That made the diagnostics endpoint show a false failure and `dnsdaddy doctor`
// exit non-zero on a supported configuration — a deliberate public resolver.
func TestClientAccessDoesNotReportFailuresWhenTheACLIsEmpty(t *testing.T) {
	for _, tt := range []struct {
		name   string
		public bool
	}{
		{"public resolver", true},
		// The same arithmetic applies without the opt-in: config validation
		// permits an empty ACL when the listeners are loopback-only, and there
		// too nothing is refused on its source address.
		{"loopback-only listeners", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checks := ClientAccess(ClientAccessInput{
				ACL: clientacl.Compute(nil, tt.public, nil),
				Networks: []Network{
					{Name: "Home", PolicyName: "Standard", Enabled: true, CIDRs: []string{"192.168.1.0/24"}},
					{Name: "Branch", PolicyName: "Strict", Enabled: true, CIDRs: []string{"203.0.113.0/24"}},
				},
			})

			for _, c := range checks {
				if c.Status == StatusFail {
					t.Errorf("reported a failure with no ACL configured, so nothing is refused: %s", c.Summary)
				}
			}
			if got := Worst(checks); got == StatusFail {
				t.Errorf("Worst = %s; doctor would exit non-zero on a working configuration", got)
			}
		})
	}
}

// Removing the reachability comparison must not remove it for a real ACL: the
// check that started this whole audit has to keep working.
func TestClientAccessStillReportsUnreachableNetworksWithAnACL(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{
		ACL:      clientacl.Compute([]string{"127.0.0.0/8"}, false, nil),
		Networks: []Network{{Name: "Home", Enabled: true, CIDRs: []string{"192.168.1.0/24"}}},
	})
	if Worst(checks) != StatusFail {
		t.Fatalf("Worst = %s, want fail", Worst(checks))
	}
}

// A stale ACL is a failure, not a warning: a permission the operator revoked
// may still be being honoured, and after a delete there is no network row left
// for any other check to notice it against.
func TestStaleACLIsReportedAsAFailure(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{
		ACL:   clientacl.Compute([]string{"127.0.0.0/8"}, false, nil),
		Stale: true,
	})

	c := find(t, checks, "Client ACL is in force")
	if c.Status != StatusFail {
		t.Errorf("status = %s, want fail — a revocation may not have taken effect", c.Status)
	}
	if !strings.Contains(c.Action, "revoked") {
		t.Errorf("the action does not say which direction is dangerous: %q", c.Action)
	}
	if Worst(checks) != StatusFail {
		t.Error("Worst did not report the failure, so doctor would exit zero on a stale ACL")
	}
}

func TestFreshACLIsNotReportedAsStale(t *testing.T) {
	checks := ClientAccess(ClientAccessInput{
		ACL: clientacl.Compute([]string{"127.0.0.0/8"}, false, nil),
	})
	for _, c := range checks {
		if strings.Contains(c.Name, "in force") {
			t.Errorf("a healthy ACL was reported as stale: %s", c.Summary)
		}
	}
}

// One range permitted from configuration and from a network is two things to
// go and change and one exposure. Counting it twice would make adding a
// redundant permission look like the resolver had been opened wider.
func TestPublicWarningCountsDistinctRanges(t *testing.T) {
	acl := clientacl.Compute([]string{"127.0.0.0/8", "203.0.113.42/32"}, false, []clientacl.Network{
		{ID: "n1", Name: "Branch", Enabled: true, AllowResolver: true, CIDRs: []string{"203.0.113.42/32"}},
	})
	checks := ClientAccess(ClientAccessInput{ACL: acl})

	c := find(t, checks, "Publicly routable ranges")
	if !strings.Contains(c.Summary, "1 publicly routable range") {
		t.Errorf("summary = %q, want a count of one distinct range", c.Summary)
	}
	// The evidence still names both, because closing it means changing both.
	if len(c.Evidence) != 2 {
		t.Errorf("evidence = %v, want both sources named", c.Evidence)
	}
}
