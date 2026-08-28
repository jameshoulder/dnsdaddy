package api

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func permits(t *testing.T, h *harness, addr string) bool {
	t.Helper()
	return h.acl.Allows(netip.MustParseAddr(addr))
}

// The whole point, end to end: add a network in the dashboard, tick the box,
// and the resolver accepts that client — with no restart and no .env edit.
func TestCreatingAPermittedNetworkTakesEffectImmediately(t *testing.T) {
	h := newHarness(t)
	h.login()

	// 198.18.0.0/15 is the RFC 2544 benchmarking range: not private, so it is
	// outside the shipped ACL, and not somebody's real address either.
	const client = "198.18.4.4"
	if permits(t, h, client) {
		t.Fatal("precondition: the default ACL should not admit this address")
	}

	resp, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":          "Benchmark lab",
		"cidrs":         []string{"198.18.0.0/15"},
		"allowResolver": true,
		"publicAck":     true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, body %s", resp.StatusCode, raw)
	}

	if !permits(t, h, client) {
		t.Error("the resolver still refuses a network the dashboard just permitted")
	}
}

// Untick the box and the resolver stops accepting that client on the next
// query. This is the direction that matters: an ACL that takes a restart to
// tighten is not an access control.
func TestRevokingAccessThroughTheAPIRefusesImmediately(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":          "Benchmark lab",
		"cidrs":         []string{"198.18.0.0/15"},
		"allowResolver": true,
		"publicAck":     true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", resp.StatusCode, raw)
	}
	created := decode[map[string]any](t, raw)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("no id in %s", raw)
	}
	if !permits(t, h, "198.18.4.4") {
		t.Fatal("precondition: the permitted network should resolve")
	}

	resp, raw = h.do("PATCH", "/api/v1/networks/"+id, map[string]any{"allowResolver": false})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch: status %d, body %s", resp.StatusCode, raw)
	}
	if permits(t, h, "198.18.4.4") {
		t.Error("the resolver still accepts a client whose permission was just withdrawn")
	}
}

// Deleting the network revokes it too — the permission lived on the row.
func TestDeletingAPermittedNetworkRevokesAccess(t *testing.T) {
	h := newHarness(t)
	h.login()

	_, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":          "Benchmark lab",
		"cidrs":         []string{"198.18.0.0/15"},
		"allowResolver": true,
		"publicAck":     true,
	})
	id := decode[map[string]any](t, raw)["id"].(string)
	if !permits(t, h, "198.18.4.4") {
		t.Fatal("precondition")
	}

	resp, raw := h.do("DELETE", "/api/v1/networks/"+id, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status %d, body %s", resp.StatusCode, raw)
	}
	if permits(t, h, "198.18.4.4") {
		t.Error("a deleted network still permits its range")
	}
}

// A public range is refused with 409 and the offending ranges named, so a
// client can re-send the same request with the affirmation and a dashboard can
// say exactly what is being agreed to.
func TestPublicRangeIsRefusedUntilAcknowledged(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":          "VPS client",
		"cidrs":         []string{"203.0.113.25/32"},
		"allowResolver": true,
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d, want 409; body %s", resp.StatusCode, raw)
	}
	body := decode[map[string]any](t, raw)
	if body["publicAckRequired"] != true {
		t.Errorf("response does not flag the acknowledgement requirement: %s", raw)
	}
	cidrs, _ := body["publicCidrs"].([]any)
	if len(cidrs) != 1 || cidrs[0] != "203.0.113.25/32" {
		t.Errorf("publicCidrs = %v, want the offending range named", body["publicCidrs"])
	}
	if permits(t, h, "203.0.113.25") {
		t.Error("the refused range was permitted anyway")
	}

	// Re-sending with the affirmation succeeds.
	resp, raw = h.do("POST", "/api/v1/networks", map[string]any{
		"name":          "VPS client",
		"cidrs":         []string{"203.0.113.25/32"},
		"allowResolver": true,
		"publicAck":     true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("acknowledged create: status %d, body %s", resp.StatusCode, raw)
	}
	if !permits(t, h, "203.0.113.25") {
		t.Error("the acknowledged public range is not permitted")
	}
}

// An open resolver must not be one form submission away, with or without the
// acknowledgement.
func TestDefaultRouteCannotBePermittedThroughTheAPI(t *testing.T) {
	h := newHarness(t)
	h.login()

	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		t.Run(cidr, func(t *testing.T) {
			resp, raw := h.do("POST", "/api/v1/networks", map[string]any{
				"name":          "Everyone",
				"cidrs":         []string{cidr},
				"allowResolver": true,
				"publicAck":     true,
			})
			if resp.StatusCode == http.StatusCreated {
				t.Fatalf("a default route was accepted as a resolver permission: %s", raw)
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status %d, want 400; body %s", resp.StatusCode, raw)
			}
			if permits(t, h, "203.0.113.9") && !h.acl.Current().Unrestricted() {
				t.Error("the resolver was opened to the internet")
			}
		})
	}
}

// A network created without the permission gets a policy and nothing else.
// That is the distinction the product now has to make visible rather than
// leave the operator to discover from a REFUSED.
func TestNetworkWithoutPermissionGrantsNoAccess(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":  "Benchmark lab",
		"cidrs": []string{"198.18.0.0/15"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, body %s", resp.StatusCode, raw)
	}
	if permits(t, h, "198.18.4.4") {
		t.Error("adding a network permitted it to resolve without anyone asking")
	}
}

// The Networks list is what the dashboard renders, so it has to carry enough
// for the UI to explain the state without re-deriving the server's rules.
func TestNetworkListExposesAccessState(t *testing.T) {
	h := newHarness(t)
	h.login()

	if _, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":          "VPS client",
		"cidrs":         []string{"203.0.113.25/32"},
		"allowResolver": true,
		"publicAck":     true,
	}); raw == nil {
		t.Fatal("no response body")
	}

	_, raw := h.do("GET", "/api/v1/networks", nil)
	body := decode[struct {
		Networks []struct {
			Name          string   `json:"name"`
			AllowResolver bool     `json:"allowResolver"`
			CanResolve    bool     `json:"canResolve"`
			PublicCIDRs   []string `json:"publicCidrs"`
			ResolvesVia   string   `json:"resolvesVia"`
		} `json:"networks"`
		ClientAccess struct {
			Unrestricted   bool     `json:"unrestricted"`
			BootstrapCIDRs []string `json:"bootstrapCidrs"`
			EffectiveCIDRs []string `json:"effectiveCidrs"`
		} `json:"clientAccess"`
	}](t, raw)

	var found bool
	for _, n := range body.Networks {
		if n.Name != "VPS client" {
			continue
		}
		found = true
		if !n.AllowResolver || !n.CanResolve {
			t.Errorf("network %+v does not report itself as permitted", n)
		}
		if len(n.PublicCIDRs) != 1 || n.PublicCIDRs[0] != "203.0.113.25/32" {
			t.Errorf("publicCidrs = %v, want the public range marked for the UI", n.PublicCIDRs)
		}
	}
	if !found {
		t.Fatal("the created network is missing from the list")
	}
	if body.ClientAccess.Unrestricted {
		t.Error("the default configuration was reported as unrestricted")
	}
	if len(body.ClientAccess.EffectiveCIDRs) <= len(body.ClientAccess.BootstrapCIDRs) {
		t.Errorf("effective (%d) should exceed bootstrap (%d) once a network is permitted",
			len(body.ClientAccess.EffectiveCIDRs), len(body.ClientAccess.BootstrapCIDRs))
	}
}

// The seeded catch-all network has no CIDRs, so nothing about it should be
// reported as unable to resolve. A first-run dashboard covered in red is how
// an operator learns to ignore the diagnostics.
func TestDiagnosticsAreCleanOnAFreshInstall(t *testing.T) {
	h := newHarness(t)
	h.login()

	_, raw := h.do("GET", "/api/v1/diagnostics", nil)
	body := decode[struct {
		Status string `json:"status"`
		Checks []struct {
			Section string `json:"section"`
			Status  string `json:"status"`
			Summary string `json:"summary"`
		} `json:"checks"`
	}](t, raw)

	for _, c := range body.Checks {
		if c.Section == "CLIENT ACCESS" && c.Status == "fail" {
			t.Errorf("a fresh install reports a client-access failure: %s", c.Summary)
		}
	}
}

// Permitting a public range has to be reported for as long as it is in force.
// DNS Daddy cannot see a cloud firewall, so the one thing it can do is keep
// saying that it has not checked one.
func TestDiagnosticsWarnAboutPermittedPublicRanges(t *testing.T) {
	h := newHarness(t)
	h.login()

	h.do("POST", "/api/v1/networks", map[string]any{
		"name":          "VPS client",
		"cidrs":         []string{"203.0.113.25/32"},
		"allowResolver": true,
		"publicAck":     true,
	})

	_, raw := h.do("GET", "/api/v1/diagnostics", nil)
	body := decode[struct {
		Checks []struct {
			Section  string   `json:"section"`
			Status   string   `json:"status"`
			Summary  string   `json:"summary"`
			Evidence []string `json:"evidence"`
			Action   string   `json:"action"`
		} `json:"checks"`
	}](t, raw)

	for _, c := range body.Checks {
		if c.Section != "CLIENT ACCESS" || c.Status != "warn" {
			continue
		}
		for _, e := range c.Evidence {
			if e == `203.0.113.25/32 (network "VPS client")` {
				// And it must not claim to know anything about the firewall.
				if c.Action == "" {
					t.Error("the warning gives no action")
				}
				return
			}
		}
	}
	t.Errorf("no warning names the permitted public range: %s", raw)
}

// Adversarial scenario B: a public VPS permits exactly one client address.
//
// The claim being tested is narrow and is the only one DNS Daddy can make:
// from the resolver's ACL perspective, that source is eligible and its
// neighbours are not. Whether packets from it actually arrive depends on a
// provider firewall this process cannot see, and nothing here asserts anything
// about that.
func TestPublicHostPermissionAdmitsOnlyThatHost(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":          "Branch office",
		"cidrs":         []string{"203.0.113.25/32"},
		"allowResolver": true,
		"publicAck":     true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, body %s", resp.StatusCode, raw)
	}

	if !permits(t, h, "203.0.113.25") {
		t.Error("the permitted host is not admitted")
	}
	for _, neighbour := range []string{"203.0.113.24", "203.0.113.26", "203.0.113.1", "198.51.100.10"} {
		if permits(t, h, neighbour) {
			t.Errorf("%s was admitted by a /32 permission for 203.0.113.25", neighbour)
		}
	}
}

// Adversarial scenario C: the network exists, the box is unticked, and the
// operator wants to know why their clients get REFUSED. Diagnostics must name
// the network, name the remedy, and not offer a restart as the first answer.
func TestDiagnosticsExplainAnUnpermittedNetwork(t *testing.T) {
	h := newHarness(t)
	h.login()

	if _, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":  "Branch office",
		"cidrs": []string{"203.0.113.0/24"},
	}); raw == nil {
		t.Fatal("no response body")
	}

	_, raw := h.do("GET", "/api/v1/diagnostics", nil)
	body := decode[struct {
		Status string `json:"status"`
		Checks []struct {
			Section string `json:"section"`
			Status  string `json:"status"`
			Summary string `json:"summary"`
			Action  string `json:"action"`
		} `json:"checks"`
	}](t, raw)

	for _, c := range body.Checks {
		if c.Section != "CLIENT ACCESS" || c.Status != "fail" {
			continue
		}
		if !strings.Contains(c.Summary, "Branch office") {
			continue
		}
		if !strings.Contains(c.Action, "Allow this network to use DNS Daddy") {
			t.Errorf("the remedy does not name the control that fixes it: %q", c.Action)
		}
		if !strings.Contains(c.Action, "no restart") {
			t.Errorf("the remedy does not say it takes effect immediately: %q", c.Action)
		}
		return
	}
	t.Errorf("no client-access failure names the unpermitted network: %s", raw)
}
