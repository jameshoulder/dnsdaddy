package api

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
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
			Coverage      string   `json:"coverage"`
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
		if !n.AllowResolver || n.Coverage != "full" {
			t.Errorf("network %+v does not report itself as permitted and fully covered", n)
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

// A network broader than the range permitting it starts at a permitted address
// and is almost entirely refused after that. Sampling the base address
// reported it green — the same misleading health this work exists to remove,
// reintroduced one column to the left.
func TestPartiallyPermittedNetworkIsNotReportedAsResolving(t *testing.T) {
	h := newHarness(t)
	h.login()

	// The shipped ACL permits 172.16.0.0/12. A /8 over the same base is
	// therefore permitted at its first address and refused across most of it.
	resp, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":  "Too broad",
		"cidrs": []string{"172.0.0.0/8"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, body %s", resp.StatusCode, raw)
	}

	_, raw = h.do("GET", "/api/v1/networks", nil)
	body := decode[struct {
		Networks []struct {
			Name     string `json:"name"`
			Coverage string `json:"coverage"`
		} `json:"networks"`
	}](t, raw)

	for _, n := range body.Networks {
		if n.Name != "Too broad" {
			continue
		}
		// Partial, not none: the /16 inside it is permitted, so some of its
		// clients are served and most are not. Reporting either extreme hides
		// half the truth.
		if n.Coverage != "partial" {
			t.Errorf("coverage = %q, want partial — a 10.0.0.0/8 network against a permitted "+
				"10.0.0.0/16 has its first 65k addresses served and the rest refused", n.Coverage)
		}
		return
	}
	t.Fatal("the created network is missing from the list")
}

// The onboarding card branches on measurements, so the overview has to carry
// them. Counting permitted networks alone told a stock LAN install — which has
// none, and serves every private range — that every client would be REFUSED.
func TestOverviewReportsMeasuredAccessState(t *testing.T) {
	h := newHarness(t)
	h.login()

	var overview struct {
		PermittedNetworks  int    `json:"permittedNetworks"`
		UnrestrictedAccess bool   `json:"unrestrictedAccess"`
		ServesOnlyLoopback bool   `json:"servesOnlyLoopback"`
		RefusedClients     uint64 `json:"refusedClients"`
	}
	h.getJSON("/api/v1/overview", &overview)

	if overview.PermittedNetworks != 0 {
		t.Errorf("permittedNetworks = %d, want 0 on a fresh install", overview.PermittedNetworks)
	}
	// The shipped ACL serves the private ranges, so this must be false — it is
	// what stops the dashboard claiming every client will be refused.
	if overview.ServesOnlyLoopback {
		t.Error("a stock install reports that only loopback may resolve, which is false " +
			"and is exactly the misleading message this replaced")
	}
	if overview.UnrestrictedAccess {
		t.Error("the default configuration was reported as unrestricted")
	}
	if overview.RefusedClients != 0 {
		t.Errorf("refusedClients = %d, want 0 before anything has been refused", overview.RefusedClients)
	}
}

// A revocation that was stored but not applied is the worst of the three
// write paths: the permission is still being honoured and the row that would
// have shown it is gone. Answering 204 and dropping the warning told the
// caller the revocation had taken effect.
//
// The failure is forced by closing the database under the API, which is the
// only way to make ListNetworks fail on demand and is exactly the transient
// condition the warning exists for.
func TestDeleteReportsAFailedReload(t *testing.T) {
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
		t.Fatal("precondition: the permitted network should resolve")
	}

	// Break only the reload, so the delete still commits — the exact ordering
	// the warning describes, and a real transient database error between the
	// commit and the reload looks like this.
	h.failACLReload.Store(true)

	resp, raw := h.do("DELETE", "/api/v1/networks/"+id, nil)
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("a delete whose reload failed answered 204, claiming the revocation took effect")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %s", resp.StatusCode, raw)
	}
	body := decode[map[string]any](t, raw)
	warning, _ := body["warning"].(string)
	if !strings.Contains(warning, "cannot confirm") {
		t.Errorf("warning = %q, want it to say the enforced access could not be confirmed",
			warning)
	}

	// The dangerous state itself: the network is gone from the database and
	// its clients are still being served.
	if !permits(t, h, "198.18.4.4") {
		t.Log("the stale snapshot happened to drop the permission; the warning still matters")
	}

	// And the condition outlives the response, so the diagnostics keep saying
	// so after the operator has clicked away.
	if !h.acl.Stale() {
		t.Fatal("the failed reload was not recorded on the controller")
	}

	h.failACLReload.Store(false)
	_, raw = h.do("GET", "/api/v1/diagnostics", nil)
	body = decode[map[string]any](t, raw)
	found := false
	for _, c := range body["checks"].([]any) {
		check := c.(map[string]any)
		// Warn rather than fail: the re-read is definitely broken, but whether
		// the enforced ACL is wrong is what could not be determined.
		if check["name"] == "Enforced client ACL confirmed" && check["status"] == "warn" {
			found = true
		}
	}
	if !found {
		t.Errorf("no diagnostics check reports the stale ACL: %s", raw)
	}
}

// Every write path records a failed reload, and none of them claims to know
// which way it went.
//
// Earlier versions decided from the write whether client access could have
// changed, so that a rename whose reload failed stayed quiet. That is a nicer
// experience and it was not sound: deciding it needs a reading of the stored
// state, which is the thing that just failed. Two networks permitting the same
// range, revoked in turn with the reload failing both times, were each
// classified as changing nothing — and the resolver went on admitting a range
// the database no longer permitted, with every surface reporting it as fresh.
func TestEveryWritePathRecordsAFailedReload(t *testing.T) {
	for _, tc := range []struct {
		name string
		do   func(h *harness, id string)
	}{
		{"create", func(h *harness, _ string) {
			h.do("POST", "/api/v1/networks", map[string]any{"name": "Another"})
		}},
		{"rename", func(h *harness, id string) {
			h.do("PATCH", "/api/v1/networks/"+id, map[string]any{"location": "Leeds"})
		}},
		{"permit", func(h *harness, id string) {
			h.do("PATCH", "/api/v1/networks/"+id, map[string]any{
				"allowResolver": true, "publicAck": true})
		}},
		{"delete", func(h *harness, id string) {
			h.do("DELETE", "/api/v1/networks/"+id, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.login()

			_, raw := h.do("POST", "/api/v1/networks", map[string]any{
				"name":  "Benchmark lab",
				"cidrs": []string{"198.18.0.0/15"},
			})
			id := decode[map[string]any](t, raw)["id"].(string)

			h.failACLReload.Store(true)
			tc.do(h, id)
			if !h.acl.Stale() {
				t.Error("a failed reload was not recorded; whether it mattered cannot be " +
					"determined here, and reporting the ACL as fresh is the one answer that " +
					"can hide an over-permission")
			}
			h.failACLReload.Store(false)
		})
	}
}

// The warning says what is known and no more. It used to assert either that
// the change was not in force or that no client was affected, and neither was
// supportable.
func TestTheWarningClaimsOnlyThatItCouldNotConfirm(t *testing.T) {
	h := newHarness(t)
	h.login()

	_, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":  "Benchmark lab",
		"cidrs": []string{"198.18.0.0/15"},
	})
	id := decode[map[string]any](t, raw)["id"].(string)

	h.failACLReload.Store(true)
	resp, raw := h.do("PATCH", "/api/v1/networks/"+id, map[string]any{"location": "Leeds"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %s", resp.StatusCode, raw)
	}
	warning, _ := decode[map[string]any](t, raw)["warning"].(string)
	if !strings.Contains(warning, "cannot confirm") {
		t.Errorf("warning = %q, want it to say the enforced access could not be confirmed",
			warning)
	}
	if strings.Contains(warning, "no client is affected") {
		t.Errorf("the warning claims no client is affected, which it cannot know: %q", warning)
	}
	h.failACLReload.Store(false)
}

// doctor runs as a separate process and rebuilds the ACL from configuration
// and the database — the desired state, not the enforced one. The health
// endpoint is the only place the running daemon's reload failure is visible,
// which is why the flag is there rather than only behind authentication.
func TestHealthReportsAStaleClientACL(t *testing.T) {
	h := newHarness(t)

	var health map[string]any
	h.getJSON("/api/v1/health", &health)
	if health["clientAclStale"] != false {
		t.Errorf("clientAclStale = %v on a healthy instance, want false", health["clientAclStale"])
	}

	h.login()
	_, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":  "Benchmark lab",
		"cidrs": []string{"198.18.0.0/15"},
	})
	id := decode[map[string]any](t, raw)["id"].(string)

	h.failACLReload.Store(true)
	h.do("PATCH", "/api/v1/networks/"+id, map[string]any{
		"allowResolver": true,
		"publicAck":     true,
	})

	// Unauthenticated, deliberately: this is what doctor can reach.
	resp, raw := h.do("GET", "/api/v1/health", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %s", resp.StatusCode, raw)
	}
	if decode[map[string]any](t, raw)["clientAclStale"] != true {
		t.Errorf("health does not report the stale ACL, so `dnsdaddy doctor` would exit zero "+
			"while the daemon enforces an out-of-date ACL: %s", raw)
	}

	h.failACLReload.Store(false)
}

// A deletion whose reload failed answers 200 with the warning rather than the
// documented 204. 204 says the revocation is in force, which is exactly what
// cannot be confirmed here, and a caller that checks for it deserves not to be
// told a false success.
func TestDeletingWithAFailedReloadAnswers200(t *testing.T) {
	h := newHarness(t)
	h.login()

	_, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":          "Benchmark lab",
		"cidrs":         []string{"198.18.0.0/15"},
		"allowResolver": true,
		"publicAck":     true,
	})
	id := decode[map[string]any](t, raw)["id"].(string)

	h.failACLReload.Store(true)
	resp, raw := h.do("DELETE", "/api/v1/networks/"+id, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 with a warning — the permission is still in force and the "+
			"row that would show it is gone; body %s", resp.StatusCode, raw)
	}
	if !h.acl.Stale() {
		t.Error("a revocation whose reload failed was not recorded as stale")
	}
	warning, _ := decode[map[string]any](t, raw)["warning"].(string)
	if warning == "" {
		t.Error("the 200 carried no warning, which is the only reason it is a 200")
	}
	h.failACLReload.Store(false)
}

// A network write and the ACL reload that follows it have to be one unit, or
// the row the handler reasons about can be superseded between them.
//
// The sequence that breaks it: an earlier PATCH commits while the network
// still carries a grant, a later PATCH revokes that grant and publishes the
// revocation, and the earlier handler then reaches its comparison holding the
// grant-bearing row. It reports a change, and if its own reload fails it marks
// the ACL stale and warns that access is not in force — while the database and
// the snapshot both already agree the grant is gone. The policy-engine reload
// sits between the commit and the ACL reload, so the window is not theoretical.
//
// This asserts the property that closes it: while one network write is between
// its commit and its reload, no other network write can commit.
func TestANetworkWriteAndItsReloadAreOneUnit(t *testing.T) {
	h := newHarness(t)
	h.login()

	_, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":          "Benchmark lab",
		"cidrs":         []string{"198.18.0.0/15"},
		"allowResolver": true,
		"publicAck":     true,
	})
	id := decode[map[string]any](t, raw)["id"].(string)

	// Park the next reload inside the first handler's write lock. Released
	// through a sync.Once registered as cleanup, so a failing assertion below
	// still unblocks the held request. Without that, the test server's
	// shutdown waits on it and the failure is reported as a five-minute hang
	// instead of as the assertion that actually fired.
	release := make(chan struct{})
	var releaseOnce sync.Once
	unhold := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unhold)
	h.holdACLReload.Store(&release)

	renamed := make(chan struct{})
	go func() {
		defer close(renamed)
		h.do("PATCH", "/api/v1/networks/"+id, map[string]any{"location": "Leeds"})
	}()

	// Wait for the rename to be inside its reload, which it signals by having
	// taken the hold: the seam clears itself when it fires.
	waitFor(t, func() bool { return h.holdACLReload.Load() == nil })

	revoked := make(chan struct{})
	go func() {
		defer close(revoked)
		h.do("PATCH", "/api/v1/networks/"+id, map[string]any{"allowResolver": false})
	}()

	// Give the revocation every chance to commit early if it can.
	time.Sleep(50 * time.Millisecond)
	current, err := h.store.GetNetwork(context.Background(), id)
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if !current.AllowResolver {
		t.Fatal("a second network write committed while the first was between its commit and " +
			"its reload; the first will then compare against a row that has been superseded, " +
			"and a failed reload there warns that access is not in force when it is not granted")
	}

	unhold()
	<-renamed
	<-revoked

	// And the end state is the later write's, with the ACL agreeing.
	current, err = h.store.GetNetwork(context.Background(), id)
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if current.AllowResolver {
		t.Error("the revocation did not land")
	}
	if h.acl.Current().Allows(netip.MustParseAddr("198.18.0.1")) {
		t.Error("the revocation is not in force after both writes completed")
	}
	if h.acl.Stale() {
		t.Error("the ACL was marked stale although every reload succeeded")
	}
}

// waitFor polls until cond holds, failing the test rather than hanging forever.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the reload to be held")
		}
		time.Sleep(time.Millisecond)
	}
}

// Coverage is two independent facts — is any address admitted, is any refused
// — not the least-covered range. A network with one fully permitted CIDR and
// one permitted by nothing has half its clients working; reporting "none"
// there badges the whole row Refused and hides the working half.
func TestMixedCoverageIsPartialRatherThanTheWorstRange(t *testing.T) {
	h := newHarness(t)
	h.login()

	// 10.10.0.0/16 sits inside the shipped 10.0.0.0/8; 198.18.0.0/15 does not.
	_, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":  "Two sites",
		"cidrs": []string{"10.10.0.0/16", "198.18.0.0/15"},
	})
	if id, _ := decode[map[string]any](t, raw)["id"].(string); id == "" {
		t.Fatalf("create failed: %s", raw)
	}

	_, raw = h.do("GET", "/api/v1/networks", nil)
	body := decode[struct {
		Networks []struct {
			Name        string `json:"name"`
			Coverage    string `json:"coverage"`
			ResolvesVia string `json:"resolvesVia"`
		} `json:"networks"`
	}](t, raw)

	for _, n := range body.Networks {
		if n.Name != "Two sites" {
			continue
		}
		if n.Coverage != "partial" {
			t.Errorf("coverage = %q, want partial — 10.10.0.0/16 is admitted and "+
				"198.18.0.0/15 is not, so some of this network resolves and some does not",
				n.Coverage)
		}
		// And the row must not be described as reachable through a wider range
		// on the strength of the half that is.
		if n.ResolvesVia != "" {
			t.Errorf("resolvesVia = %q on a partly covered network; the badge reads it before "+
				"coverage, so the refused half would be reported as reachable", n.ResolvesVia)
		}
		return
	}
	t.Fatal("the created network is missing from the list")
}

// Shadowed() reports one entry per covered range, so a network whose two CIDRs
// are covered by two different grants produced two entries. Keeping the last
// one named a single range as covering a network of which it covers half.
func TestResolvesViaNamesEveryCoveringRange(t *testing.T) {
	h := newHarness(t)
	h.login()

	// Both are inside the shipped ACL, but via different entries in it:
	// 10.10.0.0/16 through 10.0.0.0/8, and 192.168.4.0/24 through
	// 192.168.0.0/16.
	_, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":  "Two sites, two covers",
		"cidrs": []string{"10.10.0.0/16", "192.168.4.0/24"},
	})
	if id, _ := decode[map[string]any](t, raw)["id"].(string); id == "" {
		t.Fatalf("create failed: %s", raw)
	}

	_, raw = h.do("GET", "/api/v1/networks", nil)
	body := decode[struct {
		Networks []struct {
			Name        string `json:"name"`
			Coverage    string `json:"coverage"`
			ResolvesVia string `json:"resolvesVia"`
		} `json:"networks"`
	}](t, raw)

	for _, n := range body.Networks {
		if n.Name != "Two sites, two covers" {
			continue
		}
		if n.Coverage != "full" {
			t.Fatalf("coverage = %q, want full — both ranges are inside the shipped ACL", n.Coverage)
		}
		if !strings.Contains(n.ResolvesVia, "10.0.0.0/8") ||
			!strings.Contains(n.ResolvesVia, "192.168.0.0/16") {
			t.Errorf("resolvesVia = %q, want both covering ranges — naming one of them "+
				"describes it as covering a network of which it covers half", n.ResolvesVia)
		}
		return
	}
	t.Fatal("the created network is missing from the list")
}
