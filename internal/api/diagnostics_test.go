package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/diag"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func (h *harness) diagnostics(t *testing.T) DiagnosticsResponse {
	t.Helper()
	resp, raw := h.do("GET", "/api/v1/diagnostics", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/diagnostics = %d: %s", resp.StatusCode, raw)
	}
	var got DiagnosticsResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

func (h *harness) overview(t *testing.T) Overview {
	t.Helper()
	resp, raw := h.do("GET", "/api/v1/overview", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/overview = %d: %s", resp.StatusCode, raw)
	}
	var got Overview
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// The diagnostics quote configured CIDRs and network names, which is what
// makes them useful and why they must not be readable without a session.
func TestDiagnosticsRequireAuthentication(t *testing.T) {
	h := newHarness(t)

	resp, _ := h.do("GET", "/api/v1/diagnostics", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an unauthenticated caller", resp.StatusCode)
	}
}

// A stock install serves the private ranges, so a network inside them is
// reachable and the endpoint should say so without inventing a problem.
// A stock install is a fresh database and the shipped configuration. Nothing
// about it is a misconfiguration, so nothing in it may be reported as one —
// the whole point of this check is that the product does not greet a working
// deployment with a page of warnings.
//
// "Stock" no longer includes an unpermitted network. Since the Default row
// became a real ad-hoc access switch, seeded off, a network nobody permitted
// genuinely is refused; the case below pins that it is reported, with advice
// naming both ways out.
func TestDiagnosticsPassOnAStockInstall(t *testing.T) {
	h := newHarness(t)
	h.login()

	got := h.diagnostics(t)
	if got.Status != diag.StatusPass {
		t.Fatalf("status = %s, want pass; checks: %+v", got.Status, got.Checks)
	}
}

// The same install with ad-hoc access turned on and a network added: still
// nothing wrong, because the configured pool covers it.
func TestDiagnosticsPassWithAdHocAccessAndANetwork(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.enableAdHocAccess(t)

	if _, err := h.store.CreateNetwork(context.Background(), store.NetworkInput{
		Name: strPtr("Home"), CIDRs: &[]string{"192.168.1.0/24"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	got := h.diagnostics(t)
	if got.Status != diag.StatusPass {
		t.Fatalf("status = %s, want pass; checks: %+v", got.Status, got.Checks)
	}
}

// A fresh install refuses unmatched clients, so a network the operator added
// but never permitted really is being refused. Reporting that, with advice
// naming both remedies, is the product working — silently refusing the
// clients and passing the diagnostic would not be.
func TestDiagnosticsReportAnUnpermittedNetworkWhileAdHocAccessIsOff(t *testing.T) {
	h := newHarness(t)
	h.login()

	if _, err := h.store.CreateNetwork(context.Background(), store.NetworkInput{
		Name: strPtr("Home"), CIDRs: &[]string{"192.168.1.0/24"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	got := h.diagnostics(t)
	if got.Status != diag.StatusFail {
		t.Fatalf("status = %s, want fail: this network's clients are REFUSED", got.Status)
	}

	var found bool
	for _, c := range got.Checks {
		if c.Name != `Network "Home" can resolve` {
			continue
		}
		found = true
		if !strings.Contains(c.Action, "Allow this network to use DNS Daddy") {
			t.Errorf("the advice does not mention permitting the network: %q", c.Action)
		}
		if !strings.Contains(c.Action, "ad-hoc access") {
			t.Errorf("the advice does not mention ad-hoc access, the other way out: %q", c.Action)
		}
	}
	if !found {
		t.Fatalf("no reachability check named the refused network; checks: %+v", got.Checks)
	}
}

// An operator whose range is listed in dns.allowed_client_cidrs and whose
// clients are still refused must not be sent to edit that file. The evidence
// has to distinguish "eligible" from "in force".
func TestTheACLSummarySaysWhenAdHocAccessIsWithholdingThePool(t *testing.T) {
	h := newHarness(t)
	h.login()

	got := h.diagnostics(t)
	for _, c := range got.Checks {
		if c.Name != "Client ACL configured" {
			continue
		}
		joined := strings.Join(c.Evidence, " | ")
		if !strings.Contains(joined, "ad-hoc access is off") {
			t.Fatalf("the ACL summary does not say the pool is being withheld: %q", joined)
		}
		return
	}
	t.Fatal("no client ACL summary check was produced")
}

// The reported failure: a network exists in the dashboard but its addresses
// are not permitted to resolve. Here it is a public range on a stock install,
// which is the VPS shape of the same mistake.
func TestDiagnosticsReportAnUnreachableNetwork(t *testing.T) {
	h := newHarness(t)
	h.login()

	if _, err := h.store.CreateNetwork(context.Background(), store.NetworkInput{
		Name: strPtr("Branch office"), CIDRs: &[]string{"203.0.113.0/24"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	got := h.diagnostics(t)
	if got.Status != diag.StatusFail {
		t.Fatalf("status = %s, want fail; checks: %+v", got.Status, got.Checks)
	}

	var found bool
	for _, c := range got.Checks {
		if strings.Contains(c.Name, "Branch office") && c.Status == diag.StatusFail {
			found = true
			if !strings.Contains(c.Summary, "REFUSED") {
				t.Errorf("summary does not say queries are refused: %q", c.Summary)
			}
			if c.Action == "" {
				t.Error("a failing check gave the operator nothing to do")
			}
		}
	}
	if !found {
		t.Errorf("no failing check named the unreachable network; got %+v", got.Checks)
	}
}

// The refusal counter was collected and never shown anywhere. It is the
// evidence that distinguishes an ACL problem from a firewall or routing one.
func TestMetricsExposeClientRefusals(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("GET", "/metrics", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics = %d", resp.StatusCode)
	}
	if !strings.Contains(string(raw), "dnsdaddy_client_refused_total") {
		t.Error("/metrics does not export dnsdaddy_client_refused_total, so an operator " +
			"cannot see that clients are being turned away on their source address")
	}
}

func strPtr(s string) *string { return &s }

// Onboarding answers "has anything on the network ever used this?", not "has
// anything used it lately". A resolver whose network went quiet for a day — a
// holiday, a powered-down lab — must not start telling its operator that no
// device has ever used it: that is false, and indistinguishable from a fresh
// install.
//
// The upgrade case is the one that first shipped broken. On an upgrade the
// latch does not exist yet, so it has to be seeded from retained history; an
// earlier version seeded it from a 24-hour lookback and therefore re-ran
// onboarding on an established-but-quiet resolver whose evidence was sitting
// in query_log the whole time.
func TestOnboardingDoesNotResetAfterAQuietDay(t *testing.T) {
	h := newHarness(t)
	h.login()
	ctx := context.Background()

	if h.overview(t).HasSeenClients {
		t.Fatal("a fresh install reported that a client had already been seen")
	}

	// An established resolver, upgrading: a real device queried two days ago,
	// nothing since, and no latch has ever been written.
	if err := h.store.InsertQueryBatch(ctx, []store.QueryEvent{
		{Time: time.Now().UTC().Add(-48 * time.Hour), ClientIP: "192.168.1.20",
			Domain: "example.com", QType: "A", Action: store.ActionAllowed},
	}, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}

	if !h.overview(t).HasSeenClients {
		t.Fatal("an upgrade with a two-day-old client in retained history re-ran onboarding; " +
			"the latch must be seeded from history, not from a recent-activity window")
	}

	// Now drop every row, as retention eventually would. The latch must hold
	// on its own once the evidence is gone.
	if _, err := h.store.DB().ExecContext(ctx, "DELETE FROM query_log"); err != nil {
		t.Fatalf("clear query_log: %v", err)
	}
	if !h.overview(t).HasSeenClients {
		t.Error("onboarding reappeared once the query log was pruned; it claims no device has EVER used this resolver")
	}
}

// TestMetricsExposeRateLimiting. The rate-limit series are emitted whether or
// not the limiter is on, at zero when it is off, so that an alert built on
// "queries are being refused for rate" does not silently stop existing the day
// somebody disables the feature — which is precisely the day it matters.
func TestMetricsExposeRateLimiting(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("GET", "/metrics", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics = %d", resp.StatusCode)
	}
	body := string(raw)
	for _, series := range []string{
		"dnsdaddy_client_ratelimited_total",
		"dnsdaddy_ratelimit_enabled",
		"dnsdaddy_ratelimit_clients_tracked",
		"dnsdaddy_ratelimit_clients_capacity",
		"dnsdaddy_ratelimit_clients_evicted_total",
	} {
		if !strings.Contains(body, series) {
			t.Errorf("/metrics does not export %s", series)
		}
	}
}

// TestRateLimitMetricsCarryNoClientLabel. The refusal path deliberately writes
// no query-log row so that a client sending too fast cannot fill the disk. A
// label naming the client would put that cardinality straight back, in the
// monitoring system instead of the database.
func TestRateLimitMetricsCarryNoClientLabel(t *testing.T) {
	h := newHarness(t)
	h.login()

	_, raw := h.do("GET", "/metrics", nil)
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "dnsdaddy_client_ratelimited_total") &&
			!strings.HasPrefix(line, "dnsdaddy_ratelimit_") {
			continue
		}
		if strings.Contains(line, "{") {
			t.Errorf("a rate-limit series carries labels: %q", line)
		}
	}
}
