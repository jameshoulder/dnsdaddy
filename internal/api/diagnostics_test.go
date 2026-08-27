package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

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
func TestDiagnosticsPassOnAStockInstall(t *testing.T) {
	h := newHarness(t)
	h.login()

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
