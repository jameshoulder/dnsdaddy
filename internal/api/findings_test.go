package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// seedFinding writes a finding straight to the store so the endpoints can be
// tested without waiting for a detector's evaluation window.
func seedFinding(t *testing.T, h *harness, id, eventType, severity, clientIP, domain string, at time.Time) {
	t.Helper()

	detail := detect.Finding{
		SchemaVersion: detect.SchemaVersion,
		ID:            id,
		Time:          at,
		EventType:     eventType,
		Severity:      detect.Severity(severity),
		Confidence:    0.81,
		Score:         0.77,
		Client:        detect.Client{IP: clientIP},
		Domain:        domain,
		Title:         "Test finding",
		Summary:       "A seeded finding",
		Detector:      "dns_tunnel",
		Maturity:      detect.MaturityExperimental,
		MITRE:         []detect.Technique{{ID: "T1071.004", Rationale: "test"}},
		Evidence:      map[string]any{"unique_subdomains": 187},
		// Shaped like a real finding, signals included. A fixture missing the
		// fields the dashboard reads would let a contract regression pass.
		Signals: []detect.Signal{{
			Name:         "unique_subdomains",
			Description:  "Distinct names seen below this registered domain.",
			Value:        187,
			Floor:        20,
			Ceiling:      200,
			Normalised:   0.93,
			Weight:       0.28,
			Contribution: 0.26,
		}},
		FalsePositives: []string{"Reputation lookups look like this."},
		NextSteps:      []string{"Identify the parent domain's owner."},
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err := h.store.InsertFindings(context.Background(), []store.Finding{{
		ID:         id,
		Time:       at,
		EventType:  eventType,
		Severity:   severity,
		Confidence: 0.81,
		Score:      0.77,
		ClientIP:   clientIP,
		Domain:     domain,
		Detector:   "dns_tunnel",
		Title:      "Test finding",
		Summary:    "A seeded finding",
		Detail:     string(raw),
	}}); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}
}

func TestFindingsRequireAuthentication(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/api/v1/findings",
		"/api/v1/findings/summary",
		"/api/v1/findings/export",
		"/api/v1/detectors",
	} {
		resp, _ := h.do(http.MethodGet, path, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s returned %d unauthenticated, want 401", path, resp.StatusCode)
		}
	}
}

func TestListAndFilterFindings(t *testing.T) {
	h := newHarness(t)
	h.login()

	now := time.Now()
	seedFinding(t, h, "f1", "dns_tunnel_suspected", "high", "10.0.0.5", "tunnel.example", now)
	seedFinding(t, h, "f2", "nxdomain_burst", "medium", "10.0.0.6", "", now.Add(-time.Minute))
	seedFinding(t, h, "f3", "dns_tunnel_suspected", "low", "10.0.0.7", "other.example", now.Add(-2*time.Minute))

	t.Run("all", func(t *testing.T) {
		var body struct {
			Findings    []findingResponse `json:"findings"`
			Count       int               `json:"count"`
			Enforcement string            `json:"enforcement"`
		}
		h.getJSON("/api/v1/findings", &body)

		if body.Count != 3 {
			t.Fatalf("count = %d, want 3", body.Count)
		}
		// Newest first.
		if body.Findings[0].ID != "f1" {
			t.Errorf("first finding = %q, want f1", body.Findings[0].ID)
		}
		// The API restates on every response that findings do not enforce.
		if body.Enforcement != "none" {
			t.Errorf("enforcement = %q, want none", body.Enforcement)
		}
		// Detail is opt-in.
		if body.Findings[0].Detail != nil {
			t.Error("detail was included without being asked for")
		}
	})

	t.Run("by severity", func(t *testing.T) {
		var body struct {
			Findings []findingResponse `json:"findings"`
		}
		h.getJSON("/api/v1/findings?severity=high", &body)
		if len(body.Findings) != 1 || body.Findings[0].ID != "f1" {
			t.Errorf("severity filter returned %+v", body.Findings)
		}
	})

	t.Run("by event type", func(t *testing.T) {
		var body struct {
			Findings []findingResponse `json:"findings"`
		}
		h.getJSON("/api/v1/findings?type=dns_tunnel_suspected", &body)
		if len(body.Findings) != 2 {
			t.Errorf("type filter returned %d findings, want 2", len(body.Findings))
		}
	})

	t.Run("by client", func(t *testing.T) {
		var body struct {
			Findings []findingResponse `json:"findings"`
		}
		h.getJSON("/api/v1/findings?client=10.0.0.6", &body)
		if len(body.Findings) != 1 || body.Findings[0].ID != "f2" {
			t.Errorf("client filter returned %+v", body.Findings)
		}
	})

	t.Run("with detail", func(t *testing.T) {
		var body struct {
			Findings []findingResponse `json:"findings"`
		}
		h.getJSON("/api/v1/findings?detail=true&severity=high", &body)
		if len(body.Findings) != 1 {
			t.Fatalf("got %d findings", len(body.Findings))
		}
		if body.Findings[0].Detail == nil {
			t.Fatal("detail was requested but not returned")
		}
		var f detect.Finding
		if err := json.Unmarshal(body.Findings[0].Detail, &f); err != nil {
			t.Fatalf("detail is not a valid finding document: %v", err)
		}
		if f.SchemaVersion != detect.SchemaVersion {
			t.Errorf("schema version = %q", f.SchemaVersion)
		}
	})

	t.Run("invalid severity is rejected", func(t *testing.T) {
		resp, _ := h.do(http.MethodGet, "/api/v1/findings?severity=catastrophic", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})
}

func TestGetFinding(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedFinding(t, h, "abc", "dns_tunnel_suspected", "high", "10.0.0.5", "tunnel.example", time.Now())

	var body findingResponse
	h.getJSON("/api/v1/findings/abc", &body)
	if body.ID != "abc" {
		t.Errorf("id = %q", body.ID)
	}
	if body.Detail == nil {
		t.Error("single-finding responses must always carry the full detail")
	}

	resp, _ := h.do(http.MethodGet, "/api/v1/findings/does-not-exist", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing finding returned %d, want 404", resp.StatusCode)
	}
}

// The NDJSON export is the SIEM integration path, so its format is asserted
// precisely: one complete finding document per line, oldest first.
func TestExportFindingsNDJSON(t *testing.T) {
	h := newHarness(t)
	h.login()

	now := time.Now()
	seedFinding(t, h, "e1", "dns_tunnel_suspected", "high", "10.0.0.5", "a.example", now.Add(-2*time.Minute))
	seedFinding(t, h, "e2", "nxdomain_burst", "medium", "10.0.0.6", "b.example", now.Add(-time.Minute))
	seedFinding(t, h, "e3", "dns_beaconing_suspected", "low", "10.0.0.7", "c.example", now)

	resp, body := h.do(http.MethodGet, "/api/v1/findings/export", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-ndjson") {
		t.Errorf("content type = %q, want application/x-ndjson", ct)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("export is missing the nosniff header")
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}

	var ids []string
	for i, line := range lines {
		var f detect.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("line %d is not a valid finding: %v", i+1, err)
		}
		ids = append(ids, f.ID)
	}
	// Oldest first, so a consumer appending to its own store keeps time order.
	if ids[0] != "e1" || ids[2] != "e3" {
		t.Errorf("export order = %v, want oldest first (e1, e2, e3)", ids)
	}
}

func TestFindingsSummary(t *testing.T) {
	h := newHarness(t)
	h.login()

	now := time.Now()
	seedFinding(t, h, "s1", "dns_tunnel_suspected", "high", "10.0.0.5", "a.example", now)
	seedFinding(t, h, "s2", "dns_tunnel_suspected", "high", "10.0.0.6", "b.example", now)
	seedFinding(t, h, "s3", "nxdomain_burst", "medium", "10.0.0.7", "", now)

	var body struct {
		Total   int64                  `json:"total"`
		ByType  []store.FindingSummary `json:"byType"`
		Enabled bool                   `json:"enabled"`
	}
	h.getJSON("/api/v1/findings/summary", &body)

	if body.Total != 3 {
		t.Errorf("total = %d, want 3", body.Total)
	}
	if len(body.ByType) != 2 {
		t.Errorf("byType has %d groups, want 2", len(body.ByType))
	}
	if !body.Enabled {
		t.Error("summary reports detection disabled but the harness wires an engine")
	}
}

// The catalogue is how the software states its own capability. It must come
// from the running detectors, and it must not overstate them.
func TestDetectorCatalogue(t *testing.T) {
	h := newHarness(t)
	h.login()

	var body struct {
		Enabled       bool                  `json:"enabled"`
		Enforcement   string                `json:"enforcement"`
		SchemaVersion string                `json:"schemaVersion"`
		Detectors     []detect.DetectorInfo `json:"detectors"`
	}
	h.getJSON("/api/v1/detectors", &body)

	if !body.Enabled {
		t.Fatal("catalogue reports detection disabled")
	}
	if body.Enforcement != "none" {
		t.Errorf("enforcement = %q, want none", body.Enforcement)
	}
	if body.SchemaVersion != detect.SchemaVersion {
		t.Errorf("schema version = %q", body.SchemaVersion)
	}
	if len(body.Detectors) == 0 {
		t.Fatal("catalogue is empty")
	}
	for _, d := range body.Detectors {
		if d.Maturity == "" {
			t.Errorf("detector %q publishes no maturity", d.Name)
		}
		if d.Enforces {
			t.Errorf("detector %q claims to enforce policy", d.Name)
		}
		if len(d.FalsePositives) == 0 {
			t.Errorf("detector %q documents no false positives", d.Name)
		}
	}
}

// Findings carry client IPs and the domains those clients looked up. That is
// browsing history and must not be reachable without authentication, which the
// auth test above covers — this one checks the metrics surface does not leak
// it either.
func TestMetricsExposeCountsNotContent(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedFinding(t, h, "m1", "dns_tunnel_suspected", "high", "10.0.0.5", "secret-domain.example", time.Now())

	resp, body := h.do(http.MethodGet, "/metrics", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	text := string(body)
	if !strings.Contains(text, "dnsdaddy_detection_observations_total") {
		t.Error("detection metrics are missing")
	}
	if strings.Contains(text, "secret-domain.example") {
		t.Error("a domain name from a finding leaked into /metrics")
	}
	if strings.Contains(text, "10.0.0.5") {
		t.Error("a client IP from a finding leaked into /metrics")
	}
}

// getJSON fetches an authenticated endpoint and decodes it, failing the test
// on any non-200.
func (h *harness) getJSON(path string, dst any) {
	h.t.Helper()
	resp, body := h.do(http.MethodGet, path, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		h.t.Fatalf("decode %s: %v (body: %s)", path, err, body)
	}
}

// insertQueryWithDNSSEC writes a query-log row directly, so DNSSEC surfacing
// can be tested without depending on a reachable upstream.
func insertQueryWithDNSSEC(t *testing.T, h *harness, domain, status string) {
	t.Helper()
	if err := h.store.InsertQueryBatch(context.Background(), []store.QueryEvent{{
		Time:   time.Now(),
		Domain: domain,
		QType:  "A",
		Action: store.ActionAllowed,
		Reason: "Resolved",
		DNSSEC: status,
	}}, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}
}

// insertRawFinding stores a finding with an arbitrary detail blob, so the
// malformed-detail path can be exercised.
func insertRawFinding(t *testing.T, h *harness, id, detail string) {
	t.Helper()
	if err := h.store.InsertFindings(context.Background(), []store.Finding{{
		ID: id, Time: time.Now(), EventType: "dns_tunnel_suspected",
		Severity: "high", Detail: detail,
	}}); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}
}

// splitLines splits an NDJSON body into non-empty lines.
func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
