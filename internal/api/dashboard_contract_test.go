package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// The dashboard is hand-written JavaScript reading these responses by key. A
// renamed Go struct tag does not break the build, does not break any Go test,
// and does not throw in the browser — the field simply reads `undefined` and
// the panel renders blank. That is the "UI silently not wired to the backend"
// failure, and the only thing that catches it is pinning the contract.
//
// The key lists below are the fields internal/web/static/app.js actually reads.
// If you rename one, update both together.

func requireKeys(t *testing.T, what string, obj map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := obj[k]; !ok {
			t.Errorf("%s is missing %q, which the dashboard reads", what, k)
		}
	}
}

func TestFindingsListMatchesDashboardContract(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedFinding(t, h, "c1", "dns_tunnel_suspected", "high", "10.0.0.5", "tunnel.example", time.Now())

	var body struct {
		Findings []map[string]any `json:"findings"`
	}
	h.getJSON("/api/v1/findings?detail=true", &body)

	if len(body.Findings) != 1 {
		t.Fatalf("got %d findings", len(body.Findings))
	}
	f := body.Findings[0]

	// pages.detections reads these off each row.
	requireKeys(t, "finding row", f,
		"id", "time", "eventType", "severity", "confidence", "score",
		"clientIp", "domain", "detector", "summary", "detail")

	detail, ok := f["detail"].(map[string]any)
	if !ok {
		t.Fatal("detail is not an object")
	}
	// findingDetail() reads these.
	requireKeys(t, "finding detail", detail,
		"signals", "evidence", "mitre", "falsePositives", "nextSteps")

	// signalTable() reads these off each signal.
	signals, ok := detail["signals"].([]any)
	if !ok || len(signals) == 0 {
		t.Fatal("detail.signals is empty; the signal table would render nothing")
	}
	sig, ok := signals[0].(map[string]any)
	if !ok {
		t.Fatal("signal is not an object")
	}
	requireKeys(t, "signal", sig,
		"name", "description", "value", "floor", "ceiling", "weight", "contribution")

	// mitreList() reads these.
	mitre, ok := detail["mitre"].([]any)
	if !ok || len(mitre) == 0 {
		t.Fatal("detail.mitre is empty")
	}
	tech, ok := mitre[0].(map[string]any)
	if !ok {
		t.Fatal("technique is not an object")
	}
	requireKeys(t, "mitre technique", tech, "id", "rationale")
}

func TestDetectorCatalogueMatchesDashboardContract(t *testing.T) {
	h := newHarness(t)
	h.login()

	var body map[string]any
	h.getJSON("/api/v1/detectors", &body)

	requireKeys(t, "detector catalogue", body, "enabled", "detectors")

	detectors, ok := body["detectors"].([]any)
	if !ok || len(detectors) == 0 {
		t.Fatal("catalogue has no detectors")
	}
	d, ok := detectors[0].(map[string]any)
	if !ok {
		t.Fatal("detector is not an object")
	}
	// The "what is being looked for" table reads these.
	requireKeys(t, "detector", d,
		"name", "description", "maturity", "window", "maxSeverity", "enforces")
}

func TestFindingsSummaryMatchesDashboardContract(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedFinding(t, h, "s1", "dns_tunnel_suspected", "high", "10.0.0.5", "a.example", time.Now())

	var body map[string]any
	h.getJSON("/api/v1/findings/summary?days=7", &body)

	requireKeys(t, "findings summary", body, "byType")

	rows, ok := body["byType"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatal("summary.byType is empty")
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatal("summary row is not an object")
	}
	// The severity tiles group on these.
	requireKeys(t, "summary row", row, "severity", "count")
}

// The query log gained a DNSSEC column in the dashboard. The field is
// omitempty, so a blocked query legitimately omits it — the JS must and does
// handle that, but the key has to appear when there IS a status, or the column
// is permanently blank.
func TestQueryLogCarriesDNSSECStatusWhenPresent(t *testing.T) {
	h := newHarness(t)
	h.login()

	// A row with a status, written directly so the test does not depend on an
	// upstream being reachable.
	insertQueryWithDNSSEC(t, h, "signed.example", "validated")

	var body struct {
		Queries []map[string]any `json:"queries"`
	}
	h.getJSON("/api/v1/queries?limit=20", &body)

	var found bool
	for _, q := range body.Queries {
		if q["domain"] == "signed.example" {
			found = true
			if got := q["dnssec"]; got != "validated" {
				t.Errorf("dnssec = %v, want validated", got)
			}
		}
	}
	if !found {
		t.Fatal("seeded query row not returned")
	}
}

// A finding whose stored detail is not valid JSON must not corrupt the list
// response or the NDJSON stream. This should not happen — detail is written by
// the engine — but a truncated write or a hand-edited row must degrade rather
// than take the endpoint down.
func TestMalformedFindingDetailDegradesSafely(t *testing.T) {
	h := newHarness(t)
	h.login()

	insertRawFinding(t, h, "broken", "{not json")
	seedFinding(t, h, "good", "nxdomain_burst", "medium", "10.0.0.6", "b.example", time.Now())

	// The list endpoint must still answer, omitting the bad detail.
	var body struct {
		Findings []map[string]any `json:"findings"`
	}
	h.getJSON("/api/v1/findings?detail=true", &body)
	if len(body.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(body.Findings))
	}
	for _, f := range body.Findings {
		if f["id"] == "broken" {
			if _, ok := f["detail"]; ok {
				t.Error("invalid detail was returned rather than omitted")
			}
		}
	}

	// The NDJSON export must skip it rather than emit an unparseable line,
	// which would break a consumer reading line by line.
	resp, raw := h.do(http.MethodGet, "/api/v1/findings/export", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export status %d", resp.StatusCode)
	}
	for i, line := range splitLines(string(raw)) {
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Errorf("export line %d is not valid JSON: %v", i+1, err)
		}
	}
}

// pages.networks renders the access column, the public-range marker and the
// "resolves via a wider range" note straight off these keys. A rename here is
// the silent-blank failure this file exists to catch, and on this page a blank
// access column would read as "not permitted" — a wrong answer rather than a
// missing one.
func TestNetworkListMatchesDashboardContract(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":          "Branch office",
		"cidrs":         []string{"203.0.113.25/32"},
		"allowResolver": true,
		"publicAck":     true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", resp.StatusCode, raw)
	}

	var body struct {
		Networks     []map[string]any `json:"networks"`
		ClientAccess map[string]any   `json:"clientAccess"`
	}
	h.getJSON("/api/v1/networks", &body)

	if len(body.Networks) == 0 {
		t.Fatal("no networks returned")
	}
	var row map[string]any
	for _, n := range body.Networks {
		if n["name"] == "Branch office" {
			row = n
		}
	}
	if row == nil {
		t.Fatal("the created network is missing from the list")
	}

	requireKeys(t, "network row", row,
		"id", "name", "location", "policyId", "cidrs", "enabled",
		"queries24h", "blocked24h", "status",
		"allowResolver", "publicCidrs", "canResolve")

	// clientAccessSummary() reads these.
	requireKeys(t, "clientAccess", body.ClientAccess,
		"unrestricted", "allowPublicResolver", "bootstrapCidrs", "effectiveCidrs")
}

// The first-run card branches on these to decide between "nothing is permitted
// yet, here are the steps" and "point a device at it and test". Getting that
// branch wrong hands somebody a command that cannot work.
func TestOverviewMatchesOnboardingContract(t *testing.T) {
	h := newHarness(t)
	h.login()

	var overview map[string]any
	h.getJSON("/api/v1/overview", &overview)

	requireKeys(t, "overview", overview,
		"hasSeenClients", "clientAttribution", "permittedNetworks", "unrestrictedAccess",
		// The two the card actually branches on. Both are measurements; the
		// branch it used to make was a guess, and it was wrong on the most
		// common install there is.
		"servesOnlyLoopback", "refusedClients")
}

// resolvesVia is omitted when empty, so it cannot be asserted on a plain row —
// but the dashboard prints it verbatim when a network is reachable without its
// own permission, and that state has to produce it.
func TestShadowedNetworkReportsResolvesVia(t *testing.T) {
	h := newHarness(t)
	h.login()

	// 192.168.4.0/24 sits inside the shipped 192.168.0.0/16, so this network
	// resolves without a permission of its own.
	resp, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":  "Guest VLAN",
		"cidrs": []string{"192.168.4.0/24"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", resp.StatusCode, raw)
	}

	var body struct {
		Networks []map[string]any `json:"networks"`
	}
	h.getJSON("/api/v1/networks", &body)

	for _, n := range body.Networks {
		if n["name"] != "Guest VLAN" {
			continue
		}
		if n["allowResolver"] != false {
			t.Errorf("allowResolver = %v, want false", n["allowResolver"])
		}
		if n["canResolve"] != true {
			t.Errorf("canResolve = %v, want true — it is inside a permitted range", n["canResolve"])
		}
		via, _ := n["resolvesVia"].(string)
		if via == "" {
			t.Error("resolvesVia is empty; the dashboard cannot say why this network resolves")
		}
		return
	}
	t.Fatal("the created network is missing from the list")
}
