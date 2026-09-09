package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

type fixedStats struct{ s observe.Stats }

func (f fixedStats) Stats() observe.Stats { return f.s }

func seedObservations(t *testing.T, st *store.Store, rows ...store.DNSSECObservation) {
	t.Helper()
	if err := st.InsertDNSSECObservations(context.Background(), rows); err != nil {
		t.Fatalf("InsertDNSSECObservations: %v", err)
	}
}

func obs(id, domain, upstream, status, disagreement string) store.DNSSECObservation {
	return store.DNSSECObservation{
		ID: id, Time: time.Now().UTC(), Domain: domain, QType: "A",
		Upstream: upstream, Status: status, Disagreement: disagreement,
		ReasonCode: "verified", DurationMS: 1.5,
	}
}

// TestTheObservationEndpointSaysItIsNotEnforcing.
//
// Every count this endpoint returns is only meaningful alongside the fact that
// none of it changed a DNS answer. A consumer that read `bogus: 40` without
// that context would reasonably conclude forty queries had been refused.
func TestTheObservationEndpointSaysItIsNotEnforcing(t *testing.T) {
	h := newHarness(t)
	h.login()

	var body struct {
		Mode         string `json:"mode"`
		Enforcing    bool   `json:"enforcing"`
		Experimental bool   `json:"experimental"`
	}
	h.getJSON("/api/v1/dnssec/observations", &body)

	if body.Enforcing {
		t.Error("the endpoint reports enforcing: true")
	}
	if !body.Experimental {
		t.Error("the endpoint does not mark the feature experimental")
	}
	if body.Mode != "off" {
		t.Errorf("mode = %q, want off in a default configuration", body.Mode)
	}
}

// TestTheSummaryKeepsUpstreamAndLocalApart is ADR 0002 §9.
//
// Two facts, never merged. The matrix is the evidence this milestone exists to
// produce, and it only means anything if each cell names both sides.
func TestTheSummaryKeepsUpstreamAndLocalApart(t *testing.T) {
	h := newHarness(t)
	h.login()

	seedObservations(t, h.store,
		obs("a1", "signed.example", "validated", "secure", ""),
		obs("a2", "broken.example", "validated", "bogus", observe.DisagreeLocalBogusUpstreamValidated),
		obs("a3", "plain.example", "unvalidated", "insecure", ""),
		obs("a4", "hidden.example", "unvalidated", "secure", observe.DisagreeLocalSecureUpstreamUnvalidated),
	)

	var body struct {
		Summary struct {
			Total         int64            `json:"total"`
			ByStatus      map[string]int64 `json:"byStatus"`
			Disagreements map[string]int64 `json:"disagreements"`
			Matrix        []struct {
				Upstream string `json:"upstream"`
				Local    string `json:"local"`
				Count    int64  `json:"count"`
			} `json:"matrix"`
		} `json:"summary"`
	}
	h.getJSON("/api/v1/dnssec/observations", &body)

	if body.Summary.Total != 4 {
		t.Fatalf("total = %d, want 4", body.Summary.Total)
	}
	for status, want := range map[string]int64{"secure": 2, "bogus": 1, "insecure": 1} {
		if got := body.Summary.ByStatus[status]; got != want {
			t.Errorf("byStatus[%s] = %d, want %d", status, got, want)
		}
	}
	// Statuses that did not occur are present at zero, so a dashboard has a
	// stable set of rows and "none of these happened" is distinguishable from
	// "this build does not know about that outcome".
	for _, s := range observe.Statuses() {
		if _, ok := body.Summary.ByStatus[string(s)]; !ok {
			t.Errorf("status %q is missing from byStatus", s)
		}
	}
	for _, c := range observe.DisagreementClasses() {
		if _, ok := body.Summary.Disagreements[c]; !ok {
			t.Errorf("disagreement class %q is missing", c)
		}
	}
	if got := body.Summary.Disagreements[observe.DisagreeLocalBogusUpstreamValidated]; got != 1 {
		t.Errorf("local bogus / upstream validated = %d, want 1", got)
	}

	// The matrix must name both sides in every cell.
	seen := map[string]bool{}
	for _, cell := range body.Summary.Matrix {
		if cell.Upstream == "" || cell.Local == "" {
			t.Errorf("matrix cell with a missing side: %+v", cell)
		}
		seen[cell.Upstream+"/"+cell.Local] = true
	}
	for _, want := range []string{"validated/secure", "validated/bogus", "unvalidated/insecure", "unvalidated/secure"} {
		if !seen[want] {
			t.Errorf("matrix is missing the %s cell", want)
		}
	}
}

// TestDisagreementsCanBeListedOnTheirOwn: the operator question this feature
// exists to answer is "where do we and the upstream differ", and it must not
// require reading every row.
func TestDisagreementsCanBeListedOnTheirOwn(t *testing.T) {
	h := newHarness(t)
	h.login()

	seedObservations(t, h.store,
		obs("b1", "agree.example", "validated", "secure", ""),
		obs("b2", "differ.example", "validated", "bogus", observe.DisagreeLocalBogusUpstreamValidated),
	)

	var body struct {
		Recent []store.DNSSECObservation `json:"recent"`
	}
	h.getJSON("/api/v1/dnssec/observations?disagreements=1", &body)

	if len(body.Recent) != 1 {
		t.Fatalf("listed %d observations, want 1", len(body.Recent))
	}
	if body.Recent[0].Domain != "differ.example" {
		t.Errorf("listed %q, want differ.example", body.Recent[0].Domain)
	}
}

// TestTheQueryLogGainsAnOptionalFieldAndLosesNothing is the compatibility
// promise for /api/v1/queries.
//
// Every field an existing consumer reads keeps its name and meaning; one
// optional object appears beside them. A nested rename would have been tidier
// and would have broken every client.
func TestTheQueryLogGainsAnOptionalFieldAndLosesNothing(t *testing.T) {
	h := newHarness(t)
	h.login()

	// A query row with no observation, which is the default configuration.
	if err := h.store.InsertQueryBatch(context.Background(), []store.QueryEvent{{
		Time: time.Now().UTC(), Domain: "plain.example", QType: "A",
		Action: store.ActionAllowed, DNSSEC: store.DNSSECUnvalidated,
	}}, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}

	var raw struct {
		Queries []map[string]any `json:"queries"`
	}
	h.getJSON("/api/v1/queries", &raw)
	if len(raw.Queries) != 1 {
		t.Fatalf("got %d rows, want 1", len(raw.Queries))
	}
	row := raw.Queries[0]
	for _, field := range []string{"time", "domain", "qtype", "action", "dnssec"} {
		if _, ok := row[field]; !ok {
			t.Errorf("the query row lost the %q field", field)
		}
	}
	if _, ok := row["dnssecValidation"]; ok {
		t.Error("a query with no observation carries a dnssecValidation object; absence must mean not observed")
	}
	// The upstream field is untouched and still means what it meant.
	if row["dnssec"] != store.DNSSECUnvalidated {
		t.Errorf("dnssec = %v, want %q", row["dnssec"], store.DNSSECUnvalidated)
	}
}

// TestAQueryRowCarriesItsOwnObservation checks the correlation is exact rather
// than a match on name and time.
func TestAQueryRowCarriesItsOwnObservation(t *testing.T) {
	h := newHarness(t)
	h.login()

	seedObservations(t, h.store, obs("c1", "watched.example", "unvalidated", "bogus",
		observe.DisagreeLocalBogusUpstreamUnvalidated))

	// Two rows for the same name in the same instant, only one of which was
	// observed. Matching on name and time would attach the verdict to both.
	now := time.Now().UTC()
	if err := h.store.InsertQueryBatch(context.Background(), []store.QueryEvent{
		{Time: now, Domain: "watched.example", QType: "A", Action: store.ActionAllowed,
			DNSSEC: store.DNSSECUnvalidated, DNSSECObservationID: "c1"},
		{Time: now, Domain: "watched.example", QType: "A", Action: store.ActionAllowed,
			DNSSEC: store.DNSSECUnvalidated},
	}, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}

	var body struct {
		Queries []struct {
			Domain           string                   `json:"domain"`
			DNSSEC           string                   `json:"dnssec"`
			DNSSECValidation *store.DNSSECObservation `json:"dnssecValidation"`
		} `json:"queries"`
	}
	h.getJSON("/api/v1/queries", &body)
	if len(body.Queries) != 2 {
		t.Fatalf("got %d rows, want 2", len(body.Queries))
	}

	var withObs, withoutObs int
	for _, q := range body.Queries {
		if q.DNSSECValidation == nil {
			withoutObs++
			continue
		}
		withObs++
		if q.DNSSECValidation.Status != "bogus" {
			t.Errorf("local status = %q, want bogus", q.DNSSECValidation.Status)
		}
		// Both facts present, neither overwritten by the other.
		if q.DNSSEC != store.DNSSECUnvalidated {
			t.Errorf("the upstream field was overwritten: %q", q.DNSSEC)
		}
	}
	if withObs != 1 || withoutObs != 1 {
		t.Fatalf("observation attached to %d of 2 rows; the correlation is not exact", withObs)
	}
}

// TestTheMetricsHaveClosedLabelSets is Phase 8's cardinality rule.
//
// A metric labelled with a domain, a reason string or a client address grows
// one series per name an attacker chooses to ask about. The label values here
// come from constants, and this test is what keeps them there.
func TestTheMetricsHaveClosedLabelSets(t *testing.T) {
	h := newHarness(t)
	h.api.DNSSEC = fixedStats{observe.Stats{
		Observed: 7, Dropped: 2, Panics: 0,
		ByStatus:      map[observe.Status]uint64{observe.StatusSecure: 5, observe.StatusBogus: 2},
		Disagreements: map[string]uint64{observe.DisagreeLocalBogusUpstreamValidated: 2},
	}}
	h.login()

	body := h.getMetrics()

	for _, want := range []string{
		`dnsdaddy_dnssec_local_validation_total{status="secure"} 5`,
		`dnsdaddy_dnssec_local_validation_total{status="bogus"} 2`,
		`dnsdaddy_dnssec_local_validation_total{status="timeout"} 0`,
		`dnsdaddy_dnssec_local_disagreement_total{class="local_bogus_upstream_validated"} 2`,
		`dnsdaddy_dnssec_local_dropped_total 2`,
		`dnsdaddy_dnssec_local_panics_total 0`,
	} {
		if !contains(body, want) {
			t.Errorf("/metrics does not contain %q", want)
		}
	}

	// The only labels permitted on these series are status and class.
	for _, line := range strings.Split(body, "\n") {
		if !contains(line, "dnsdaddy_dnssec_local_") || !contains(line, "{") {
			continue
		}
		label := line[strings.Index(line, "{")+1 : strings.Index(line, "=")]
		if label != "status" && label != "class" {
			t.Errorf("unexpected label %q on a DNSSEC metric: %s", label, line)
		}
	}
}

// TestMetricsAreAbsentWhenObservationIsOff.
//
// A counter that is always zero invites an alert on a feature nobody enabled.
// The absence of the series is a clearer statement than a zero.
func TestMetricsAreAbsentWhenObservationIsOff(t *testing.T) {
	h := newHarness(t)
	h.login()
	if body := h.getMetrics(); contains(body, "dnsdaddy_dnssec_local_") {
		t.Error("/metrics carries local DNSSEC series with observation off")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// getMetrics fetches /metrics as text.
func (h *harness) getMetrics() string {
	h.t.Helper()
	resp, body := h.do(http.MethodGet, "/metrics", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /metrics = %d: %s", resp.StatusCode, body)
	}
	return string(body)
}

var _ = json.Marshal
