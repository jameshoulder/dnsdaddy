package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// The investigation service. The tests below pin the properties the brief
// requires of it: it reads, it never writes, its sections stay apart, a
// historical decision is never re-rendered from today's policy, and the
// preview never guesses "allowed" for a name an external provider would be
// asked about.

func (h *harness) investigate(t *testing.T, domain string, params ...string) domainInvestigation {
	t.Helper()
	path := "/api/v1/investigate/domain/" + url.PathEscape(domain)
	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}
	var out domainInvestigation
	h.getJSON(path, &out)
	return out
}

func (h *harness) investigateClient(t *testing.T, ip string, params ...string) clientInvestigation {
	t.Helper()
	path := "/api/v1/investigate/client/" + url.PathEscape(ip)
	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}
	var out clientInvestigation
	h.getJSON(path, &out)
	return out
}

func (h *harness) countRows(t *testing.T, table string) int64 {
	t.Helper()
	var n int64
	if err := h.store.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestInvestigationRequiresAuthenticationAndValidInput(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/api/v1/investigate/domain/evil.com",
		"/api/v1/investigate/client/10.0.0.5",
	} {
		resp, _ := h.do(http.MethodGet, path, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s unauthenticated = %d, want 401", path, resp.StatusCode)
		}
	}
	resp, _ := h.do(http.MethodPost, "/api/v1/investigate/domain/evil.com/enrich", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("enrich unauthenticated = %d, want 401", resp.StatusCode)
	}

	h.login()
	for _, bad := range []string{"a..b", "not%20a%20domain", strings.Repeat("a", 70) + ".example"} {
		resp, raw := h.do(http.MethodGet, "/api/v1/investigate/domain/"+bad, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("domain %q = %d, want 400: %s", bad, resp.StatusCode, raw)
		}
	}
	resp, _ = h.do(http.MethodGet, "/api/v1/investigate/domain/evil.com?client=not-an-ip", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad client param = %d, want 400", resp.StatusCode)
	}
	resp, _ = h.do(http.MethodGet, "/api/v1/investigate/client/laptop-7", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("client path that is not an address = %d, want 400", resp.StatusCode)
	}
}

func TestInvestigationNormalisesTheNameToTheWireForm(t *testing.T) {
	h := newHarness(t)
	h.login()

	out := h.investigate(t, "Bücher.Example.")
	if out.Subject.Domain != "xn--bcher-kva.example" {
		t.Errorf("normalised domain = %q, want the A-label form", out.Subject.Domain)
	}
	if out.Subject.Input != "Bücher.Example." {
		t.Errorf("input = %q, want the typed form kept for display", out.Subject.Input)
	}
	// The mapped client form lands where the plain one does.
	out = h.investigate(t, "evil.com", "client=::ffff:10.0.0.5")
	if out.Subject.Client != "10.0.0.5" {
		t.Errorf("client = %q, want the unmapped address", out.Subject.Client)
	}
}

func TestInvestigationReadsRecordedActivityForTheExactName(t *testing.T) {
	h := newHarness(t)
	h.login()
	now := time.Now().UTC()

	ev := func(ago time.Duration, ip, domain, action, cat string) store.QueryEvent {
		return store.QueryEvent{
			Time: now.Add(-ago), ClientIP: ip, NetworkID: "n_default", Domain: domain,
			QType: "A", Action: action, Category: cat, ElapsedMS: 3,
		}
	}
	h.insertQueries(t, true,
		ev(5*time.Minute, "10.0.0.1", "evil.com", store.ActionBlocked, "malware"),
		ev(4*time.Minute, "10.0.0.2", "evil.com", store.ActionBlocked, "malware"),
		ev(3*time.Minute, "10.0.0.2", "notevil.com", store.ActionAllowed, ""),
		ev(2*time.Minute, "10.0.0.2", "www.evil.com", store.ActionAllowed, ""),
		ev(30*24*time.Hour, "10.0.0.3", "evil.com", store.ActionBlocked, "malware"),
	)

	out := h.investigate(t, "evil.com", "hours=24")
	act := out.Activity
	if !act.Available || act.Source != "query_log" {
		t.Fatalf("activity = %+v, want available from the query log", act)
	}
	if act.Summary.Queries != 2 || act.Summary.Blocked != 2 {
		t.Errorf("summary = %+v, want exactly the 2 in-window rows for evil.com", act.Summary)
	}
	if len(act.Clients) != 2 {
		t.Errorf("clients = %+v, want 2", act.Clients)
	}
	if len(act.Recent) != 2 {
		t.Errorf("recent = %d rows, want 2", len(act.Recent))
	}
	for _, r := range act.Recent {
		if r.Domain != "evil.com" {
			t.Errorf("a row for %q appeared under evil.com; the name match must be exact", r.Domain)
		}
	}
	if out.Window.Hours != 24 || out.Window.RetentionDays == 0 || !out.Window.QueryLog {
		t.Errorf("window = %+v", out.Window)
	}

	// Narrowed to one client.
	out = h.investigate(t, "evil.com", "hours=24", "client=10.0.0.1")
	if out.Activity.Summary.Queries != 1 || len(out.Activity.Recent) != 1 {
		t.Errorf("client-narrowed activity = %+v", out.Activity.Summary)
	}
}

func TestInvestigationKeepsHistoryApartFromTheCurrentPolicy(t *testing.T) {
	// The scenario the whole view exists for: a block was recorded, and
	// then the operator allow-listed the name. The stored decision must
	// still say blocked, with the explanation written at the time; the
	// preview must say the current configuration would allow it; and the
	// two must be presented as different things.
	h := newHarness(t)
	h.login()
	r := enableDecisions(t, h)
	ctx := context.Background()

	r.Record(blockEvent("evil.com"))
	waitForDecisions(t, r, 1, h)

	before := h.investigate(t, "evil.com")
	if len(before.Decisions.Items) != 1 || before.Decisions.Items[0].Action != store.ActionBlocked {
		t.Fatalf("decisions = %+v, want the recorded block", before.Decisions.Items)
	}
	if before.Preview.Decision.Outcome != "blocked" || before.Preview.Decision.Rule != "category" {
		t.Fatalf("preview before the change = %+v, want blocked by category", before.Preview.Decision)
	}
	if !before.Preview.ReadOnly || !strings.Contains(before.Preview.Note, "not what happened") {
		t.Errorf("the preview is not labelled as a preview: %+v", before.Preview)
	}

	if _, err := h.store.UpdatePolicy(ctx, "p_standard", store.PolicyInput{AllowDomains: &[]string{"evil.com"}}); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if err := h.api.Engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	after := h.investigate(t, "evil.com")
	if after.Preview.Decision.Outcome != "allowed" || after.Preview.Decision.Rule != "allow_list" {
		t.Errorf("preview after allow-listing = %+v, want allowed by the allow-list", after.Preview.Decision)
	}
	// History is unchanged: same decision, same stored explanation.
	if len(after.Decisions.Items) != 1 || after.Decisions.Items[0].Explanation != before.Decisions.Items[0].Explanation {
		t.Errorf("the recorded decision changed with the policy: %+v", after.Decisions.Items)
	}
	if after.Decisions.Items[0].Action != store.ActionBlocked {
		t.Error("the historical decision was re-rendered from the current policy")
	}
	// The per-policy comparison shows the difference without changing anything.
	var sawStandard, sawStrict bool
	for _, p := range after.Preview.ByPolicy {
		switch p.PolicyID {
		case "p_standard":
			sawStandard = p.Decision.Outcome == "allowed"
		case "p_strict":
			sawStrict = p.Decision.Outcome == "blocked"
		}
	}
	if !sawStandard || !sawStrict {
		t.Errorf("byPolicy = %+v, want standard allowed and strict blocked", after.Preview.ByPolicy)
	}
}

func TestInvestigationWritesNothing(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableDecisions(t, h)

	tables := []string{"query_log", "decisions", "evidence", "stats_hourly", "client_hourly", "intel_verdicts", "findings"}
	before := map[string]int64{}
	for _, tbl := range tables {
		before[tbl] = h.countRows(t, tbl)
	}
	cacheBefore, _, _ := h.api.Resolver.Cache().Stats()

	h.investigate(t, "evil.com", "client=10.0.0.5")
	h.investigate(t, "unknown.example")
	h.investigateClient(t, "10.0.0.5")
	// Give any stray asynchronous write a moment to land before counting.
	time.Sleep(50 * time.Millisecond)

	for _, tbl := range tables {
		if after := h.countRows(t, tbl); after != before[tbl] {
			t.Errorf("%s: %d rows before, %d after an investigation; reads must not write", tbl, before[tbl], after)
		}
	}
	if cacheAfter, _, _ := h.api.Resolver.Cache().Stats(); cacheAfter != cacheBefore {
		t.Error("an investigation changed the answer cache")
	}
}

// recordingConsultant is a reputation consultant that counts live lookups
// and answers cache reads from a fixed table.
type recordingConsultant struct {
	calls  int
	cached map[string]policy.ReputationVerdict
}

func (c *recordingConsultant) Consult(_ context.Context, _, _ string) (policy.ReputationVerdict, bool) {
	c.calls++
	return policy.ReputationVerdict{Malicious: true, ProviderName: "LiveOnly"}, true
}

func (c *recordingConsultant) ConsultCached(_, domain string) (policy.ReputationVerdict, policy.CacheState) {
	if v, ok := c.cached[domain]; ok {
		return v, policy.CacheHit
	}
	return policy.ReputationVerdict{}, policy.CacheMiss
}

func TestPreviewSaysNotEvaluatedRatherThanGuessingAllowed(t *testing.T) {
	h := newHarness(t)
	h.login()
	rep := &recordingConsultant{cached: map[string]policy.ReputationVerdict{
		"cached-bad.example": {Malicious: true, Category: "phishing", ProviderName: "TestIntel"},
	}}
	h.api.Engine.SetReputation(rep)
	t.Cleanup(func() { h.api.Engine.SetReputation(nil) })

	// A name nothing local knows and the provider has not cached: the live
	// path would ask; the preview must say so and ask nobody.
	out := h.investigate(t, "unknown.example")
	if out.Preview.Decision.Outcome != "not_evaluated" {
		t.Errorf("outcome = %q, want not_evaluated", out.Preview.Decision.Outcome)
	}
	if !strings.Contains(out.Preview.Decision.Reason, "provider lookup not performed") {
		t.Errorf("reason = %q, want it to say the lookup was not performed", out.Preview.Decision.Reason)
	}
	if !out.Preview.External.Configured || !out.Preview.External.Reached || out.Preview.External.Evaluated {
		t.Errorf("external = %+v", out.Preview.External)
	}
	if rep.calls != 0 {
		t.Fatalf("the preview made %d live provider call(s)", rep.calls)
	}

	// A cached verdict is used, and said to be from the cache.
	out = h.investigate(t, "cached-bad.example")
	if out.Preview.Decision.Outcome != "blocked" || out.Preview.Decision.Rule != "reputation" ||
		!out.Preview.External.FromCache || out.Preview.External.Provider != "TestIntel" {
		t.Errorf("cached verdict preview = %+v / %+v", out.Preview.Decision, out.Preview.External)
	}
	// A locally listed name never reaches the provider, and says so.
	out = h.investigate(t, "evil.com")
	if out.Preview.Decision.Outcome != "blocked" || out.Preview.External.Reached {
		t.Errorf("locally blocked name: %+v / %+v", out.Preview.Decision, out.Preview.External)
	}
	if rep.calls != 0 {
		t.Errorf("previews made %d live provider call(s) in total", rep.calls)
	}
}

func TestInvestigationEvidenceSaysWhichClaimsDecided(t *testing.T) {
	h := newHarness(t)
	h.login()
	r := enableDecisions(t, h)
	r.Record(blockEvent("evil.com"))
	waitForDecisions(t, r, 1, h)

	out := h.investigate(t, "evil.com")
	if len(out.Evidence.Items) != 1 {
		t.Fatalf("evidence = %+v, want the one claim the decision recorded", out.Evidence.Items)
	}
	item := out.Evidence.Items[0]
	if item.ContributedTo != 1 || item.Expired {
		t.Errorf("evidence item = %+v, want contributedTo 1 and not expired", item)
	}
	if out.Evidence.Assessment.Verdict != "malicious" {
		t.Errorf("assessment = %+v", out.Evidence.Assessment)
	}
	if !strings.Contains(out.Evidence.Note, "expired") {
		t.Error("the evidence section does not say how expired claims are treated")
	}
}

func TestInvestigationRelatesFindingsByExactParentAndKeepsTheirLabels(t *testing.T) {
	h := newHarness(t)
	h.login()
	now := time.Now()
	seedFinding(t, h, "f_parent", "dns_tunnel_suspected", "high", "10.0.0.5", "evil.com", now)
	seedFinding(t, h, "f_other", "dns_tunnel_suspected", "high", "10.0.0.6", "notevil.com", now)

	out := h.investigate(t, "a.b.evil.com")
	if len(out.Findings.Items) != 1 || out.Findings.Items[0].ID != "f_parent" {
		t.Errorf("findings = %+v, want only the finding about the parent evil.com", out.Findings.Items)
	}
	if out.Findings.Enforcement != "none" || !out.Findings.Experimental || !out.Findings.Enabled {
		t.Errorf("findings section lost its labels: %+v", out.Findings)
	}
	if out.Findings.Items[0].Detail == nil {
		t.Error("a related finding carries no detail; the view cannot show its measurements")
	}
	// Narrowed to a client that did not raise it.
	out = h.investigate(t, "evil.com", "client=10.0.0.9")
	if len(out.Findings.Items) != 0 {
		t.Errorf("findings for another client leaked into a client-narrowed view: %+v", out.Findings.Items)
	}
}

func TestInvestigationObservationsAreLabelledAndExact(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedObservations(t, h.store,
		obs("o1", "evil.com", "validated", "bogus", "local_bogus_upstream_validated"),
		obs("o2", "www.evil.com", "validated", "secure", ""),
	)

	out := h.investigate(t, "evil.com")
	if len(out.Observations.Items) != 1 || out.Observations.Items[0].ID != "o1" {
		t.Errorf("observations = %+v, want only the exact-name row", out.Observations.Items)
	}
	if out.Observations.Enforcing || !out.Observations.Experimental {
		t.Errorf("observation labels = %+v", out.Observations)
	}
	if !strings.Contains(out.Observations.Note, "changed nothing") {
		t.Error("the observation section does not say the verdict changed nothing")
	}
}

func TestClientInvestigationRespectsAttributionSettings(t *testing.T) {
	h := newHarness(t)
	h.login()
	now := time.Now().UTC()
	h.insertQueries(t, true,
		store.QueryEvent{Time: now, ClientIP: "10.0.0.5", NetworkID: "n_default", Domain: "evil.com", QType: "A", Action: store.ActionBlocked, Category: "malware"},
		store.QueryEvent{Time: now, ClientIP: "10.0.0.5", NetworkID: "n_default", Domain: "fine.example", QType: "A", Action: store.ActionAllowed},
		store.QueryEvent{Time: now, ClientIP: "10.0.0.6", NetworkID: "n_default", Domain: "fine.example", QType: "A", Action: store.ActionAllowed},
	)
	seedFinding(t, h, "fc", "dns_tunnel_suspected", "high", "10.0.0.5", "evil.com", now)

	out := h.investigateClient(t, "10.0.0.5")
	if !out.Activity.Available || out.Activity.Summary.Queries != 2 || out.Activity.Summary.Blocked != 1 {
		t.Errorf("client activity = %+v", out.Activity.Summary)
	}
	if len(out.Activity.Domains) != 2 || out.Activity.Domains[0].Domain == "" {
		t.Errorf("domains = %+v, want the client's 2 names", out.Activity.Domains)
	}
	if len(out.Findings.Items) != 1 {
		t.Errorf("findings = %+v, want the client's finding", out.Findings.Items)
	}
	if out.Subject.Attribution.PolicyID != "p_standard" || out.Subject.Attribution.Attribution != "catch_all" {
		t.Errorf("attribution = %+v, want the catch-all's current policy", out.Subject.Attribution)
	}

	// With attribution off, the rows are not searched by any other route.
	h.api.Config.Log.LogClientIP = false
	out = h.investigateClient(t, "10.0.0.5")
	if out.Activity.Available {
		t.Error("client activity reported available with client addresses not recorded")
	}
	if out.Activity.Unavailable == "" || out.Activity.Summary.Queries != 0 || len(out.Activity.Domains) != 0 {
		t.Errorf("activity with attribution off = %+v; nothing may be reconstructed", out.Activity)
	}
}

func TestInvestigationWithTheQueryLogOffSaysSo(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.api.Config.Log.QueryLog = false

	out := h.investigate(t, "evil.com")
	if out.Activity.Available || out.Activity.Unavailable == "" {
		t.Errorf("activity = %+v, want unavailable with a reason", out.Activity)
	}
	if out.Window.QueryLog || out.Window.ClientAttribution {
		t.Errorf("window = %+v, want both privacy switches reported off", out.Window)
	}
	// The other sections still answer: the preview does not need the log.
	if out.Preview.Decision.Outcome != "blocked" {
		t.Errorf("preview = %+v, want the index block regardless of logging", out.Preview.Decision)
	}
}

func TestEnrichIsADeliberateActionBehindProviders(t *testing.T) {
	h := newHarness(t)
	h.login()

	// No providers on this deployment: 503, and nothing was looked up.
	resp, raw := h.do(http.MethodPost, "/api/v1/investigate/domain/evil.com/enrich", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("enrich without providers = %d: %s", resp.StatusCode, raw)
	}

	// With an engine in mode off, the request is honoured by doing nothing
	// and saying so.
	eng := apiprovider.NewEngine(apiprovider.Options{Mode: apiprovider.ModeOff})
	h.api.Providers = eng
	resp, raw = h.do(http.MethodPost, "/api/v1/investigate/domain/evil.com/enrich", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enrich in mode off = %d: %s", resp.StatusCode, raw)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["lookup"] != "not_performed" || body["mode"] != "off" {
		t.Errorf("enrich body = %v, want lookup not_performed in mode off", body)
	}

	// A GET must not be able to trigger it.
	resp, _ = h.do(http.MethodGet, "/api/v1/investigate/domain/evil.com/enrich", nil)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("GET on the enrich route succeeded; a link could trigger a provider call")
	}
}

// The detail on a related finding is the same document the findings
// endpoint returns, so the dashboard's finding renderer applies unchanged.
func TestInvestigationFindingsCarryTheFullDocument(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedFinding(t, h, "fd", "dns_tunnel_suspected", "high", "10.0.0.5", "evil.com", time.Now())

	out := h.investigate(t, "evil.com")
	if len(out.Findings.Items) != 1 {
		t.Fatalf("findings = %d", len(out.Findings.Items))
	}
	var f detect.Finding
	if err := json.Unmarshal(out.Findings.Items[0].Detail, &f); err != nil || f.ID != "fd" {
		t.Errorf("detail did not decode as a finding: %v (%+v)", err, f)
	}
}
