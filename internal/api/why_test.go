package api

import (
	"context"
	"encoding/json"
	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/evidence"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestWhyRejectsANonNumericID.
func TestWhyRejectsANonNumericID(t *testing.T) {
	h := newHarness(t)
	h.login()
	if resp, _ := h.do("GET", "/api/v1/queries/abc/why", nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestWhyForAnUnknownQueryIs404NotAFabricatedAnswer.
func TestWhyForAnUnknownQueryIs404NotAFabricatedAnswer(t *testing.T) {
	h := newHarness(t)
	h.login()
	if resp, _ := h.do("GET", "/api/v1/queries/999999/why", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestWhyAndAuditNeedAuthentication. Both show what was resolved and who
// changed what; neither is public.
func TestWhyAndAuditNeedAuthentication(t *testing.T) {
	h := newHarness(t) // no login
	for _, path := range []string{"/api/v1/queries/1/why", "/api/v1/audit"} {
		resp, _ := h.do("GET", path, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s returned %d unauthenticated, want 401", path, resp.StatusCode)
		}
	}
}

// TestAuditListingIsBoundedAndReportsItsOwnGaps.
//
// The drop counters are on every response rather than only in /metrics,
// because the person reading an audit log is exactly the person who needs to
// know that some entries never made it.
func TestAuditListingIsBoundedAndReportsItsOwnGaps(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("GET", "/api/v1/audit?limit=1000000", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	var got struct {
		Entries []any             `json:"entries"`
		Dropped map[string]uint64 `json:"dropped"`
		Written uint64            `json:"written"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) > 500 {
		t.Errorf("an unbounded request returned %d entries", len(got.Entries))
	}
	if got.Dropped == nil {
		t.Error("the response does not report whether entries were dropped")
	}

	if bad, _ := h.do("GET", "/api/v1/audit?limit=0", nil); bad.StatusCode != http.StatusBadRequest {
		t.Errorf("limit=0 returned %d, want 400", bad.StatusCode)
	}
}

// TestAPolicyEditLeavesAnAuditEntryWithoutSecrets, through the real API.
func TestAPolicyEditLeavesAnAuditEntryWithoutSecrets(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("POST", "/api/v1/policies", map[string]any{
		"name":       "Audited",
		"categories": []string{"malware"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create policy: %d %s", resp.StatusCode, raw)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}

	if resp, raw := h.do("PATCH", "/api/v1/policies/"+created.ID, map[string]any{
		"categories": []string{"malware", "phishing"},
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("update policy: %d %s", resp.StatusCode, raw)
	}

	h.drainAudit(2) // the create and the edit

	_, raw = h.do("GET", "/api/v1/audit?target_type=policy", nil)
	var list struct {
		Entries []struct {
			Action string `json:"action"`
			Before string `json:"before"`
			After  string `json:"after"`
			Actor  string `json:"actor"`
			Source string `json:"source"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Entries) < 2 {
		t.Fatalf("%d audit entries for the create and the edit, want at least 2", len(list.Entries))
	}

	var update bool
	for _, e := range list.Entries {
		if e.Action != "policy.update" {
			continue
		}
		update = true
		if !strings.Contains(e.Before, "malware") || strings.Contains(e.Before, "phishing") {
			t.Errorf("before = %q, want the pre-edit categories", e.Before)
		}
		if !strings.Contains(e.After, "phishing") {
			t.Errorf("after = %q, want the post-edit categories", e.After)
		}
		if e.Actor == "" || e.Source == "" {
			t.Errorf("the entry does not say who or from where: %+v", e)
		}
	}
	if !update {
		t.Error("no policy.update entry was recorded")
	}
}

// TestAnAPITokenIsAuditedByIdentifierNotBySecret.
func TestAnAPITokenIsAuditedByIdentifierNotBySecret(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("POST", "/api/v1/tokens", map[string]any{"name": "CI"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: %d %s", resp.StatusCode, raw)
	}
	var tok struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		t.Fatal(err)
	}
	if tok.Secret == "" {
		t.Fatal("the API did not return a secret; the test cannot check it is absent from the audit log")
	}

	h.drainAudit(1)

	_, raw = h.do("GET", "/api/v1/audit?action=token.create", nil)
	if strings.Contains(string(raw), tok.Secret) {
		t.Fatal("the raw token appears in the audit log")
	}
	if !strings.Contains(string(raw), tok.ID) {
		t.Errorf("the audit entry does not identify the token: %s", raw)
	}
}

// seedQuery writes one query-log row directly and returns its id, so a test
// can ask why about a row whose decision state it controls.
func seedQuery(t *testing.T, h *harness, e store.QueryEvent) int64 {
	t.Helper()
	if err := h.store.InsertQueryBatch(context.Background(), []store.QueryEvent{e}, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}
	rows, _, err := h.store.ListQueries(context.Background(), store.QueryFilter{Limit: 1})
	if err != nil || len(rows) == 0 {
		t.Fatalf("no row was written (%v)", err)
	}
	return rows[0].ID
}

func fetchWhy(t *testing.T, h *harness, id int64) map[string]any {
	t.Helper()
	resp, raw := h.do("GET", "/api/v1/queries/"+strconv.FormatInt(id, 10)+"/why", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("why returned %d: %s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestWhyReportsAMissingRecordHonestly.
//
// This is the property that keeps the endpoint from being a liar. A blocked
// query whose decision record was dropped, or which predates decision records
// entirely, has a one-line reason in the query log and no evidence behind it.
// Presenting that sentence as the full answer would be exactly the failure the
// whole feature exists to prevent: an explanation with nothing under it,
// indistinguishable from one that was reconstructed from stored facts.
func TestWhyReportsAMissingRecordHonestly(t *testing.T) {
	h := newHarness(t)
	h.login()

	// A blocked row with no decision id: the shape of a dropped record, and
	// the shape of every row written before this feature existed.
	id := seedQuery(t, h, store.QueryEvent{
		Time: time.Now().UTC(), Domain: "orphan.example", QType: "A",
		Action: store.ActionBlocked, Reason: "Blocked by a feed",
	})

	got := fetchWhy(t, h, id)
	if got["completeness"] != whyMissing {
		t.Errorf("completeness = %v, want %q", got["completeness"], whyMissing)
	}
	if got["explanation"] != nil && got["explanation"] != "" {
		t.Errorf("an explanation was produced for a record that does not exist: %v", got["explanation"])
	}
	ev, _ := got["evidence"].([]any)
	if len(ev) != 0 {
		t.Errorf("evidence was invented: %v", ev)
	}
	note, _ := got["note"].(string)
	for _, want := range []string{"dropped", "no stored evidence"} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q does not explain why there is no record (%q)", note, want)
		}
	}
	// The flattened reason may still be shown — it is what the activity view
	// displays — but it must be alongside the missing state, not instead of it.
	if got["reason"] != "Blocked by a feed" {
		t.Errorf("reason = %v, want the query log's own summary", got["reason"])
	}
}

// TestWhyForAnOrdinaryAllowedQueryIsNotReportedAsALostRecord.
//
// "Nothing decided this" and "the record went missing" are different facts and
// an operator investigating an incident has to tell them apart. Both have no
// decision row, so only the query's own action distinguishes them.
func TestWhyForAnOrdinaryAllowedQueryIsNotReportedAsALostRecord(t *testing.T) {
	h := newHarness(t)
	h.login()

	id := seedQuery(t, h, store.QueryEvent{
		Time: time.Now().UTC(), Domain: "ordinary.example", QType: "A",
		Action: store.ActionAllowed, Reason: "Resolved",
	})

	got := fetchWhy(t, h, id)
	if got["completeness"] != whyMissing {
		t.Errorf("completeness = %v", got["completeness"])
	}
	note, _ := got["note"].(string)
	if !strings.Contains(note, "Nothing decided this query") {
		t.Errorf("note %q does not say that nothing decided", note)
	}
	if strings.Contains(note, "dropped") {
		t.Errorf("an ordinary allowed query was reported as a dropped record: %q", note)
	}
}

// TestWhyRebuildsFromTheStoredRecordNotFromLiveFeeds.
//
// The record is written with the evidence that was true at the time. If a feed
// later drops the domain — or the operator deletes the policy — the answer to
// "why was this blocked last night?" must not change. Re-running the policy
// engine at display time would produce an answer that quietly rewrites itself
// every time the intelligence refreshes.
func TestWhyRebuildsFromTheStoredRecordNotFromLiveFeeds(t *testing.T) {
	h := newHarness(t)
	h.login()
	ctx := context.Background()

	// Record a decision citing a feed, and link a query-log row to it.
	// Evidence has to be stored before it can be cited: the decision refers to
	// it by id, which is the whole mechanism that makes the citation survive a
	// feed refresh.
	ev, err := h.store.PutEvidence(ctx, evidence.Evidence{
		Subject: evidence.Domain("gone.example"), ObservedAt: time.Now().UTC(),
		Kind: evidence.KindFeed, Source: "f_threat", SourceName: "Threat feed",
		Category: "malware", Claim: "listed as malware", Confidence: evidence.ConfidenceHigh,
	})
	if err != nil {
		t.Fatalf("PutEvidence: %v", err)
	}
	stored, err := h.store.RecordDecision(ctx, store.Decision{
		ID: "dec_fixed", Time: time.Now().UTC(),
		Subject: evidence.Domain("gone.example"), Action: "blocked",
		Rule: "category", Category: "malware", PolicyID: "p_standard",
		Explanation: "Blocked because Threat feed listed it as malware.",
	}, []store.CitedEvidence{{Evidence: ev, Role: store.RoleCaused}})
	if err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}

	id := seedQuery(t, h, store.QueryEvent{
		Time: time.Now().UTC(), Domain: "gone.example", QType: "A",
		Action: store.ActionBlocked, Reason: "Blocked by a feed", DecisionID: stored.ID,
	})

	// Now empty the live index entirely: as far as the running resolver is
	// concerned, nothing lists this domain any more.
	h.lists.Store(blocklist.NewBuilder(0).Build())

	got := fetchWhy(t, h, id)
	if got["completeness"] != whyComplete {
		t.Fatalf("completeness = %v, want complete", got["completeness"])
	}
	cited, _ := got["evidence"].([]any)
	if len(cited) != 1 {
		t.Fatalf("%d pieces of evidence after the feed was emptied, want the stored one", len(cited))
	}
	first, _ := cited[0].(map[string]any)
	if first["sourceName"] != "Threat feed" {
		t.Errorf("evidence source = %v, want the feed as it was at the time", first["sourceName"])
	}
	if first["role"] != string(store.RoleCaused) {
		t.Errorf("role = %v, want caused", first["role"])
	}
	if !strings.Contains(got["explanation"].(string), "Threat feed") {
		t.Errorf("explanation = %v, want the sentence stored at decision time", got["explanation"])
	}
}

// TestWhyMarksATruncatedRecordAsSuch, so a partial evidence list is never
// presented as the whole story.
func TestWhyMarksATruncatedRecordAsSuch(t *testing.T) {
	h := newHarness(t)
	h.login()
	ctx := context.Background()

	stored, err := h.store.RecordDecision(ctx, store.Decision{
		ID: "dec_trunc", Time: time.Now().UTC(),
		Subject: evidence.Domain("many.example"), Action: "blocked",
		Rule: "category", Completeness: store.TruncatedRecord,
		Explanation: "Blocked because Threat feed listed it as malware.",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := seedQuery(t, h, store.QueryEvent{
		Time: time.Now().UTC(), Domain: "many.example", QType: "A",
		Action: store.ActionBlocked, DecisionID: stored.ID,
	})

	got := fetchWhy(t, h, id)
	if got["completeness"] != whyTruncated {
		t.Errorf("completeness = %v, want %q", got["completeness"], whyTruncated)
	}
	if note, _ := got["note"].(string); !strings.Contains(note, "more evidence") {
		t.Errorf("note %q does not explain the truncation", note)
	}
}

// TestWhyReportsADanglingDecisionIDAsMissing. The query log names a record the
// decisions table does not hold, which is what a drop between the two
// independent writers looks like.
func TestWhyReportsADanglingDecisionIDAsMissing(t *testing.T) {
	h := newHarness(t)
	h.login()

	id := seedQuery(t, h, store.QueryEvent{
		Time: time.Now().UTC(), Domain: "dangling.example", QType: "A",
		Action: store.ActionBlocked, Reason: "Blocked by a feed",
		DecisionID: "dec_never_written",
	})

	got := fetchWhy(t, h, id)
	if got["completeness"] != whyMissing {
		t.Errorf("completeness = %v, want missing", got["completeness"])
	}
	if note, _ := got["note"].(string); !strings.Contains(note, "dropped under load") {
		t.Errorf("note %q does not say the record was dropped", note)
	}
}
