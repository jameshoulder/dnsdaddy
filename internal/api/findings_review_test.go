package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// The review workflow over HTTP. Beyond the store's own guarantees, these
// pin what the API adds: who may write, how a conflict is answered, that a
// review never changes what was detected, and that the disposition changes
// nothing about enforcement.

func (h *harness) review(t *testing.T, id string, body map[string]any) (*http.Response, map[string]any) {
	t.Helper()
	resp, raw := h.doWithHeaders(http.MethodPut, "/api/v1/findings/"+id+"/review", body,
		map[string]string{"Origin": h.server.URL})
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode review response: %v (%s)", err, raw)
		}
	}
	return resp, out
}

func TestReviewRequiresASameOriginAuthenticatedWrite(t *testing.T) {
	h := newHarness(t)
	seedFinding(t, h, "r1", "dns_tunnel_suspected", "high", "10.0.0.5", "t.example", time.Now())

	resp, _ := h.doWithHeaders(http.MethodPut, "/api/v1/findings/r1/review",
		map[string]any{"state": "acknowledged", "version": 0}, map[string]string{"Origin": h.server.URL})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated review = %d, want 401", resp.StatusCode)
	}
	resp, _ = h.do(http.MethodGet, "/api/v1/findings/r1/review/history", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated history = %d, want 401", resp.StatusCode)
	}

	h.login()
	resp, _ = h.doWithHeaders(http.MethodPut, "/api/v1/findings/r1/review",
		map[string]any{"state": "acknowledged", "version": 0}, map[string]string{"Origin": "https://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin review = %d, want 403", resp.StatusCode)
	}
	if rv, _ := h.store.GetFindingReview(context.Background(), "r1"); rv.Version != 0 {
		t.Error("a refused write still changed the review")
	}
}

func TestReviewLifecycleOverTheApi(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedFinding(t, h, "r1", "dns_tunnel_suspected", "high", "10.0.0.5", "t.example", time.Now())

	// Every listed finding carries a review, new at version 0 to begin with.
	var page findingsPage
	h.getJSON("/api/v1/findings", &page)
	if len(page.Findings) != 1 || page.Findings[0].Review == nil ||
		page.Findings[0].Review.State != "new" || page.Findings[0].Review.Version != 0 {
		t.Fatalf("listed review = %+v, want new at version 0", page.Findings[0].Review)
	}

	resp, body := h.review(t, "r1", map[string]any{"state": "acknowledged", "note": "looking at it", "version": 0})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("acknowledge = %d: %v", resp.StatusCode, body)
	}
	if body["state"] != "acknowledged" || body["version"] != float64(1) || body["actor"] != "session:admin" {
		t.Errorf("review = %v, want acknowledged, version 1, actor session:admin", body)
	}

	// A stale writer is told what the review is now.
	resp, body = h.review(t, "r1", map[string]any{"state": "resolved", "version": 0})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale write = %d, want 409: %v", resp.StatusCode, body)
	}
	current, _ := body["current"].(map[string]any)
	if current["version"] != float64(1) || current["state"] != "acknowledged" {
		t.Errorf("409 body carries %v, want the current review", body)
	}

	// The current writer proceeds, and the finding's own row reports it.
	resp, _ = h.review(t, "r1", map[string]any{"state": "false_positive", "note": "printer firmware check-in", "version": 1})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("false positive = %d", resp.StatusCode)
	}
	var one findingResponse
	h.getJSON("/api/v1/findings/r1", &one)
	if one.Review == nil || one.Review.State != "false_positive" || one.Review.Version != 2 {
		t.Errorf("finding carries review %+v", one.Review)
	}

	// An unknown finding, an unknown state and an impossible transition.
	resp, _ = h.review(t, "nope", map[string]any{"state": "acknowledged", "version": 0})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown finding = %d, want 404", resp.StatusCode)
	}
	resp, _ = h.review(t, "r1", map[string]any{"state": "escalated", "version": 2})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown state = %d, want 400", resp.StatusCode)
	}
	resp, body = h.review(t, "r1", map[string]any{"state": "new", "version": 2})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body["error"].(string), "cannot move") {
		t.Errorf("false_positive → new = %d %v, want 400 naming the transition", resp.StatusCode, body)
	}
	resp, _ = h.review(t, "r1", map[string]any{"state": "acknowledged", "note": strings.Repeat("n", 2001), "version": 2})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("over-long note = %d, want 400", resp.StatusCode)
	}

	// Reopen, and the history explains every step.
	resp, _ = h.review(t, "r1", map[string]any{"state": "acknowledged", "note": "reopened: seen again", "version": 2})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reopen = %d", resp.StatusCode)
	}
	var hist struct {
		History []store.ReviewEvent `json:"history"`
		Note    string              `json:"note"`
	}
	h.getJSON("/api/v1/findings/r1/review/history", &hist)
	if len(hist.History) != 3 {
		t.Fatalf("history has %d entries, want 3", len(hist.History))
	}
	if hist.History[2].FromState != "false_positive" || hist.History[2].ToState != "acknowledged" {
		t.Errorf("last entry = %+v", hist.History[2])
	}
	if !strings.Contains(hist.Note, "not tamper-evident") {
		t.Error("the history does not say what kind of record it is")
	}
	for _, e := range hist.History {
		if strings.Contains(e.Actor, "dnsd_") || len(e.Actor) > 64 {
			t.Errorf("actor %q looks like a secret rather than a label", e.Actor)
		}
	}
}

func TestATokenActorIsRecordedByNameNeverBySecret(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedFinding(t, h, "r1", "dns_tunnel_suspected", "high", "10.0.0.5", "t.example", time.Now())

	resp, raw := h.do(http.MethodPost, "/api/v1/tokens", map[string]string{"name": "soc-automation"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: %d %s", resp.StatusCode, raw)
	}
	token := decode[store.APIToken](t, raw)

	req, _ := http.NewRequest(http.MethodPut, h.server.URL+"/api/v1/findings/r1/review",
		strings.NewReader(`{"state":"acknowledged","version":0}`))
	req.Header.Set("Authorization", "Bearer "+token.Secret)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req) // no cookie jar, so the token is the only credential
	if err != nil {
		t.Fatalf("token review: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token review = %d", res.StatusCode)
	}
	rv, err := h.store.GetFindingReview(context.Background(), "r1")
	if err != nil {
		t.Fatal(err)
	}
	if rv.Actor != "token:soc-automation" {
		t.Errorf("actor = %q, want token:soc-automation", rv.Actor)
	}
	if strings.Contains(rv.Actor, token.Secret) {
		t.Fatal("the token secret was stored as the actor")
	}
}

func TestAReviewChangesNothingAboutDetectionOrEnforcement(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedFinding(t, h, "r1", "dns_tunnel_suspected", "high", "10.0.0.5", "evil.com", time.Now())

	var before findingResponse
	h.getJSON("/api/v1/findings/r1", &before)
	policiesBefore := h.countRows(t, "policy_rules")
	evidenceBefore := h.countRows(t, "evidence")
	lookupBefore := h.lists.Load().Len()

	resp, _ := h.review(t, "r1", map[string]any{"state": "false_positive", "note": "known good", "version": 0})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("review = %d", resp.StatusCode)
	}

	var after findingResponse
	h.getJSON("/api/v1/findings/r1", &after)
	if string(after.Detail) != string(before.Detail) || after.Severity != before.Severity ||
		after.Score != before.Score || after.Confidence != before.Confidence || after.Summary != before.Summary {
		t.Error("marking a false positive altered the finding's own evidence or measurements")
	}
	// evil.com is in the harness index: a false-positive review must not
	// have allowed it, added a rule, deleted evidence or touched the index.
	if h.countRows(t, "policy_rules") != policiesBefore {
		t.Error("a review changed policy rules")
	}
	if h.countRows(t, "evidence") != evidenceBefore {
		t.Error("a review changed the evidence table")
	}
	if h.lists.Load().Len() != lookupBefore {
		t.Error("a review changed the blocklist index")
	}
	if d := h.api.Engine.Evaluate("p_standard", "evil.com"); !d.Blocked {
		t.Error("a false-positive review allowed a listed domain")
	}
	var cat struct {
		Detectors []map[string]any `json:"detectors"`
	}
	h.getJSON("/api/v1/detectors", &cat)
	for _, d := range cat.Detectors {
		if d["enforces"] == true {
			t.Errorf("detector %v claims to enforce after a review", d["name"])
		}
	}
}

func TestReviewNotesRoundTripAsInertText(t *testing.T) {
	h := newHarness(t)
	h.login()
	seedFinding(t, h, "r1", "dns_tunnel_suspected", "high", "10.0.0.5", "t.example", time.Now())

	payload := `<img src=x onerror="alert(1)"> & "quotes" <script>`
	resp, body := h.review(t, "r1", map[string]any{"state": "acknowledged", "note": payload, "version": 0})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("review = %d", resp.StatusCode)
	}
	// Stored and returned as the literal characters: JSON-encoded on the
	// way out, escaped by every renderer, never interpreted by the server.
	if body["note"] != strings.TrimSpace(payload) {
		t.Errorf("note = %q, want the literal text", body["note"])
	}
	resp2, raw := h.do(http.MethodGet, "/api/v1/findings/r1", nil)
	resp2.Body.Close()
	if ct := resp2.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content type = %q", ct)
	}
	if strings.Contains(string(raw), "<img") {
		t.Error("raw markup reached the JSON body unencoded")
	}
}

func TestFindingsFilterAndCountByReviewState(t *testing.T) {
	h := newHarness(t)
	h.login()
	now := time.Now()
	seedFinding(t, h, "a", "dns_tunnel_suspected", "high", "10.0.0.5", "a.example", now)
	seedFinding(t, h, "b", "dns_tunnel_suspected", "high", "10.0.0.5", "b.example", now.Add(-time.Minute))
	seedFinding(t, h, "c", "nxdomain_burst", "medium", "10.0.0.6", "", now.Add(-2*time.Minute))
	if resp, _ := h.review(t, "b", map[string]any{"state": "resolved", "version": 0}); resp.StatusCode != http.StatusOK {
		t.Fatal("resolve b")
	}

	var page findingsPage
	h.getJSON("/api/v1/findings?state=new", &page)
	if page.Count != 2 {
		t.Errorf("new = %d, want 2", page.Count)
	}
	h.getJSON("/api/v1/findings?state=resolved", &page)
	if page.Count != 1 || page.Findings[0].ID != "b" {
		t.Errorf("resolved = %+v, want b", page.Findings)
	}
	h.getJSON("/api/v1/findings?state=new&severity=high&limit=1", &page)
	if page.Count != 1 || page.NextCursor != "" {
		t.Errorf("combined filters: count %d, cursor %q; want the single high new finding and no cursor", page.Count, page.NextCursor)
	}
	resp, _ := h.do(http.MethodGet, "/api/v1/findings?state=bogus", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad state = %d, want 400", resp.StatusCode)
	}

	var summary struct {
		ByState map[string]int64 `json:"byState"`
		Total   int64            `json:"total"`
	}
	h.getJSON("/api/v1/findings/summary?days=7", &summary)
	if summary.ByState["new"] != 2 || summary.ByState["resolved"] != 1 || summary.ByState["acknowledged"] != 0 {
		t.Errorf("byState = %v", summary.ByState)
	}
	if _, ok := summary.ByState["false_positive"]; !ok {
		t.Error("byState omits a state with no findings; every state must be present")
	}
}
