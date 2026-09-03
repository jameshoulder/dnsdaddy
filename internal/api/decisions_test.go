package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/decisions"
	"github.com/jameshoulder/dnsdaddy/internal/evidence"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// enableDecisions attaches a running recorder to a harness, the way the daemon
// does when decision records are switched on.
func enableDecisions(t *testing.T, h *harness) *decisions.Recorder {
	t.Helper()
	r := decisions.New(h.store, decisions.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)
	t.Cleanup(func() { cancel(); r.Wait() })
	h.api.Decisions = r
	return r
}

func blockEvent(domain string) decisions.Event {
	return decisions.Event{
		Time: time.Now().UTC(), Domain: domain, QType: "A",
		ClientIP: "192.0.2.10", ClientName: "workstation-14",
		NetworkID: "n_1", NetworkName: "Office",
		Action: store.ActionBlocked, Blocked: true,
		Basis: policy.Basis{
			Rule: policy.RuleCategory, PolicyID: "p_std", PolicyName: "Standard",
			FeedID: "f_urlhaus", FeedName: "URLhaus", Category: "malware",
		},
	}
}

func waitForDecisions(t *testing.T, r *decisions.Recorder, want int, h *harness) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := h.store.ListDecisions(context.Background(), store.DecisionFilter{})
		if err == nil && len(rows) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("only %d decisions were recorded; stats %+v", want, r.Stats())
}

// The read path an operator actually walks: see that something was blocked,
// open it, and read what decided.
func TestTheApiExplainsWhyADomainWasBlocked(t *testing.T) {
	h := newHarness(t)
	h.login()
	r := enableDecisions(t, h)

	r.Record(blockEvent("evil.example"))
	waitForDecisions(t, r, 1, h)

	// The list.
	_, raw := h.do("GET", "/api/v1/decisions", nil)
	var list struct {
		Decisions []store.Decision `json:"decisions"`
		Recording bool             `json:"recording"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	if !list.Recording {
		t.Error("the API does not report that recording is on")
	}
	if len(list.Decisions) != 1 {
		t.Fatalf("got %d decisions", len(list.Decisions))
	}
	d := list.Decisions[0]
	if d.Explanation == "" || !strings.Contains(d.Explanation, "URLhaus") {
		t.Errorf("explanation = %q", d.Explanation)
	}
	if !strings.Contains(d.PolicyPath, "BLOCK") {
		t.Errorf("policy path = %q", d.PolicyPath)
	}

	// The detail, with the evidence.
	resp, raw := h.do("GET", "/api/v1/decisions/"+d.ID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail: %d %s", resp.StatusCode, raw)
	}
	var full store.Decision
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatal(err)
	}
	if len(full.Cited) != 1 {
		t.Fatalf("the detail cites %d pieces of evidence", len(full.Cited))
	}
	if !full.Cited[0].Contributed {
		t.Error("the evidence that decided is not marked as contributing")
	}
	if full.Cited[0].Evidence.SourceName != "URLhaus" {
		t.Errorf("cited source = %q", full.Cited[0].Evidence.SourceName)
	}

	// And the domain view, which answers "what do we know now".
	_, raw = h.do("GET", "/api/v1/evidence/domain/evil.example", nil)
	var view struct {
		Assessment evidence.Assessment `json:"assessment"`
		Evidence   []evidence.Evidence `json:"evidence"`
		Decisions  []store.Decision    `json:"decisions"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	if view.Assessment.Verdict != evidence.VerdictMalicious {
		t.Errorf("assessment verdict = %q", view.Assessment.Verdict)
	}
	if len(view.Evidence) != 1 || len(view.Decisions) != 1 {
		t.Errorf("domain view: %d evidence, %d decisions", len(view.Evidence), len(view.Decisions))
	}
}

// An empty list with recording off and an empty list with recording on mean
// opposite things, and the API has to say which.
func TestTheApiDistinguishesNothingBlockedFromNothingRecorded(t *testing.T) {
	h := newHarness(t)
	h.login()

	_, raw := h.do("GET", "/api/v1/decisions", nil)
	var off struct {
		Decisions []store.Decision `json:"decisions"`
		Recording bool             `json:"recording"`
	}
	if err := json.Unmarshal(raw, &off); err != nil {
		t.Fatal(err)
	}
	if off.Recording {
		t.Error("recording is reported as on when no recorder is configured")
	}
	if len(off.Decisions) != 0 {
		t.Errorf("got %d decisions with no recorder", len(off.Decisions))
	}

	enableDecisions(t, h)
	_, raw = h.do("GET", "/api/v1/decisions", nil)
	var on struct {
		Recording bool `json:"recording"`
	}
	if err := json.Unmarshal(raw, &on); err != nil {
		t.Fatal(err)
	}
	if !on.Recording {
		t.Error("recording is reported as off when a recorder is configured")
	}
}

// A decision record is what the resolver did. There must be no route that can
// rewrite one, or it stops being evidence.
func TestDecisionsAreReadOnlyOverTheApi(t *testing.T) {
	h := newHarness(t)
	h.login()
	r := enableDecisions(t, h)
	r.Record(blockEvent("evil.example"))
	waitForDecisions(t, r, 1, h)

	rows, err := h.store.ListDecisions(context.Background(), store.DecisionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	id := rows[0].ID

	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/decisions"},
		{"PUT", "/api/v1/decisions/" + id},
		{"PATCH", "/api/v1/decisions/" + id},
		{"DELETE", "/api/v1/decisions/" + id},
		{"POST", "/api/v1/evidence/domain/evil.example"},
		{"DELETE", "/api/v1/evidence/domain/evil.example"},
	} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			resp, _ := h.do(c.method, c.path, map[string]any{"explanation": "rewritten"})
			// 405 or 404 — anything but a success. A 2xx here would mean a
			// route exists that can alter the record.
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				t.Errorf("%s %s returned %d; decision records must not be writable",
					c.method, c.path, resp.StatusCode)
			}
		})
	}

	// And the record is untouched.
	after, err := h.store.DecisionWithEvidence(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if after.Explanation != rows[0].Explanation {
		t.Error("the explanation changed")
	}
}

// Filtering, so an investigation can narrow to one domain or one client.
func TestDecisionsCanBeFiltered(t *testing.T) {
	h := newHarness(t)
	h.login()
	r := enableDecisions(t, h)

	a := blockEvent("one.example")
	b := blockEvent("two.example")
	b.ClientIP, b.ClientName = "192.0.2.99", "laptop-03"
	r.Record(a)
	r.Record(b)
	waitForDecisions(t, r, 2, h)

	for _, tc := range []struct {
		query string
		want  string
	}{
		{"?domain=one.example", "one.example"},
		{"?client=192.0.2.99", "two.example"},
	} {
		_, raw := h.do("GET", "/api/v1/decisions"+tc.query, nil)
		var got struct {
			Decisions []store.Decision `json:"decisions"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Decisions) != 1 {
			t.Fatalf("%s returned %d decisions, want 1", tc.query, len(got.Decisions))
		}
		if got.Decisions[0].Subject.Value != tc.want {
			t.Errorf("%s returned %q, want %q", tc.query, got.Decisions[0].Subject.Value, tc.want)
		}
	}
}

func TestAnUnknownDecisionIsANotFound(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableDecisions(t, h)

	resp, _ := h.do("GET", "/api/v1/decisions/dec_doesnotexist", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
