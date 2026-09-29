package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/evidence"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func exportNextLink(t *testing.T, resp *http.Response) string {
	t.Helper()
	link := resp.Header.Get("Link")
	if link == "" {
		return ""
	}
	if !strings.HasPrefix(link, "<") || !strings.HasSuffix(link, ">; rel=\"next\"") {
		t.Fatalf("bad next Link %q", link)
	}
	return strings.TrimSuffix(strings.TrimPrefix(link, "<"), ">; rel=\"next\"")
}

func exportLines(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			t.Fatalf("invalid NDJSON line %q: %v", line, err)
		}
		out = append(out, doc)
	}
	return out
}

func TestExportsRequireAuthentication(t *testing.T) {
	h := newHarness(t)
	for _, kind := range []string{"queries", "decisions", "findings"} {
		resp, _ := h.do(http.MethodGet, "/api/v1/"+kind+"/export", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s export without auth = %d", kind, resp.StatusCode)
		}
	}
}

func TestAllExportsWalkTiesAndFreezeLateInsertsAfterHighestRowDeletion(t *testing.T) {
	for _, kind := range []string{"queries", "decisions", "findings"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t)
			h.login()
			at := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
			insert := func(id string, client string) {
				t.Helper()
				switch kind {
				case "queries":
					h.insertQueries(t, true, store.QueryEvent{Time: at, ClientIP: client, Domain: "wanted.example", QType: "A", Action: store.ActionAllowed, Reason: id})
				case "decisions":
					_, err := h.store.RecordDecision(context.Background(), store.Decision{ID: id, Time: at, ClientIP: client, Subject: evidence.Domain("wanted.example"), Action: store.ActionBlocked, Explanation: id}, nil)
					if err != nil {
						t.Fatal(err)
					}
				case "findings":
					seedFinding(t, h, id, "dns_tunnel_suspected", "high", client, "wanted.example", at)
				}
			}
			for i := 0; i < 11; i++ {
				insert(fmt.Sprintf("row%02d", i), "192.0.2.1")
			}
			insert("other-client", "192.0.2.2")
			path := "/api/v1/" + kind + "/export?limit=4&client=192.0.2.1&since=" + url.QueryEscape(at.Format(time.RFC3339Nano)) + "&until=" + url.QueryEscape(at.Format(time.RFC3339Nano))
			seen := map[string]bool{}
			var snapshot, frozenUntil string
			for page := 0; ; page++ {
				if page > 5 {
					t.Fatal("pagination did not terminate")
				}
				resp, raw := h.do(http.MethodGet, path, nil)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("%s = %d: %s", path, resp.StatusCode, raw)
				}
				lines := exportLines(t, raw)
				if resp.Header.Get("X-Export-Count") != fmt.Sprint(len(lines)) || resp.Header.Get("X-Export-Skipped") != "0" {
					t.Fatalf("incorrect export counts: %v", resp.Header)
				}
				if page == 0 {
					snapshot = resp.Header.Get("X-Export-Snapshot")
					frozenUntil = resp.Header.Get("X-Export-Until")
				}
				if resp.Header.Get("X-Export-Snapshot") != snapshot || resp.Header.Get("X-Export-Until") != frozenUntil {
					t.Fatal("export moved its snapshot boundary")
				}
				for _, line := range lines {
					id := fmt.Sprint(line["id"])
					if kind == "queries" {
						id = fmt.Sprint(line["reason"])
					}
					if seen[id] {
						t.Fatalf("duplicate row %s", id)
					}
					seen[id] = true
					if kind == "decisions" && line["evidenceSource"] != "recorded_snapshot" {
						t.Fatalf("decision export lost evidence provenance: %v", line)
					}
				}
				if page == 0 {
					// The final insertion belongs to another client. Removing
					// it must not allow SQLite's reused rowid to smuggle a new,
					// backdated record into the existing export boundary.
					var removeHighest string
					switch kind {
					case "queries":
						removeHighest = `DELETE FROM query_log WHERE id = (SELECT MAX(id) FROM query_log)`
					case "decisions":
						removeHighest = `DELETE FROM decisions WHERE rowid = (SELECT MAX(rowid) FROM decisions)`
					case "findings":
						removeHighest = `DELETE FROM findings WHERE rowid = (SELECT MAX(rowid) FROM findings)`
					}
					if _, err := h.store.DB().Exec(removeHighest); err != nil {
						t.Fatal(err)
					}
					insert("late-backdated", "192.0.2.1")
				}
				path = exportNextLink(t, resp)
				if path == "" {
					if resp.Header.Get("X-Truncated") != "false" || resp.Header.Get("X-Next-Cursor") != "" {
						t.Fatal("terminal page metadata is inconsistent")
					}
					break
				}
				if resp.Header.Get("X-Truncated") != "true" {
					t.Fatal("next Link without truncation flag")
				}
			}
			if len(seen) != 11 || seen["late-backdated"] || seen["other-client"] {
				t.Fatalf("export population = %v", seen)
			}
		})
	}
}

func TestExportRejectsBadCursorChangedFiltersAndInvalidWindow(t *testing.T) {
	h := newHarness(t)
	h.login()
	at := time.Now().Add(-time.Hour)
	for _, id := range []string{"a", "b"} {
		seedFinding(t, h, id, "dns_tunnel_suspected", "low", "192.0.2.1", "x.example", at)
	}
	resp, _ := h.do(http.MethodGet, "/api/v1/findings/export?limit=1&hours=24", nil)
	cursor := resp.Header.Get("X-Next-Cursor")
	if cursor == "" {
		t.Fatal("fixture did not produce a cursor")
	}
	for _, path := range []string{
		"/api/v1/findings/export?cursor=garbage",
		"/api/v1/findings/export?cursor=" + cursor + "&hours=48",
		"/api/v1/decisions/export?cursor=" + cursor + "&hours=24",
		"/api/v1/queries/export?hours=-1", "/api/v1/queries/export?hours=9999999999999",
		"/api/v1/findings/export?since=yesterday", "/api/v1/decisions/export?since=2026-01-02T00:00:00Z&until=2026-01-01T00:00:00Z",
		"/api/v1/findings/export?hours=24&since=2026-01-01T00:00:00Z", "/api/v1/queries?cursor=oops", "/api/v1/queries?cursor=-2",
	} {
		resp, raw := h.do(http.MethodGet, path, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d: %s", path, resp.StatusCode, raw)
		}
	}
}

func TestFindingExportCompactsDocumentsAndReportsCorruptRows(t *testing.T) {
	h := newHarness(t)
	h.login()
	at := time.Now().Add(-time.Hour)
	err := h.store.InsertFindings(context.Background(), []store.Finding{
		{ID: "a", Time: at, Detail: "{\n  \"id\": \"a\",\n  \"futureField\": true\n}"},
		{ID: "b", Time: at, Detail: "not JSON"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, raw := h.do(http.MethodGet, "/api/v1/findings/export", nil)
	lines := exportLines(t, raw)
	if len(lines) != 1 || lines[0]["futureField"] != true || resp.Header.Get("X-Export-Count") != "1" || resp.Header.Get("X-Export-Skipped") != "1" || resp.Header.Get("X-Export-Scanned") != "2" || resp.Header.Get("X-Truncated") != "false" {
		t.Fatalf("corrupt/pretty printed export: %s headers=%v", raw, resp.Header)
	}
}

func TestQueryContinuationUsesExactDomainClientAndAbsoluteWindow(t *testing.T) {
	h := newHarness(t)
	h.login()
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	for _, e := range []store.QueryEvent{
		{Time: at, Domain: "x.example", ClientIP: "192.0.2.1"}, {Time: at, Domain: "x.example", ClientIP: "192.0.2.1"},
		{Time: at, Domain: "notx.example", ClientIP: "192.0.2.1"}, {Time: at, Domain: "x.example", ClientIP: "192.0.2.2"},
	} {
		h.insertQueries(t, true, e)
	}
	base := "/api/v1/queries?exactDomain=X.EXAMPLE.&client=" + url.QueryEscape("::ffff:192.0.2.1") + "&limit=1&since=" + url.QueryEscape(at.Format(time.RFC3339Nano)) + "&until=" + url.QueryEscape(at.Format(time.RFC3339Nano))
	var page struct {
		Queries []store.QueryEvent `json:"queries"`
		Next    int64              `json:"nextCursor"`
	}
	h.getJSON(base, &page)
	if len(page.Queries) != 1 || page.Next == 0 {
		t.Fatalf("first exact page = %+v", page)
	}
	first := page.Queries[0].ID
	h.getJSON(base+"&cursor="+fmt.Sprint(page.Next), &page)
	if len(page.Queries) != 1 || page.Next != 0 || page.Queries[0].ID == first {
		t.Fatalf("terminal exact page = %+v", page)
	}
}
