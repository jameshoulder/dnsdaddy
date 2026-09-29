package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
)

// The list and the export both page by keyset cursor. These tests pin the
// HTTP contract: where the cursor travels, what an exhausted walk looks like,
// what a bad cursor gets, and that an export never claims to be complete when
// it is not.

type findingsPage struct {
	Findings   []findingResponse `json:"findings"`
	Count      int               `json:"count"`
	Limit      int               `json:"limit"`
	NextCursor string            `json:"nextCursor"`
}

func TestFindingsListPagesByCursorWithoutRepeatingOrSkipping(t *testing.T) {
	h := newHarness(t)
	h.login()

	now := time.Now()
	for i := 0; i < 11; i++ {
		seedFinding(t, h, "p"+string(rune('a'+i)), "dns_tunnel_suspected", "low", "10.0.0.5", "x.example",
			now.Add(-time.Duration(i)*time.Second))
	}

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		path := "/api/v1/findings?limit=4"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		var page findingsPage
		h.getJSON(path, &page)
		pages++
		if page.Limit != 4 {
			t.Errorf("limit echoed as %d, want 4", page.Limit)
		}
		for _, f := range page.Findings {
			if seen[f.ID] {
				t.Errorf("finding %s appeared twice", f.ID)
			}
			seen[f.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		if page.Count != 4 {
			t.Errorf("a page with a continuation held %d rows, want the full 4", page.Count)
		}
		cursor = page.NextCursor
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 11 || pages != 3 {
		t.Errorf("walked %d findings in %d pages, want 11 in 3", len(seen), pages)
	}
}

func TestFindingsListRejectsAnInvalidCursor(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do(http.MethodGet, "/api/v1/findings?cursor=not-a-cursor", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "cursor") {
		t.Errorf("the error does not name the cursor: %s", raw)
	}

	resp, _ = h.do(http.MethodGet, "/api/v1/findings/export?cursor=%3A", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("export with a bad cursor = %d, want 400", resp.StatusCode)
	}
}

func TestExportReportsTruncationAndContinuesInTimeOrder(t *testing.T) {
	h := newHarness(t)
	h.login()

	now := time.Now()
	want := make([]string, 0, 7)
	for i := 0; i < 7; i++ {
		id := "x" + string(rune('a'+i))
		want = append(want, id)
		// Oldest first in `want`, so the walk below must reproduce it.
		seedFinding(t, h, id, "dns_tunnel_suspected", "low", "10.0.0.5", "x.example",
			now.Add(-time.Duration(7-i)*time.Second))
	}

	var got []string
	cursor := ""
	for round := 0; ; round++ {
		path := "/api/v1/findings/export?limit=3"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		resp, body := h.do(http.MethodGet, path, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("round %d: status %d", round, resp.StatusCode)
		}
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		if strings.TrimSpace(string(body)) == "" {
			lines = nil
		}
		if count := resp.Header.Get("X-Export-Count"); count != itoa(len(lines)) {
			t.Errorf("round %d: X-Export-Count = %q, body has %d lines", round, count, len(lines))
		}
		for _, line := range lines {
			var f detect.Finding
			if err := json.Unmarshal([]byte(line), &f); err != nil {
				t.Fatalf("round %d: bad line %q: %v", round, line, err)
			}
			got = append(got, f.ID)
		}
		next := resp.Header.Get("X-Next-Cursor")
		truncated := resp.Header.Get("X-Truncated")
		switch {
		case next != "" && truncated != "true":
			t.Errorf("round %d: a continuation cursor with X-Truncated=%q", round, truncated)
		case next == "" && truncated != "false":
			t.Errorf("round %d: no continuation but X-Truncated=%q", round, truncated)
		}
		if next == "" {
			break
		}
		if len(lines) != 3 {
			t.Errorf("round %d: truncated export carried %d lines, want the full 3", round, len(lines))
		}
		cursor = next
		if round > 5 {
			t.Fatal("export pagination did not terminate")
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("export walk = %v, want oldest first %v with no repeats", got, want)
	}
}

func TestAFullExportPageIsNotClaimedComplete(t *testing.T) {
	// The case the brief names: a page exactly at the limit with more behind
	// it. The old export returned the same body with nothing to say it was a
	// prefix.
	h := newHarness(t)
	h.login()
	now := time.Now()
	for i := 0; i < 4; i++ {
		seedFinding(t, h, "q"+string(rune('a'+i)), "dns_tunnel_suspected", "low", "10.0.0.5", "x.example",
			now.Add(-time.Duration(i)*time.Second))
	}
	resp, body := h.do(http.MethodGet, "/api/v1/findings/export?limit=4", nil)
	resp.Body.Close()
	if n := len(strings.Split(strings.TrimSpace(string(body)), "\n")); n != 4 {
		t.Fatalf("got %d lines, want 4", n)
	}
	if resp.Header.Get("X-Truncated") != "false" || resp.Header.Get("X-Next-Cursor") != "" {
		t.Errorf("an export holding every match was marked truncated: %v", resp.Header)
	}

	seedFinding(t, h, "qe", "dns_tunnel_suspected", "low", "10.0.0.5", "x.example", now.Add(-time.Millisecond))
	resp, _ = h.do(http.MethodGet, "/api/v1/findings/export?limit=4", nil)
	resp.Body.Close()
	if resp.Header.Get("X-Truncated") != "true" || resp.Header.Get("X-Next-Cursor") == "" {
		t.Errorf("an export at its limit with a row remaining was not marked truncated: %v", resp.Header)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
