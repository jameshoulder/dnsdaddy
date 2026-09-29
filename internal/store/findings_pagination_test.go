package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Keyset pagination over findings. Each test pins one property a consumer
// relies on and that an offset-based page would get wrong.

func seedFindings(t *testing.T, st *Store, n int, at time.Time, step time.Duration) []string {
	t.Helper()
	ids := make([]string, 0, n)
	rows := make([]Finding, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("f%03d", i)
		ids = append(ids, id)
		rows = append(rows, Finding{
			ID: id, Time: at.Add(time.Duration(i) * step), EventType: "dns_tunnel_suspected",
			Severity: "low", Detector: "dns_tunnel", Title: "t", Summary: "s", Detail: "{}",
		})
	}
	if err := st.InsertFindings(context.Background(), rows); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}
	return ids
}

// walk pages through every finding matching f and returns the ids in order.
func walk(t *testing.T, st *Store, f FindingFilter) []string {
	t.Helper()
	var out []string
	seen := map[string]bool{}
	for page := 0; page < 1000; page++ {
		rows, next, err := st.ListFindings(context.Background(), f)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		for _, r := range rows {
			if seen[r.ID] {
				t.Fatalf("page %d repeated %s", page, r.ID)
			}
			seen[r.ID] = true
			out = append(out, r.ID)
		}
		if next == "" {
			return out
		}
		if len(rows) != f.Limit {
			t.Fatalf("page %d returned %d rows with a next cursor; only the last page may be short", page, len(rows))
		}
		f.Cursor = next
	}
	t.Fatal("pagination did not terminate")
	return nil
}

func TestFindingsPageThroughSameTimestampRowsWithoutRepeatingOrSkipping(t *testing.T) {
	st := newTestStore(t)
	// Every row at the identical millisecond, as a detection batch writes
	// them. Only the id can order these, and a page boundary must fall
	// between two of them cleanly.
	at := time.Now().UTC().Truncate(time.Millisecond)
	ids := seedFindings(t, st, 25, at, 0)

	got := walk(t, st, FindingFilter{Limit: 7})
	if len(got) != len(ids) {
		t.Fatalf("walked %d rows, want %d", len(got), len(ids))
	}
	// Newest first, and among equal timestamps by id descending.
	for i := 1; i < len(got); i++ {
		if got[i] >= got[i-1] {
			t.Fatalf("order broke at %d: %s then %s", i, got[i-1], got[i])
		}
	}
}

func TestFindingsAscendingWalkVisitsEveryRowOnceOldestFirst(t *testing.T) {
	st := newTestStore(t)
	at := time.Now().UTC().Add(-time.Hour)
	ids := seedFindings(t, st, 23, at, time.Second)

	got := walk(t, st, FindingFilter{Limit: 5, Ascending: true})
	if len(got) != len(ids) {
		t.Fatalf("walked %d rows, want %d", len(got), len(ids))
	}
	for i := range ids {
		if got[i] != ids[i] {
			t.Fatalf("position %d = %s, want %s", i, got[i], ids[i])
		}
	}
}

func TestFindingsInsertedDuringAWalkNeitherRepeatNorDisplaceRows(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	seedFindings(t, st, 10, at, time.Second)

	// First page, newest first.
	first, next, err := st.ListFindings(ctx, FindingFilter{Limit: 4})
	if err != nil || next == "" {
		t.Fatalf("first page: %v (next %q)", err, next)
	}

	// The engine keeps writing: a newer finding and one older than anything
	// stored. An offset would now shift the second page by one and repeat
	// the last row of the first; a keyset position does not move.
	if err := st.InsertFindings(ctx, []Finding{
		{ID: "newer", Time: at.Add(time.Hour), EventType: "x", Severity: "low", Detail: "{}"},
		{ID: "older", Time: at.Add(-time.Hour), EventType: "x", Severity: "low", Detail: "{}"},
	}); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}

	seen := map[string]bool{}
	for _, r := range first {
		seen[r.ID] = true
	}
	for next != "" {
		var rows []Finding
		rows, next, err = st.ListFindings(ctx, FindingFilter{Limit: 4, Cursor: next})
		if err != nil {
			t.Fatalf("continuation: %v", err)
		}
		for _, r := range rows {
			if seen[r.ID] {
				t.Errorf("row %s repeated after a concurrent insert", r.ID)
			}
			seen[r.ID] = true
		}
	}
	// Every original row not on the first page turned up exactly once, and
	// so did the older insert, which sorts after the cursor.
	if len(seen) != 11 {
		t.Errorf("saw %d distinct rows, want the 10 originals plus the older insert", len(seen))
	}
	if !seen["older"] {
		t.Error("the finding inserted behind the cursor was never reached")
	}
	// The newer insert sorts before the cursor and belongs to a fresh walk,
	// not to this one — a consumer that wants it starts again from the top.
	if seen["newer"] {
		t.Error("a finding inserted ahead of the cursor appeared mid-walk, which means the position moved")
	}
}

func TestFindingsLastPageReturnsNoCursor(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedFindings(t, st, 6, time.Now().UTC(), time.Second)

	// Exactly one page: no cursor even though the page is full.
	rows, next, err := st.ListFindings(ctx, FindingFilter{Limit: 6})
	if err != nil || len(rows) != 6 {
		t.Fatalf("full page: %d rows, %v", len(rows), err)
	}
	if next != "" {
		t.Errorf("a page holding every matching row returned a cursor %q", next)
	}

	// A larger limit than there are rows: the same.
	rows, next, err = st.ListFindings(ctx, FindingFilter{Limit: 100})
	if err != nil || len(rows) != 6 || next != "" {
		t.Errorf("oversized page: %d rows, cursor %q, %v", len(rows), next, err)
	}

	// An empty result has no cursor and no error.
	rows, next, err = st.ListFindings(ctx, FindingFilter{Limit: 5, Severity: "high"})
	if err != nil || len(rows) != 0 || next != "" {
		t.Errorf("empty result: %d rows, cursor %q, %v", len(rows), next, err)
	}
}

func TestFindingsRejectAForeignCursor(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedFindings(t, st, 3, time.Now().UTC(), time.Second)

	for _, bad := range []string{"garbage", ":", "12:", ":abc", "-5:f001", "1e3:f001", "12", "abc:def"} {
		_, _, err := st.ListFindings(ctx, FindingFilter{Limit: 5, Cursor: bad})
		if !errors.Is(err, ErrInvalidCursor) {
			t.Errorf("cursor %q: err = %v, want ErrInvalidCursor", bad, err)
		}
	}
	// A well-formed cursor naming a row that no longer exists is still a
	// position, and continues from it rather than failing.
	rows, _, err := st.ListFindings(ctx, FindingFilter{Limit: 5, Cursor: "0:zzz", Ascending: true})
	if err != nil || len(rows) != 3 {
		t.Errorf("cursor at a vanished position: %d rows, %v", len(rows), err)
	}
}

func TestFindingsCursorRespectsTheOtherFilters(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	var rows []Finding
	for i := 0; i < 12; i++ {
		sev := "low"
		if i%3 == 0 {
			sev = "high"
		}
		rows = append(rows, Finding{
			ID: fmt.Sprintf("m%02d", i), Time: at.Add(time.Duration(i) * time.Second),
			EventType: "x", Severity: sev, ClientIP: "10.0.0.1", Detail: "{}",
		})
	}
	if err := st.InsertFindings(ctx, rows); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}
	got := walk(t, st, FindingFilter{Limit: 2, Severity: "high", ClientIP: "10.0.0.1"})
	if len(got) != 4 {
		t.Errorf("filtered walk visited %v, want the four high-severity rows", got)
	}
}
