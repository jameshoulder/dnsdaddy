package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/evidence"
)

func TestDecisionPagesPreserveTiesWindowAndInsertionBoundary(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	for i := 0; i < 11; i++ {
		_, err := st.RecordDecision(ctx, Decision{ID: fmt.Sprintf("tie%02d", i), Time: at,
			Subject: evidence.Domain("wanted.example"), ClientIP: "192.0.2.1", Action: ActionBlocked}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []Decision{
		{ID: "older", Time: at.Add(-time.Millisecond), Subject: evidence.Domain("wanted.example"), ClientIP: "192.0.2.1"},
		{ID: "other-client", Time: at, Subject: evidence.Domain("wanted.example"), ClientIP: "192.0.2.2"},
		{ID: "other-domain", Time: at, Subject: evidence.Domain("other.example"), ClientIP: "192.0.2.1"},
	} {
		if _, err := st.RecordDecision(ctx, d, nil); err != nil {
			t.Fatal(err)
		}
	}
	upper, err := st.ExportHighWater(ctx, "decisions")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordDecision(ctx, Decision{ID: "late-backdated", Time: at, Subject: evidence.Domain("wanted.example"), ClientIP: "192.0.2.1", Action: ActionBlocked}, nil); err != nil {
		t.Fatal(err)
	}
	for _, asc := range []bool{false, true} {
		f := DecisionFilter{Subject: "WANTED.EXAMPLE.", ClientIP: "192.0.2.1", Action: ActionBlocked,
			Since: at, Until: at, Limit: 4, Ascending: asc, MaxInsertionID: &upper}
		seen := map[string]bool{}
		var ordered []string
		for page := 0; ; page++ {
			if page > 5 {
				t.Fatal("decision pagination did not end")
			}
			rows, next, err := st.ListDecisionsPage(ctx, f)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if seen[row.ID] {
					t.Fatalf("duplicate decision %s", row.ID)
				}
				seen[row.ID] = true
				ordered = append(ordered, row.ID)
			}
			if next == "" {
				break
			}
			f.Cursor = next
		}
		if len(seen) != 11 || seen["late-backdated"] {
			t.Fatalf("wrong frozen population: %v", ordered)
		}
		for i, id := range ordered {
			want := fmt.Sprintf("tie%02d", i)
			if !asc {
				want = fmt.Sprintf("tie%02d", 10-i)
			}
			if id != want {
				t.Fatalf("order %v at %d = %s want %s", asc, i, id, want)
			}
		}
	}
	rows, next, err := st.ListDecisionsPage(ctx, DecisionFilter{Subject: "other.example", Limit: 1})
	if err != nil || len(rows) != 1 || next != "" {
		t.Fatalf("full final page = %v %q %v", rows, next, err)
	}
	if _, _, err := st.ListDecisionsPage(ctx, DecisionFilter{Cursor: "broken"}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("invalid cursor = %v", err)
	}
}

func TestDecisionEvidenceSnapshotSurvivesRefreshAndRemoval(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	expires := now.Add(time.Hour)
	original, err := st.PutEvidence(ctx, evidence.Evidence{Subject: evidence.Domain("x.example"), Kind: evidence.KindFeed,
		Source: "feed", SourceName: "Original feed", Claim: "listed", Category: "malware", Confidence: evidence.ConfidenceHigh,
		ObservedAt: now, ExpiresAt: &expires, Detail: map[string]any{"reason": "original observation"}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := st.RecordDecision(ctx, Decision{Time: now, Subject: original.Subject, Action: ActionBlocked, Explanation: "Original explanation"}, []CitedEvidence{{Evidence: original, Contributed: true}})
	if err != nil {
		t.Fatal(err)
	}
	changed := original
	changed.SourceName = "Changed feed"
	changed.Category = "phishing"
	changed.Confidence = evidence.ConfidenceLow
	changed.Detail = map[string]any{"reason": "changed observation"}
	if _, err := st.PutEvidence(ctx, changed); err != nil {
		t.Fatal(err)
	}
	for _, remove := range []bool{false, true} {
		if remove {
			if _, err := st.DeleteEvidenceFrom(ctx, "feed"); err != nil {
				t.Fatal(err)
			}
		}
		read, err := st.DecisionWithEvidence(ctx, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if read.EvidenceSource != "recorded_snapshot" || read.Explanation != "Original explanation" || len(read.Cited) != 1 {
			t.Fatalf("snapshot missing: %+v", read)
		}
		got := read.Cited[0]
		if !got.Contributed || got.Evidence.SourceName != "Original feed" || got.Evidence.Category != "malware" || got.Evidence.Confidence != evidence.ConfidenceHigh || got.Evidence.Detail["reason"] != "original observation" {
			t.Fatalf("historical evidence changed: %+v", got)
		}
	}
	if _, err := st.PruneDecisions(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"decision_evidence_captures", "decision_evidence_snapshots"} {
		var n int
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("snapshot retention %s = %d: %v", table, n, err)
		}
	}
}

func TestLegacyDecisionEvidenceIsExplicitlyNotAHistoricalSnapshot(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	d, err := st.RecordDecision(ctx, Decision{Time: time.Now(), Subject: evidence.Domain("legacy.example"), Explanation: "original text"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM decision_evidence_captures WHERE decision_id = ?`, d.ID); err != nil {
		t.Fatal(err)
	}
	if err := migrateDecisionSnapshots(st.db); err != nil {
		t.Fatal(err)
	}
	read, err := st.DecisionWithEvidence(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if read.EvidenceSource != "legacy_current_reference" || read.EvidenceNote == "" || read.Explanation != "original text" {
		t.Fatalf("legacy provenance = %+v", read)
	}
	fresh, err := st.RecordDecision(ctx, Decision{Time: time.Now(), Subject: evidence.Domain("zero.example")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	read, err = st.DecisionWithEvidence(ctx, fresh.ID)
	if err != nil || read.EvidenceSource != "recorded_snapshot" || len(read.Cited) != 0 {
		t.Fatalf("empty captured evidence = %+v: %v", read, err)
	}
}
