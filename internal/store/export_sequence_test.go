package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/evidence"
)

func TestExportSequencesPreserveLegacyEvidenceAndSurviveDeletionAndReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	// schema.sql is deliberately applied without startup migrations here:
	// these records predate both snapshot capture and insertion sequences.
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO query_log(id, ts, qname, qtype, action) VALUES
			(7, 1000, 'legacy.example', 'A', 'allowed'),
			(31, 1000, 'last.example', 'A', 'allowed');
		INSERT INTO evidence(id, subject_type, subject, kind, source, claim, observed_at)
			VALUES ('ev_legacy', 'domain', 'legacy.example', 'feed', 'legacy-feed', 'original claim', 1000);
		INSERT INTO decisions(id, ts, query_log_id, subject, action, explanation) VALUES
			('legacy', 1000, 7, 'legacy.example', 'blocked', 'original explanation'),
			('last', 1000, 31, 'last.example', 'blocked', 'last explanation');
		INSERT INTO decision_evidence(decision_id, evidence_id, contributed) VALUES ('legacy', 'ev_legacy', 1);
		INSERT INTO findings(id, ts, event_type, severity, confidence) VALUES
			('legacy', 1000, 'fixture', 'low', 0), ('last', 1000, 'fixture', 'low', 0);
	`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { st.Close() }()
	original, err := st.DecisionWithEvidence(ctx, "legacy")
	if err != nil || original.QueryLogID == nil || *original.QueryLogID != 7 || original.Explanation != "original explanation" || original.EvidenceSource != "legacy_current_reference" || len(original.Cited) != 1 || original.Cited[0].Evidence.Claim != "original claim" {
		t.Fatalf("migration rewrote legacy decision/evidence: %+v %v", original, err)
	}
	boundaries := map[string]int64{"queries": 31, "decisions": 2, "findings": 2}
	for dataset, want := range boundaries {
		got, err := st.ExportHighWater(ctx, dataset)
		if err != nil || got != want {
			t.Fatalf("%s initial boundary = %d, %v; want %d", dataset, got, err, want)
		}
	}
	if _, err := st.DB().Exec(`
		DELETE FROM query_log WHERE id = 31;
		DELETE FROM decisions WHERE id = 'last';
		DELETE FROM findings WHERE id = 'last';
	`); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for dataset, want := range boundaries {
		got, err := st.ExportHighWater(ctx, dataset)
		if err != nil || got != want {
			t.Fatalf("%s counter moved backwards on reopen: %d, %v; want %d", dataset, got, err, want)
		}
	}
	at := time.Unix(1, 0)
	if err := st.InsertQueryBatch(ctx, []QueryEvent{{Time: at, Domain: "new.example", QType: "A", Action: ActionAllowed}}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordDecision(ctx, Decision{ID: "new", Time: at, Subject: evidence.Domain("new.example"), Action: ActionBlocked}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertFindings(ctx, []Finding{{ID: "new", Time: at, EventType: "fixture", Severity: "low"}}); err != nil {
		t.Fatal(err)
	}
	for dataset, previous := range boundaries {
		got, err := st.ExportHighWater(ctx, dataset)
		if err != nil || got != previous+1 {
			t.Fatalf("%s did not advance past pruned insertion: %d, %v", dataset, got, err)
		}
	}
	queries, _, err := st.ListQueries(ctx, QueryFilter{ExactDomain: "new.example", Limit: 10})
	if err != nil || len(queries) != 1 || queries[0].ID != 32 {
		t.Fatalf("query id was reused after pruning: %+v %v", queries, err)
	}
	upper := int64(2)
	decisions, _, err := st.ListDecisionsPage(ctx, DecisionFilter{MaxInsertionID: &upper})
	if err != nil || len(decisions) != 1 || decisions[0].ID != "legacy" {
		t.Fatalf("late decision entered old snapshot: %+v %v", decisions, err)
	}
	findings, _, err := st.ListFindings(ctx, FindingFilter{MaxInsertionID: &upper})
	if err != nil || len(findings) != 1 || findings[0].ID != "legacy" {
		t.Fatalf("late finding entered old snapshot: %+v %v", findings, err)
	}
	// Old binaries insert without specifying the ID. The compatibility trigger
	// must keep their query IDs monotonic even if every retained row is gone.
	if _, err := st.DB().Exec(`DELETE FROM query_log;
		INSERT INTO query_log(ts, qname, qtype, action) VALUES (1000, 'old-writer.example', 'A', 'allowed')`); err != nil {
		t.Fatal(err)
	}
	queries, _, err = st.ListQueries(ctx, QueryFilter{Limit: 10})
	if err != nil || len(queries) != 1 || queries[0].ID != 33 {
		t.Fatalf("legacy writer reused an exported ID: %+v %v", queries, err)
	}
}
