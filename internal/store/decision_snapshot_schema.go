package store

import (
	"database/sql"
	"fmt"
)

// migrateDecisionSnapshots adds an append-only copy of the evidence presented
// to RecordDecision. It intentionally does not backfill old decisions: the
// current evidence row cannot reconstruct what an earlier decision saw.
func migrateDecisionSnapshots(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS decision_evidence_captures (
			decision_id TEXT PRIMARY KEY REFERENCES decisions(id) ON DELETE CASCADE,
			evidence_count INTEGER NOT NULL CHECK(evidence_count >= 0)
		);
		CREATE TABLE IF NOT EXISTS decision_evidence_snapshots (
			decision_id TEXT NOT NULL REFERENCES decisions(id) ON DELETE CASCADE,
			evidence_id TEXT NOT NULL,
			contributed INTEGER NOT NULL,
			snapshot TEXT NOT NULL,
			PRIMARY KEY(decision_id, evidence_id)
		);
	`)
	if err != nil {
		return fmt.Errorf("create decision evidence snapshots: %w", err)
	}
	return nil
}
