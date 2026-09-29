package store

import (
	"context"
	"database/sql"
	"fmt"
)

// migrateExportSequences assigns retained records an insertion position once
// and then keeps a counter that pruning cannot move backwards. SQLite's plain
// rowid can be reused after deleting the highest row, so MAX(rowid) is not a
// stable snapshot boundary for a multi-request export.
//
// Existing query IDs, decision IDs and evidence are unchanged. The two text-ID
// tables receive an internal sequence column; query_log keeps its existing
// numeric ID. This avoids rebuilding a large query table or retaining a second
// per-query ledger. The migration is transactional and does not scan retained
// data on later starts.
func migrateExportSequences(db *sql.DB) error {
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin export sequence migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS export_sequences (
		dataset TEXT PRIMARY KEY,
		value INTEGER NOT NULL CHECK(typeof(value) = 'integer' AND value >= 0)
	)`); err != nil {
		return fmt.Errorf("create export sequences: %w", err)
	}
	for _, migration := range []struct {
		dataset, table, addColumn, backfill, initial, trigger string
	}{
		{
			dataset: "queries", table: "query_log",
			initial: `SELECT COALESCE(MAX(id), 0) FROM query_log`,
			trigger: `CREATE TRIGGER IF NOT EXISTS query_log_export_sequence AFTER INSERT ON query_log
			BEGIN
				UPDATE export_sequences SET value = MAX(value + 1, NEW.id) WHERE dataset = 'queries';
				UPDATE query_log SET id = (SELECT value FROM export_sequences WHERE dataset = 'queries')
				 WHERE id = NEW.id AND id < (SELECT value FROM export_sequences WHERE dataset = 'queries');
			END`,
		},
		{
			dataset: "decisions", table: "decisions",
			addColumn: `ALTER TABLE decisions ADD COLUMN insertion_seq INTEGER NOT NULL DEFAULT 0`,
			backfill:  `UPDATE decisions SET insertion_seq = rowid`,
			initial:   `SELECT COALESCE(MAX(insertion_seq), 0) FROM decisions`,
			trigger: `CREATE TRIGGER IF NOT EXISTS decisions_export_sequence AFTER INSERT ON decisions
			BEGIN
				UPDATE export_sequences SET value = value + 1 WHERE dataset = 'decisions';
				UPDATE decisions SET insertion_seq = (SELECT value FROM export_sequences WHERE dataset = 'decisions')
				 WHERE rowid = NEW.rowid;
			END`,
		},
		{
			dataset: "findings", table: "findings",
			addColumn: `ALTER TABLE findings ADD COLUMN insertion_seq INTEGER NOT NULL DEFAULT 0`,
			backfill:  `UPDATE findings SET insertion_seq = rowid`,
			initial:   `SELECT COALESCE(MAX(insertion_seq), 0) FROM findings`,
			trigger: `CREATE TRIGGER IF NOT EXISTS findings_export_sequence AFTER INSERT ON findings
			BEGIN
				UPDATE export_sequences SET value = value + 1 WHERE dataset = 'findings';
				UPDATE findings SET insertion_seq = (SELECT value FROM export_sequences WHERE dataset = 'findings')
				 WHERE rowid = NEW.rowid;
			END`,
		},
	} {
		if migration.addColumn != "" {
			var present int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = 'insertion_seq'`, migration.table).Scan(&present); err != nil {
				return fmt.Errorf("inspect %s export column: %w", migration.dataset, err)
			}
			if present == 0 {
				if _, err := tx.ExecContext(ctx, migration.addColumn); err != nil {
					return fmt.Errorf("add %s export column: %w", migration.dataset, err)
				}
				if _, err := tx.ExecContext(ctx, migration.backfill); err != nil {
					return fmt.Errorf("assign retained %s insertion positions: %w", migration.dataset, err)
				}
			}
		}
		var present int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM export_sequences WHERE dataset = ?`, migration.dataset).Scan(&present); err != nil {
			return fmt.Errorf("inspect %s export sequence: %w", migration.dataset, err)
		}
		if present == 0 {
			var initial int64
			if err := tx.QueryRowContext(ctx, migration.initial).Scan(&initial); err != nil {
				return fmt.Errorf("read retained %s insertion boundary: %w", migration.dataset, err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO export_sequences(dataset, value) VALUES (?, ?)`, migration.dataset, max(initial, 0)); err != nil {
				return fmt.Errorf("initialize %s export sequence: %w", migration.dataset, err)
			}
		}
		if _, err := tx.ExecContext(ctx, migration.trigger); err != nil {
			return fmt.Errorf("maintain %s export sequence: %w", migration.dataset, err)
		}
	}
	return tx.Commit()
}
