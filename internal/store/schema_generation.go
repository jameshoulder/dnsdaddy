package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// SchemaGeneration is the highest schema generation this binary understands.
//
// Additive column/table migrations keep prior binaries working historically.
// When a future change is incompatible with older binaries, bump this value
// and document the boundary. Already-published binaries that lack this check
// are not retroactively protected — operators must use backup/restore rather
// than assuming a blind downgrade is safe.
const SchemaGeneration = 1

const schemaGenerationTable = `
CREATE TABLE IF NOT EXISTS schema_generation (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  generation INTEGER NOT NULL
);
`

// rejectIncompatibleSchemaGeneration refuses a database whose marker is newer
// than this binary, before any CREATE/ALTER from applySchemaAndAdminAuth runs.
// Missing tables (fresh files) are allowed.
func rejectIncompatibleSchemaGeneration(db *sql.DB) error {
	var current sql.NullInt64
	err := db.QueryRow(`SELECT generation FROM schema_generation WHERE id = 1`).Scan(&current)
	if err == nil {
		if current.Valid && current.Int64 > int64(SchemaGeneration) {
			return fmt.Errorf("database schema generation %d is newer than this binary (%d); restore a compatible snapshot or use a matching release — see docs/maturity/upgrade-recovery-rehearsal.md",
				current.Int64, SchemaGeneration)
		}
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	// SQLite reports missing tables as a plain error string.
	if strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return nil
	}
	return fmt.Errorf("read schema_generation: %w", err)
}

// migrateSchemaGeneration records and enforces the schema generation marker
// after the base schema has been applied on a compatible database.
func migrateSchemaGeneration(db *sql.DB) error {
	if _, err := db.Exec(schemaGenerationTable); err != nil {
		return fmt.Errorf("create schema_generation: %w", err)
	}
	var current sql.NullInt64
	err := db.QueryRow(`SELECT generation FROM schema_generation WHERE id = 1`).Scan(&current)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("read schema_generation: %w", err)
	}
	if err == sql.ErrNoRows {
		_, err = db.Exec(`INSERT INTO schema_generation(id, generation) VALUES (1, ?)`, SchemaGeneration)
		return err
	}
	if current.Int64 > int64(SchemaGeneration) {
		return fmt.Errorf("database schema generation %d is newer than this binary (%d); restore a compatible snapshot or use a matching release — see docs/maturity/upgrade-recovery-rehearsal.md",
			current.Int64, SchemaGeneration)
	}
	if current.Int64 < int64(SchemaGeneration) {
		_, err = db.Exec(`UPDATE schema_generation SET generation = ? WHERE id = 1`, SchemaGeneration)
		return err
	}
	return nil
}
