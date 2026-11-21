package store

import (
	"database/sql"
	"fmt"
)

// migrateDomainFirstSeen creates the retention-independent registered-domain
// index on upgrades. CREATE TABLE IF NOT EXISTS is enough: new columns are not
// expected, and the table is additive.
func migrateDomainFirstSeen(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS domain_first_seen (
			registered_domain TEXT    PRIMARY KEY,
			first_seen        INTEGER NOT NULL,
			last_seen         INTEGER NOT NULL,
			query_count       INTEGER NOT NULL DEFAULT 1
		)`); err != nil {
		return fmt.Errorf("migrate domain_first_seen: %w", err)
	}
	if _, err := db.Exec(`
		CREATE INDEX IF NOT EXISTS domain_first_seen_last_idx
			ON domain_first_seen (last_seen DESC)`); err != nil {
		return fmt.Errorf("index domain_first_seen: %w", err)
	}
	return nil
}
