// Package store is DNS Daddy's persistence layer: a single SQLite database
// holding configuration, query logs, and pre-aggregated statistics.
//
// SQLite is a deliberate choice for the reference deployment. On a 1 GB VPS a
// separate database server would cost more RAM than the resolver itself, and
// the write pattern here — batched appends from one process — is exactly what
// SQLite in WAL mode is good at.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver: no cgo, so the binary stays static
)

//go:embed schema.sql
var schemaSQL string

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// Store owns the database handle.
type Store struct {
	db *sql.DB

	// localFeedDir is the only directory a file:// feed may read from. Empty
	// (the default) rejects file:// feeds outright. Set once at startup from
	// the config, before any request is served.
	localFeedDir string
}

// SetLocalFeedDir confines file:// feed URLs to dir. Call it during startup;
// an empty dir leaves file:// feeds disabled.
func (s *Store) SetLocalFeedDir(dir string) { s.localFeedDir = dir }

// LocalFeedDir returns the directory file:// feeds are confined to.
func (s *Store) LocalFeedDir() string { return s.localFeedDir }

// Open opens (creating if necessary) the database at path, applies the schema,
// and seeds first-run defaults.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// modernc's driver serialises access per connection; a small pool keeps
	// memory flat and avoids SQLITE_BUSY storms on a single-vCPU box.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	s := &Store{db: db}
	if err := s.seed(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("seed defaults: %w", err)
	}
	return s, nil
}

// OpenReadOnly opens an existing database for inspection, and changes nothing.
//
// Open is the wrong tool for a diagnostic. It applies the schema, runs
// migrations, seeds first-run defaults and switches journalling to WAL — all
// correct for the daemon that owns the database, and all of it a modification
// made by a command whose whole promise is that it makes none. Running a newer
// binary's `dnsdaddy doctor` against an older live deployment would have
// migrated it.
//
// Two independent guarantees, because one of them is a pragma the driver could
// in principle ignore:
//
//	mode=ro     SQLite opens the file read-only and never creates it, so a
//	            mistyped data_dir reports "no database" instead of quietly
//	            manufacturing an empty one.
//	query_only  any statement that would write fails rather than being
//	            attempted.
//
// journal_mode is deliberately not set. Setting it writes to the database
// header, which is precisely the mutation being avoided; the mode already
// recorded in the file is used as-is, and a WAL database opened this way reads
// correctly both while the daemon holds it open and after a clean shutdown.
func OpenReadOnly(path string) (*Store, error) {
	// Checked before the DSN is built so the error names the real problem.
	// mode=ro would report "unable to open database file", which is true of a
	// permissions fault and a missing file alike.
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("open sqlite read-only: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(true)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite read-only: %w", err)
	}

	// A diagnostic issues a handful of queries and exits. Two connections is
	// ample, and keeps it out of the way of a daemon that is serving.
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite read-only: %w", err)
	}

	// No schema, no migrations, no seeding. If the database predates a column
	// this binary knows about, a query naming it fails and the caller reports
	// that — which is the honest outcome, and better than silently upgrading
	// a deployment somebody was only trying to inspect.
	return &Store{db: db}, nil
}

// addedColumns are columns introduced after the initial release.
//
// schema.sql is applied with CREATE TABLE IF NOT EXISTS, which does exactly
// the right thing for a new table and nothing at all for a new column on a
// table that already exists. SQLite has no ADD COLUMN IF NOT EXISTS, so the
// statement is run unconditionally and the "duplicate column" error is treated
// as success.
//
// Deliberately the whole migration story: every column added here has a
// default, so an upgrade is a no-op for existing rows and a downgrade to the
// previous binary still reads the database. That is a lot cheaper to keep
// correct on a self-hosted tool than a versioned migration runner, and it
// means an operator can roll back a bad release by swapping the binary.
var addedColumns = []struct{ table, column, definition string }{
	// DNSSEC validation status as reported by the upstream. See
	// docs/dnssec.md for what each value can and cannot tell you.
	{"query_log", "dnssec", "TEXT NOT NULL DEFAULT ''"},
	// When a feed last downloaded successfully, as opposed to when it was last
	// attempted. last_refreshed_at moves on a failure too, so on its own it
	// cannot answer the question an operator actually asks of a feed that is
	// erroring: how old is the intelligence still being enforced.
	{"feeds", "last_success_at", "INTEGER"},
}

func migrate(db *sql.DB) error {
	for _, c := range addedColumns {
		stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", c.table, c.column, c.definition)
		if _, err := db.Exec(stmt); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
				continue // already applied
			}
			return fmt.Errorf("migrate %s.%s: %w", c.table, c.column, err)
		}
	}
	return nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the underlying handle for maintenance tasks.
func (s *Store) DB() *sql.DB { return s.db }

// Vacuum reclaims disk space after a retention prune.
func (s *Store) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "PRAGMA incremental_vacuum")
	return err
}

func unixMilli(t time.Time) int64 { return t.UnixMilli() }

func fromUnixMilli(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

func encodeJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeStrings(raw string) []string {
	var out []string
	if raw == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}
