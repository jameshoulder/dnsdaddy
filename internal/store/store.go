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

	s := &Store{db: db}
	if err := s.seed(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("seed defaults: %w", err)
	}
	return s, nil
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
