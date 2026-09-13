package store

import (
	"context"
	"fmt"
	"time"
)

// AuditEntry is one recorded configuration change, already redacted.
//
// Before and After are JSON strings rather than structured values because the
// shape differs per action and the audit log's job is to preserve what was
// written, not to model it. They are redacted by internal/audit before they
// reach here; nothing in this package inspects them.
type AuditEntry struct {
	ID         string    `json:"id"`
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	ActorKind  string    `json:"actorKind"`
	Action     string    `json:"action"`
	TargetType string    `json:"targetType,omitempty"`
	TargetID   string    `json:"targetId,omitempty"`
	Before     string    `json:"before,omitempty"`
	After      string    `json:"after,omitempty"`
	Source     string    `json:"source,omitempty"`
}

// RecordAudit appends one entry.
func (s *Store) RecordAudit(ctx context.Context, e AuditEntry) error {
	if e.ID == "" {
		e.ID = NewID("aud")
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log
			(id, ts, actor, actor_kind, action, target_type, target_id, before_json, after_json, source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, unixMilli(e.Time), e.Actor, e.ActorKind, e.Action,
		e.TargetType, e.TargetID, e.Before, e.After, e.Source)
	if err != nil {
		return fmt.Errorf("record audit entry: %w", err)
	}
	return nil
}

// RecordAuditBatch appends several entries in one transaction.
//
// One transaction rather than several, because SQLite takes one writer at a
// time and every transaction this process opens is a chance to collide with
// the management mutation that produced these entries.
func (s *Store) RecordAuditBatch(ctx context.Context, entries []AuditEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // committed below on the happy path

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO audit_log
			(id, ts, actor, actor_kind, action, target_type, target_id, before_json, after_json, source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range entries {
		if e.ID == "" {
			e.ID = NewID("aud")
		}
		if e.Time.IsZero() {
			e.Time = time.Now().UTC()
		}
		if _, err := stmt.ExecContext(ctx, e.ID, unixMilli(e.Time), e.Actor, e.ActorKind,
			e.Action, e.TargetType, e.TargetID, e.Before, e.After, e.Source); err != nil {
			return fmt.Errorf("record audit entries: %w", err)
		}
	}
	return tx.Commit()
}

// AuditFilter bounds an audit listing.
type AuditFilter struct {
	Action     string
	TargetType string
	TargetID   string
	Limit      int
}

// maxAuditPage bounds a listing however much a caller asks for.
const maxAuditPage = 500

// ListAudit returns recent entries, newest first.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	limit := f.Limit
	if limit <= 0 || limit > maxAuditPage {
		limit = 100
	}
	q := `SELECT id, ts, actor, actor_kind, action, target_type, target_id,
	             before_json, after_json, source
	        FROM audit_log WHERE 1=1`
	args := []any{}
	if f.Action != "" {
		q += ` AND action = ?`
		args = append(args, f.Action)
	}
	if f.TargetType != "" {
		q += ` AND target_type = ?`
		args = append(args, f.TargetType)
	}
	if f.TargetID != "" {
		q += ` AND target_id = ?`
		args = append(args, f.TargetID)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AuditEntry, 0, 16)
	for rows.Next() {
		var (
			e  AuditEntry
			ts int64
		)
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.ActorKind, &e.Action,
			&e.TargetType, &e.TargetID, &e.Before, &e.After, &e.Source); err != nil {
			return nil, err
		}
		e.Time = fromUnixMilli(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountAudit reports how many entries are held.
func (s *Store) CountAudit(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&n)
	return n, err
}

// PruneAudit deletes entries older than cutoff and returns how many went.
//
// Its own statement and its own retention, deliberately separate from the
// query-log pruner. The two answer different questions over different
// timescales — who changed the configuration, versus who resolved what — and
// an operator who shortened their query-log retention for privacy reasons has
// said nothing about how long they want to keep a record of policy edits.
func (s *Store) PruneAudit(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE ts < ?`, unixMilli(cutoff))
	if err != nil {
		return 0, fmt.Errorf("prune audit_log: %w", err)
	}
	return res.RowsAffected()
}

// LastAuditAt returns when the most recent entry was written, or the zero
// time when there are none.
func (s *Store) LastAuditAt(ctx context.Context) (time.Time, error) {
	var ts *int64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(ts) FROM audit_log`).Scan(&ts); err != nil {
		return time.Time{}, err
	}
	if ts == nil {
		return time.Time{}, nil
	}
	return fromUnixMilli(*ts), nil
}
