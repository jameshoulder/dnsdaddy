package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Finding is a stored behavioural security finding.
//
// The columns are the fields worth filtering and sorting on; Detail holds the
// complete finding document as JSON. That split is deliberate: the detection
// engine's finding format will grow — new signals, new evidence, new
// techniques — and none of that should require a schema change. What an
// operator queries on is stable and indexed; what they read is whole.
type Finding struct {
	ID         string    `json:"id"`
	Time       time.Time `json:"time"`
	EventType  string    `json:"eventType"`
	Severity   string    `json:"severity"`
	Confidence float64   `json:"confidence"`
	Score      float64   `json:"score"`
	ClientIP   string    `json:"clientIp,omitempty"`
	ClientName string    `json:"clientName,omitempty"`
	NetworkID  string    `json:"networkId,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	QType      string    `json:"qtype,omitempty"`
	Detector   string    `json:"detector"`
	Title      string    `json:"title"`
	Summary    string    `json:"summary"`
	// Detail is the full finding document. It is stored and returned as raw
	// JSON so the API can hand it back without re-encoding, and so a schema
	// version the running binary predates still round-trips intact.
	Detail string `json:"-"`
}

// FindingFilter narrows a findings query.
type FindingFilter struct {
	Severity  string
	EventType string
	ClientIP  string
	Domain    string
	Since     time.Time
	Until     time.Time
	Limit     int
	// Cursor pages backwards through time; pass the previous page's last
	// timestamp-and-id cursor.
	Cursor string
}

// InsertFindings writes a batch of findings.
//
// Insert-or-ignore on the primary key: findings carry random IDs, so a
// collision means the same finding is being written twice — which can happen
// if a sink is retried — and silently keeping the first is the right outcome.
func (s *Store) InsertFindings(ctx context.Context, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after a successful commit is a no-op

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO findings
			(id, ts, event_type, severity, confidence, score, client_ip, client_name,
			 network_id, domain, qtype, detector, title, summary, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		if _, err := stmt.ExecContext(ctx, f.ID, unixMilli(f.Time), f.EventType, f.Severity,
			f.Confidence, f.Score, f.ClientIP, f.ClientName, f.NetworkID, f.Domain,
			f.QType, f.Detector, f.Title, f.Summary, f.Detail); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListFindings returns findings newest first.
func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]Finding, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	where := []string{"1 = 1"}
	args := []any{}

	if f.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, strings.ToLower(f.Severity))
	}
	if f.EventType != "" {
		where = append(where, "event_type = ?")
		args = append(args, f.EventType)
	}
	if f.ClientIP != "" {
		where = append(where, "client_ip = ?")
		args = append(args, f.ClientIP)
	}
	if d := strings.TrimSpace(f.Domain); d != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+strings.ToLower(d)+"%")
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, unixMilli(f.Since))
	}
	if !f.Until.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, unixMilli(f.Until))
	}
	args = append(args, limit)

	// #nosec G202 -- where holds only hardcoded predicate fragments
	// ("severity = ?"); every filter value is bound as a parameter in args.
	q := `SELECT id, ts, event_type, severity, confidence, score, client_ip, client_name,
	             network_id, domain, qtype, detector, title, summary, detail
	      FROM findings WHERE ` + strings.Join(where, " AND ") + `
	      ORDER BY ts DESC, id DESC LIMIT ?`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Finding, 0, limit)
	for rows.Next() {
		var (
			f  Finding
			ts int64
		)
		if err := rows.Scan(&f.ID, &ts, &f.EventType, &f.Severity, &f.Confidence, &f.Score,
			&f.ClientIP, &f.ClientName, &f.NetworkID, &f.Domain, &f.QType, &f.Detector,
			&f.Title, &f.Summary, &f.Detail); err != nil {
			return nil, err
		}
		f.Time = fromUnixMilli(ts)
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetFinding returns one finding by ID.
func (s *Store) GetFinding(ctx context.Context, id string) (Finding, error) {
	var (
		f  Finding
		ts int64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, ts, event_type, severity, confidence, score, client_ip, client_name,
		       network_id, domain, qtype, detector, title, summary, detail
		FROM findings WHERE id = ?`, id).
		Scan(&f.ID, &ts, &f.EventType, &f.Severity, &f.Confidence, &f.Score,
			&f.ClientIP, &f.ClientName, &f.NetworkID, &f.Domain, &f.QType, &f.Detector,
			&f.Title, &f.Summary, &f.Detail)
	if err == sql.ErrNoRows {
		return Finding{}, ErrNotFound
	}
	if err != nil {
		return Finding{}, err
	}
	f.Time = fromUnixMilli(ts)
	return f, nil
}

// FindingSummary counts findings by type and severity over a window.
type FindingSummary struct {
	EventType string `json:"eventType"`
	Severity  string `json:"severity"`
	Count     int64  `json:"count"`
}

// SummariseFindings groups findings since t.
func (s *Store) SummariseFindings(ctx context.Context, t time.Time) ([]FindingSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_type, severity, COUNT(*)
		FROM findings WHERE ts >= ?
		GROUP BY event_type, severity
		ORDER BY event_type, severity`, unixMilli(t))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FindingSummary
	for rows.Next() {
		var fs FindingSummary
		if err := rows.Scan(&fs.EventType, &fs.Severity, &fs.Count); err != nil {
			return nil, err
		}
		out = append(out, fs)
	}
	return out, rows.Err()
}

// CountFindings returns how many findings are stored.
func (s *Store) CountFindings(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings").Scan(&n)
	return n, err
}

// PruneFindings deletes findings older than retentionDays.
//
// Findings are kept longer than the raw query log by default, because the
// question they answer — "has this host done this before?" — is a
// months-scale question, and a finding is a few kilobytes where the traffic
// behind it was thousands of rows.
func (s *Store) PruneFindings(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := unixMilli(time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour))
	res, err := s.db.ExecContext(ctx, "DELETE FROM findings WHERE ts < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune findings: %w", err)
	}
	return res.RowsAffected()
}
