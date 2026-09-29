package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
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
	// Cursor continues a previous page: pass the NextCursor that page
	// returned. Empty starts from the beginning. A cursor that does not
	// parse is ErrInvalidCursor rather than a silent restart, because a
	// consumer that restarted from the top without noticing would re-ingest
	// every finding it already had.
	Cursor string
	// Ascending walks oldest first. The default, newest first, is what a
	// dashboard wants; the export walks forward so that a consumer can keep
	// the last cursor and pick up exactly where it left off.
	Ascending bool
	// State, when set, keeps only findings whose review is in that state.
	// "new" matches findings with no review row as well as those returned
	// to new.
	State string
	// MaxInsertionID freezes the insertion boundary of an export; nil is a live list.
	MaxInsertionID *int64
}

// ErrInvalidCursor reports a continuation cursor this store did not issue.
var ErrInvalidCursor = errors.New("invalid cursor")

// findingCursor is the keyset position: the (ts, id) of the last row served.
//
// Keyset rather than offset, for the two properties an export needs. A row
// inserted while a consumer is paging — the detection engine writes
// continuously — shifts every offset and either repeats or skips a row at the
// page boundary; a keyset predicate is a fixed point in the (ts, id) order and
// does neither. And two findings written in the same millisecond, which a
// batch does, have a stable order between them because id is the tie-break.
type findingCursor struct {
	ts int64
	id string
}

// encodeCursor renders a position as the opaque string a client hands back.
func encodeCursor(c findingCursor) string {
	return strconv.FormatInt(c.ts, 10) + ":" + c.id
}

// parseCursor reads a cursor, refusing anything this package would not have
// produced.
func parseCursor(raw string) (findingCursor, error) {
	raw = strings.TrimSpace(raw)
	i := strings.IndexByte(raw, ':')
	if i <= 0 || i == len(raw)-1 {
		return findingCursor{}, ErrInvalidCursor
	}
	ts, err := strconv.ParseInt(raw[:i], 10, 64)
	if err != nil || ts < 0 {
		return findingCursor{}, ErrInvalidCursor
	}
	id := raw[i+1:]
	if len(id) > 128 {
		return findingCursor{}, ErrInvalidCursor
	}
	return findingCursor{ts: ts, id: id}, nil
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

// ListFindings returns one page of findings and the cursor for the next.
//
// Newest first unless f.Ascending. The returned cursor is empty when the page
// was the last one; otherwise it names the position after the last row
// returned, and passing it back in f.Cursor continues from there with no row
// repeated and none skipped, whatever is inserted in between.
func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]Finding, string, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	where := []string{"1 = 1"}
	args := []any{}

	if f.Cursor != "" {
		c, err := parseCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		// The keyset predicate, in the direction of travel. Both halves are
		// bound: (ts, id) is a total order because id is unique.
		if f.Ascending {
			where = append(where, "(ts > ? OR (ts = ? AND id > ?))")
		} else {
			where = append(where, "(ts < ? OR (ts = ? AND id < ?))")
		}
		args = append(args, c.ts, c.ts, c.id)
	}

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
	if f.State != "" {
		// A LEFT JOIN so "new" reaches findings that have never been
		// reviewed. The join key is the primary key on both sides, so the
		// cost is one lookup per candidate row.
		where = append(where, "COALESCE(r.state, ?) = ?")
		args = append(args, ReviewNew, f.State)
	}
	if f.MaxInsertionID != nil {
		where = append(where, "findings.insertion_seq <= ?")
		args = append(args, *f.MaxInsertionID)
	}
	// One more than the page, so "is there another page" is answered by
	// the same query rather than by a count that a concurrent insert could
	// make wrong.
	args = append(args, limit+1)

	order := "ts DESC, id DESC"
	if f.Ascending {
		order = "ts ASC, id ASC"
	}

	// #nosec G202 -- where holds only hardcoded predicate fragments
	// ("severity = ?") and order is one of two literals above; every filter
	// value is bound as a parameter in args.
	q := `SELECT id, ts, event_type, severity, confidence, score, client_ip, client_name,
	             network_id, domain, qtype, detector, title, summary, detail
	      FROM findings LEFT JOIN finding_reviews r ON r.finding_id = findings.id
	      WHERE ` + strings.Join(where, " AND ") + `
	      ORDER BY ` + order + ` LIMIT ?`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	out := make([]Finding, 0, limit)
	var lastTS int64
	for rows.Next() {
		var (
			f  Finding
			ts int64
		)
		if err := rows.Scan(&f.ID, &ts, &f.EventType, &f.Severity, &f.Confidence, &f.Score,
			&f.ClientIP, &f.ClientName, &f.NetworkID, &f.Domain, &f.QType, &f.Detector,
			&f.Title, &f.Summary, &f.Detail); err != nil {
			return nil, "", err
		}
		f.Time = fromUnixMilli(ts)
		if len(out) == limit {
			// The extra row exists, so there is a next page. It is not
			// returned; the cursor points just past the last row that is.
			return out, encodeCursor(findingCursor{ts: lastTS, id: out[len(out)-1].ID}), rows.Err()
		}
		out = append(out, f)
		lastTS = ts
	}
	return out, "", rows.Err()
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
