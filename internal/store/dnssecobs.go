package store

import (
	"context"
	"database/sql"
	"time"
)

// DNSSECObservation is one local Daddybound verdict about one query.
//
// Stored, reported and never acted upon. Observe mode exists to collect
// evidence about what a local validator concludes on real traffic; nothing in
// DNS Daddy reads these rows to decide anything. See
// docs/decisions/0002-daddybound-observe-mode.md.
type DNSSECObservation struct {
	ID     string    `json:"id"`
	Time   time.Time `json:"time"`
	Domain string    `json:"domain"`
	QType  string    `json:"qtype"`
	Cached bool      `json:"cached"`
	// Upstream is what the upstream resolver asserted for the same query.
	// A separate fact from Status, and never merged with it.
	Upstream string `json:"upstream,omitempty"`
	// Status is the local verdict or the operational outcome.
	Status     string  `json:"status"`
	ReasonCode string  `json:"reasonCode,omitempty"`
	Reason     string  `json:"reason,omitempty"`
	DurationMS float64 `json:"durationMs"`
	// Disagreement names how the local and upstream views differ, or is empty
	// when they are consistent or not comparable.
	Disagreement string `json:"disagreement,omitempty"`
}

// InsertDNSSECObservations writes a batch.
//
// Batched and called from a background writer, never from the answer path.
// ON CONFLICT DO NOTHING because the id is the correlation key: a retry that
// wrote the same observation twice would double-count it in every summary.
func (s *Store) InsertDNSSECObservations(ctx context.Context, rows []DNSSECObservation) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // committed below on success

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO dnssec_observations
		    (id, ts, qname, qtype, cached, upstream, status, reason_code, reason,
		     duration_ms, disagreement)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, o := range rows {
		if _, err := stmt.ExecContext(ctx, o.ID, unixMilli(o.Time), o.Domain, o.QType,
			boolToInt(o.Cached), o.Upstream, o.Status, o.ReasonCode, o.Reason,
			o.DurationMS, o.Disagreement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DNSSECObservationSummary aggregates what local validation has concluded.
type DNSSECObservationSummary struct {
	// Total is how many observations are stored within the window.
	Total int64 `json:"total"`
	// ByStatus counts each recorded status.
	ByStatus map[string]int64 `json:"byStatus"`
	// Disagreements counts each disagreement class.
	Disagreements map[string]int64 `json:"disagreements"`
	// Matrix cross-tabulates the upstream's assertion against the local
	// verdict, which is the evidence this milestone exists to produce.
	Matrix []DNSSECObservationCell `json:"matrix"`
	// AvgDurationMS is the mean observation time.
	AvgDurationMS float64 `json:"avgDurationMs"`
	// P95DurationMS is the 95th percentile, computed over the window.
	P95DurationMS float64 `json:"p95DurationMs"`
}

// DNSSECObservationCell is one cell of the upstream-versus-local matrix.
type DNSSECObservationCell struct {
	Upstream string `json:"upstream"`
	Local    string `json:"local"`
	Count    int64  `json:"count"`
}

// DNSSECObservationSummarySince aggregates observations newer than since.
func (s *Store) DNSSECObservationSummarySince(ctx context.Context, since time.Time) (DNSSECObservationSummary, error) {
	out := DNSSECObservationSummary{
		ByStatus:      map[string]int64{},
		Disagreements: map[string]int64{},
	}
	cutoff := unixMilli(since)

	rows, err := s.db.QueryContext(ctx, `
		SELECT upstream, status, disagreement, COUNT(*)
		FROM dnssec_observations WHERE ts >= ?
		GROUP BY upstream, status, disagreement`, cutoff)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	for rows.Next() {
		var upstream, status, disagreement string
		var n int64
		if err := rows.Scan(&upstream, &status, &disagreement, &n); err != nil {
			return out, err
		}
		out.Total += n
		out.ByStatus[status] += n
		if disagreement != "" {
			out.Disagreements[disagreement] += n
		}
		out.Matrix = append(out.Matrix, DNSSECObservationCell{
			Upstream: upstream, Local: status, Count: n,
		})
	}
	if err := rows.Err(); err != nil {
		return out, err
	}

	// Latency separately. AVG is cheap; the percentile is computed by
	// offsetting into the ordered set rather than loading every row, so this
	// stays a bounded query on a table that grows with traffic.
	if out.Total > 0 {
		if err := s.db.QueryRowContext(ctx,
			`SELECT AVG(duration_ms) FROM dnssec_observations WHERE ts >= ?`, cutoff,
		).Scan(&out.AvgDurationMS); err != nil && err != sql.ErrNoRows {
			return out, err
		}
		offset := out.Total * 95 / 100
		if offset >= out.Total {
			offset = out.Total - 1
		}
		if err := s.db.QueryRowContext(ctx,
			`SELECT duration_ms FROM dnssec_observations WHERE ts >= ?
			 ORDER BY duration_ms LIMIT 1 OFFSET ?`, cutoff, offset,
		).Scan(&out.P95DurationMS); err != nil && err != sql.ErrNoRows {
			return out, err
		}
	}
	return out, nil
}

// DNSSECObservationFilter selects observations to list.
type DNSSECObservationFilter struct {
	// Status, when set, keeps only that status.
	Status string
	// DisagreementsOnly keeps only rows where local and upstream differ,
	// which is what an operator investigating this feature actually wants.
	DisagreementsOnly bool
	Limit             int
}

// ListDNSSECObservations returns recent observations, newest first.
func (s *Store) ListDNSSECObservations(ctx context.Context, f DNSSECObservationFilter) ([]DNSSECObservation, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	q := `SELECT id, ts, qname, qtype, cached, upstream, status, reason_code, reason,
	             duration_ms, disagreement
	      FROM dnssec_observations WHERE 1=1`
	var args []any
	if f.Status != "" {
		q += " AND status = ?"
		args = append(args, f.Status)
	}
	if f.DisagreementsOnly {
		q += " AND disagreement <> ''"
	}
	q += " ORDER BY ts DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []DNSSECObservation{}
	for rows.Next() {
		var (
			o      DNSSECObservation
			ts     int64
			cached int
		)
		if err := rows.Scan(&o.ID, &ts, &o.Domain, &o.QType, &cached, &o.Upstream,
			&o.Status, &o.ReasonCode, &o.Reason, &o.DurationMS, &o.Disagreement); err != nil {
			return nil, err
		}
		o.Time = time.UnixMilli(ts).UTC()
		o.Cached = cached != 0
		out = append(out, o)
	}
	return out, rows.Err()
}

// DNSSECObservationsByID fetches observations for a set of correlation ids.
//
// Used to attach a local verdict to query-log rows. Ids that have no
// observation are simply absent from the result: an observation may have been
// dropped when the queue was full, or may not have finished yet.
func (s *Store) DNSSECObservationsByID(ctx context.Context, ids []string) (map[string]DNSSECObservation, error) {
	out := map[string]DNSSECObservation{}
	if len(ids) == 0 {
		return out, nil
	}
	// Chunked so a page of query-log rows cannot build a statement with more
	// placeholders than SQLite accepts.
	const chunk = 200
	for start := 0; start < len(ids); start += chunk {
		end := min(start+chunk, len(ids))
		batch := ids[start:end]

		q := `SELECT id, ts, qname, qtype, cached, upstream, status, reason_code, reason,
		             duration_ms, disagreement
		      FROM dnssec_observations WHERE id IN (` + placeholders(len(batch)) + `)`
		args := make([]any, len(batch))
		for i, id := range batch {
			args[i] = id
		}
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var (
				o      DNSSECObservation
				ts     int64
				cached int
			)
			if err := rows.Scan(&o.ID, &ts, &o.Domain, &o.QType, &cached, &o.Upstream,
				&o.Status, &o.ReasonCode, &o.Reason, &o.DurationMS, &o.Disagreement); err != nil {
				rows.Close()
				return nil, err
			}
			o.Time = time.UnixMilli(ts).UTC()
			o.Cached = cached != 0
			out[o.ID] = o
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// PruneDNSSECObservations deletes observations older than before.
//
// Observations follow the query log's retention rather than accumulating
// forever: they describe the same traffic, and an operator who set a short
// retention window did so for a reason.
func (s *Store) PruneDNSSECObservations(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM dnssec_observations WHERE ts < ?`, unixMilli(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, n*2-1)
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(b)
}
