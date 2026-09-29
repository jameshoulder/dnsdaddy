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

	// Resolution says how the records behind this verdict were obtained:
	// "native" or "forwarded". A Secure reached through somebody else's
	// recursive resolver and a Secure reached by asking the authoritative
	// servers are not the same claim, so a row that did not say which could
	// not be interpreted at all.
	Resolution string `json:"resolution,omitempty"`
	// Queries and Delegations are what native resolution cost: questions sent
	// to authoritative servers, and zone cuts crossed. Zero for a forwarded
	// verdict.
	Queries     int `json:"queries,omitempty"`
	Delegations int `json:"delegations,omitempty"`
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
		     duration_ms, disagreement, resolution, queries, delegations)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, o := range rows {
		if _, err := stmt.ExecContext(ctx, o.ID, unixMilli(o.Time), o.Domain, o.QType,
			boolToInt(o.Cached), o.Upstream, o.Status, o.ReasonCode, o.Reason,
			o.DurationMS, o.Disagreement, o.Resolution, o.Queries, o.Delegations); err != nil {
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
	// Since, when set, keeps only rows observed at or after it — the same
	// window the summary is computed over, so a list and its summary
	// describe one population.
	Since time.Time
	Until time.Time
	// ClientIP narrows via the retained query log's exact observation ID.
	// Observations without recorded client correlation cannot be attributed.
	ClientIP string
	// Domain, when set, keeps only observations of exactly that name.
	Domain string
	Limit  int
}

// ListDNSSECObservations returns recent observations, newest first.
func (s *Store) ListDNSSECObservations(ctx context.Context, f DNSSECObservationFilter) ([]DNSSECObservation, error) {
	// 501, not 500: a caller asking for one more than it will show is how
	// the API learns whether the window holds more rows than the page.
	limit := f.Limit
	if limit <= 0 || limit > 501 {
		limit = 100
	}

	// #nosec G202 -- every fragment appended below is a string literal
	// ("AND status = ?"); the filter values are bound as parameters in args.
	q := `SELECT id, ts, qname, qtype, cached, upstream, status, reason_code, reason,
	             duration_ms, disagreement, resolution, queries, delegations
	      FROM dnssec_observations WHERE 1=1`
	var args []any
	if f.Status != "" {
		q += " AND status = ?"
		args = append(args, f.Status)
	}
	if f.DisagreementsOnly {
		q += " AND disagreement <> ''"
	}
	if !f.Since.IsZero() {
		q += " AND ts >= ?"
		args = append(args, unixMilli(f.Since))
	}
	if !f.Until.IsZero() {
		q += " AND ts <= ?"
		args = append(args, unixMilli(f.Until))
	}
	if f.ClientIP != "" {
		q += " AND EXISTS (SELECT 1 FROM query_log l WHERE l.dnssec_obs = dnssec_observations.id AND l.dnssec_obs <> '' AND l.client_ip = ?)"
		args = append(args, f.ClientIP)
	}
	if f.Domain != "" {
		q += " AND qname = ?"
		args = append(args, f.Domain)
	}
	q += " ORDER BY ts DESC, id DESC LIMIT ?"
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
			&o.Status, &o.ReasonCode, &o.Reason, &o.DurationMS, &o.Disagreement,
			&o.Resolution, &o.Queries, &o.Delegations); err != nil {
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

		// #nosec G202 -- the only thing concatenated is a run of "?" built
		// from an integer count by placeholders(); every id is bound as a
		// parameter in args below. Never append a fragment built from input.
		q := `SELECT id, ts, qname, qtype, cached, upstream, status, reason_code, reason,
		             duration_ms, disagreement, resolution, queries, delegations
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
				&o.Status, &o.ReasonCode, &o.Reason, &o.DurationMS, &o.Disagreement,
				&o.Resolution, &o.Queries, &o.Delegations); err != nil {
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

// DNSSECPopulationCell is one cell of the population breakdown: how the
// records were obtained, whether the client's answer came from cache, what
// the upstream asserted and what Daddybound concluded.
//
// Kept as the raw cross-tabulation so a reader can separate the populations
// that are comparable from those that are not. A disagreement reached
// through a forwarder is a different claim from one reached natively, and a
// disagreement about a name whose client answer was minutes old is not
// evidence about that answer at all.
type DNSSECPopulationCell struct {
	Resolution   string `json:"resolution"`
	Cached       bool   `json:"cached"`
	Upstream     string `json:"upstream"`
	Status       string `json:"status"`
	Disagreement string `json:"disagreement,omitempty"`
	Count        int64  `json:"count"`
}

// DNSSECPopulationsSince cross-tabulates stored observations in a window.
func (s *Store) DNSSECPopulationsSince(ctx context.Context, since time.Time) ([]DNSSECPopulationCell, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT resolution, cached, upstream, status, disagreement, COUNT(*)
		  FROM dnssec_observations WHERE ts >= ?
		 GROUP BY resolution, cached, upstream, status, disagreement`, unixMilli(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []DNSSECPopulationCell{}
	for rows.Next() {
		var (
			c      DNSSECPopulationCell
			cached int
		)
		if err := rows.Scan(&c.Resolution, &cached, &c.Upstream, &c.Status, &c.Disagreement, &c.Count); err != nil {
			return nil, err
		}
		c.Cached = cached != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// DNSSECObservationSpan reports the oldest and newest stored observation and
// how many there are, over everything retention has kept.
//
// Bounded reads on the ts index. "Observing since" is the honest measure of
// how long the evidence has been accumulating, and it is bounded by
// retention rather than by uptime: a restart does not shorten it, and a long
// retention setting does not lengthen it past the first row.
func (s *Store) DNSSECObservationSpan(ctx context.Context) (first, last time.Time, count int64, err error) {
	var minTS, maxTS sql.NullInt64
	err = s.db.QueryRowContext(ctx,
		`SELECT MIN(ts), MAX(ts), COUNT(*) FROM dnssec_observations`).Scan(&minTS, &maxTS, &count)
	if err != nil {
		return time.Time{}, time.Time{}, 0, err
	}
	if minTS.Valid {
		first = fromUnixMilli(minTS.Int64)
	}
	if maxTS.Valid {
		last = fromUnixMilli(maxTS.Int64)
	}
	return first, last, count, nil
}
