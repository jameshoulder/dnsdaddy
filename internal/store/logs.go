package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// InsertQueryBatch writes a batch of query events and updates the rollup
// tables in one transaction. The DNS hot path never calls this directly — the
// logger goroutine batches events so that disk latency cannot delay a
// resolution.
//
// Events with LogQueries disabled on their policy should be passed with
// persist=false by the caller; they still update rollups so the dashboard has
// counts, but no per-query row is written. That is what makes "zero-log mode"
// useful rather than blind.
func (s *Store) InsertQueryBatch(ctx context.Context, events []QueryEvent, persist bool) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if persist {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO query_log (ts, client_ip, client_name, network_id, qname, qtype,
			                       action, reason, category, source, proto, elapsed_ms, cached,
			                       dnssec)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, e := range events {
			if _, err := stmt.ExecContext(ctx, unixMilli(e.Time), e.ClientIP, e.ClientName, e.NetworkID,
				e.Domain, e.QType, e.Action, e.Reason, e.Category, e.Source, e.Proto,
				e.ElapsedMS, boolToInt(e.Cached), e.DNSSEC); err != nil {
				return err
			}
		}
	}

	if err := upsertRollups(ctx, tx, events); err != nil {
		return err
	}
	return tx.Commit()
}

type rollupKey struct {
	hour      int64
	networkID string
	category  string
}

type blockedKey struct {
	day       int64
	domain    string
	networkID string
}

func upsertRollups(ctx context.Context, tx txExecer, events []QueryEvent) error {
	// Aggregate in memory first: a 256-event batch typically collapses to a
	// handful of rows, turning 256 upserts into 5.
	counts := map[rollupKey][2]int{}
	blocked := map[blockedKey]struct {
		category string
		count    int
		lastSeen int64
	}{}

	for _, e := range events {
		hour := e.Time.UTC().Truncate(time.Hour).Unix()
		cat := e.Category
		if e.Action != ActionBlocked {
			cat = ""
		}
		k := rollupKey{hour: hour, networkID: e.NetworkID, category: cat}
		c := counts[k]
		c[0]++
		if e.Action == ActionBlocked {
			c[1]++
		}
		counts[k] = c

		if e.Action == ActionBlocked {
			day := e.Time.UTC().Truncate(24 * time.Hour).Unix()
			bk := blockedKey{day: day, domain: e.Domain, networkID: e.NetworkID}
			b := blocked[bk]
			b.category = e.Category
			b.count++
			if ms := unixMilli(e.Time); ms > b.lastSeen {
				b.lastSeen = ms
			}
			blocked[bk] = b
		}
	}

	for k, v := range counts {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO stats_hourly (hour, network_id, category, total, blocked)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(hour, network_id, category) DO UPDATE SET
				total   = total + excluded.total,
				blocked = blocked + excluded.blocked`,
			k.hour, k.networkID, k.category, v[0], v[1]); err != nil {
			return err
		}
	}

	for k, v := range blocked {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO blocked_domain_stats (day, domain, network_id, category, count, last_seen)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(day, domain, network_id) DO UPDATE SET
				count     = count + excluded.count,
				category  = excluded.category,
				last_seen = MAX(last_seen, excluded.last_seen)`,
			k.day, k.domain, k.networkID, v.category, v.count, v.lastSeen); err != nil {
			return err
		}
	}
	return nil
}

type txExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// QueryFilter narrows a query-log search.
type QueryFilter struct {
	NetworkID string
	Action    string
	Category  string
	Domain    string
	ClientIP  string
	Since     time.Time
	Until     time.Time
	Cursor    int64 // return rows with id < cursor; 0 means start at the newest
	Limit     int
}

// ListQueries returns query-log rows newest-first, plus the cursor to pass in
// for the following page (0 when the result set is exhausted).
func (s *Store) ListQueries(ctx context.Context, f QueryFilter) ([]QueryEvent, int64, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	where := []string{"1 = 1"}
	args := []any{}

	if f.NetworkID != "" {
		where = append(where, "network_id = ?")
		args = append(args, f.NetworkID)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	if f.Category != "" {
		where = append(where, "category = ?")
		args = append(args, f.Category)
	}
	if f.ClientIP != "" {
		where = append(where, "client_ip = ?")
		args = append(args, f.ClientIP)
	}
	if d := strings.TrimSpace(f.Domain); d != "" {
		where = append(where, "qname LIKE ?")
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
	if f.Cursor > 0 {
		where = append(where, "id < ?")
		args = append(args, f.Cursor)
	}
	args = append(args, limit+1)

	// #nosec G202 -- where holds only hardcoded predicate fragments
	// ("network_id = ?"); every filter value is bound as a parameter in args.
	// Never append a fragment built from input here.
	q := `SELECT id, ts, client_ip, client_name, network_id, qname, qtype, action,
	             reason, category, source, proto, elapsed_ms, cached, dnssec
	      FROM query_log WHERE ` + strings.Join(where, " AND ") + `
	      ORDER BY id DESC LIMIT ?`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]QueryEvent, 0, limit)
	for rows.Next() {
		var (
			e      QueryEvent
			ts     int64
			cached int
		)
		if err := rows.Scan(&e.ID, &ts, &e.ClientIP, &e.ClientName, &e.NetworkID, &e.Domain,
			&e.QType, &e.Action, &e.Reason, &e.Category, &e.Source, &e.Proto, &e.ElapsedMS,
			&cached, &e.DNSSEC); err != nil {
			return nil, 0, err
		}
		e.Time = fromUnixMilli(ts)
		e.Cached = cached == 1
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var next int64
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ID
	}
	return out, next, nil
}

// Totals is a queries/blocked pair over some window.
type Totals struct {
	Queries int64 `json:"queries"`
	Blocked int64 `json:"blocked"`
}

// TotalsSince sums the rollups from t to now.
func (s *Store) TotalsSince(ctx context.Context, t time.Time) (Totals, error) {
	var out Totals
	err := s.db.QueryRowContext(ctx,
		"SELECT COALESCE(SUM(total), 0), COALESCE(SUM(blocked), 0) FROM stats_hourly WHERE hour >= ?",
		t.UTC().Truncate(time.Hour).Unix()).Scan(&out.Queries, &out.Blocked)
	return out, err
}

// ActivityBucket is one hour of the query-activity chart.
type ActivityBucket struct {
	Hour    time.Time `json:"hour"`
	Label   string    `json:"label"`
	Total   int64     `json:"total"`
	Blocked int64     `json:"blocked"`
}

// QueryActivity returns per-hour totals for the last n hours, including empty
// hours so the chart has an unbroken x-axis.
func (s *Store) QueryActivity(ctx context.Context, hours int) ([]ActivityBucket, error) {
	if hours <= 0 || hours > 24*30 {
		hours = 24
	}
	start := time.Now().UTC().Truncate(time.Hour).Add(-time.Duration(hours-1) * time.Hour)

	rows, err := s.db.QueryContext(ctx, `
		SELECT hour, COALESCE(SUM(total), 0), COALESCE(SUM(blocked), 0)
		FROM stats_hourly WHERE hour >= ? GROUP BY hour`, start.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := map[int64][2]int64{}
	for rows.Next() {
		var h, total, blocked int64
		if err := rows.Scan(&h, &total, &blocked); err != nil {
			return nil, err
		}
		seen[h] = [2]int64{total, blocked}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]ActivityBucket, 0, hours)
	for i := 0; i < hours; i++ {
		h := start.Add(time.Duration(i) * time.Hour)
		v := seen[h.Unix()]
		out = append(out, ActivityBucket{
			Hour:    h,
			Label:   h.Format("15:04"),
			Total:   v[0],
			Blocked: v[1],
		})
	}
	return out, nil
}

// CategoryCount is one slice of the threats-by-category breakdown.
type CategoryCount struct {
	Category string `json:"category"`
	Label    string `json:"label"`
	Count    int64  `json:"count"`
}

// ThreatsByCategory returns blocked counts grouped by category since t.
func (s *Store) ThreatsByCategory(ctx context.Context, t time.Time) ([]CategoryCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT category, COALESCE(SUM(blocked), 0) AS n
		FROM stats_hourly
		WHERE hour >= ? AND category != '' AND blocked > 0
		GROUP BY category ORDER BY n DESC`,
		t.UTC().Truncate(time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CategoryCount
	for rows.Next() {
		var c CategoryCount
		if err := rows.Scan(&c.Category, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// TopBlocked is one row of the "most blocked domains" table.
type TopBlocked struct {
	Domain   string    `json:"domain"`
	Category string    `json:"category"`
	Count    int64     `json:"count"`
	LastSeen time.Time `json:"lastSeen"`
}

// TopBlockedDomains returns the most frequently blocked domains since t.
func (s *Store) TopBlockedDomains(ctx context.Context, t time.Time, limit int) ([]TopBlocked, error) {
	if limit <= 0 || limit > 200 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain,
		       MAX(category)  AS category,
		       SUM(count)     AS n,
		       MAX(last_seen) AS seen
		FROM blocked_domain_stats
		WHERE day >= ?
		GROUP BY domain ORDER BY n DESC, seen DESC LIMIT ?`,
		t.UTC().Truncate(24*time.Hour).Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TopBlocked
	for rows.Next() {
		var (
			b    TopBlocked
			seen int64
		)
		if err := rows.Scan(&b.Domain, &b.Category, &b.Count, &seen); err != nil {
			return nil, err
		}
		b.LastSeen = fromUnixMilli(seen)
		out = append(out, b)
	}
	return out, rows.Err()
}

// NetworkActivity is per-network traffic used on the networks page.
type NetworkActivity struct {
	NetworkID string     `json:"networkId"`
	Queries   int64      `json:"queries"`
	Blocked   int64      `json:"blocked"`
	LastSeen  *time.Time `json:"lastSeen"`
}

// NetworkActivitySince returns per-network counts since t, keyed by network ID.
func (s *Store) NetworkActivitySince(ctx context.Context, t time.Time) (map[string]NetworkActivity, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT network_id, COALESCE(SUM(total), 0), COALESCE(SUM(blocked), 0), MAX(hour)
		FROM stats_hourly WHERE hour >= ? GROUP BY network_id`,
		t.UTC().Truncate(time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]NetworkActivity{}
	for rows.Next() {
		var (
			a       NetworkActivity
			maxHour *int64
		)
		if err := rows.Scan(&a.NetworkID, &a.Queries, &a.Blocked, &maxHour); err != nil {
			return nil, err
		}
		if maxHour != nil {
			t := time.Unix(*maxHour, 0).UTC()
			a.LastSeen = &t
		}
		out[a.NetworkID] = a
	}
	return out, rows.Err()
}

// Prune deletes query-log rows and rollups past their retention windows.
// It returns the number of query-log rows removed.
func (s *Store) Prune(ctx context.Context, retentionDays, rollupDays int) (int64, error) {
	if retentionDays <= 0 {
		retentionDays = 7
	}
	if rollupDays <= 0 {
		rollupDays = 90
	}

	logCutoff := unixMilli(time.Now().AddDate(0, 0, -retentionDays))
	res, err := s.db.ExecContext(ctx, "DELETE FROM query_log WHERE ts < ?", logCutoff)
	if err != nil {
		return 0, fmt.Errorf("prune query_log: %w", err)
	}
	removed, _ := res.RowsAffected()

	rollupCutoff := time.Now().AddDate(0, 0, -rollupDays)
	if _, err := s.db.ExecContext(ctx, "DELETE FROM stats_hourly WHERE hour < ?",
		rollupCutoff.UTC().Truncate(time.Hour).Unix()); err != nil {
		return removed, fmt.Errorf("prune stats_hourly: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM blocked_domain_stats WHERE day < ?",
		rollupCutoff.UTC().Truncate(24*time.Hour).Unix()); err != nil {
		return removed, fmt.Errorf("prune blocked_domain_stats: %w", err)
	}
	return removed, nil
}

// CountQueryLogRows returns the number of stored query-log rows, used for the
// disk-usage figure on the settings page.
func (s *Store) CountQueryLogRows(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM query_log").Scan(&n)
	return n, err
}
