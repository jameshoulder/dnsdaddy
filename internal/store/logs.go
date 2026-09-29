package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
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
		// Allocate from a persistent counter rather than MAX(id): retention
		// may remove the newest insertion, and reusing its ID would collide
		// with previously exported queries. The insert trigger advances the
		// counter in this transaction, including between rows in one batch.
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO query_log (id, ts, client_ip, client_name, network_id, qname, qtype,
			                       action, reason, category, source, proto, elapsed_ms, cached,
			                       dnssec, dnssec_obs, dnssec_source)
			VALUES ((SELECT value + 1 FROM export_sequences WHERE dataset = 'queries'),
			        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, e := range events {
			if _, err := stmt.ExecContext(ctx, unixMilli(e.Time), e.ClientIP, e.ClientName, e.NetworkID,
				e.Domain, e.QType, e.Action, e.Reason, e.Category, e.Source, e.Proto,
				e.ElapsedMS, boolToInt(e.Cached), e.DNSSEC, e.DNSSECObservationID, e.DNSSECSource); err != nil {
				return err
			}
		}
	}

	if err := upsertRollups(ctx, tx, events); err != nil {
		return err
	}
	// Client presence follows the per-query row, not the rollup: see the
	// comment on client_hourly in schema.sql.
	var fresh []clientHour
	if persist {
		fresh = s.clientHours.unseen(events)
		if err := upsertClientHours(ctx, tx, fresh); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Remembered only after the commit: a rolled-back batch must not leave
	// the memory claiming rows the table does not hold.
	s.clientHours.remember(fresh)
	return nil
}

// clientHour is one (hour, client) presence row.
type clientHour struct {
	hour int64
	ip   string
}

// clientHourSet is the bounded memory behind client_hourly writes.
//
// A busy client appears in every batch, and without this each batch would
// re-run an INSERT OR IGNORE that changes nothing. The set holds the current
// hour's clients; a later hour clears it. It is a cache in front of a
// correct-anyway write — INSERT OR IGNORE is idempotent — so losing it, or
// refusing to grow past its bound, costs repeated no-op writes and never a
// missing row.
type clientHourSet struct {
	mu   sync.Mutex
	hour int64
	seen map[string]struct{}
}

// maxRememberedClients bounds the set. A network with more distinct
// addresses than this in one hour is served correctly and simply loses the
// de-duplication above the bound, which is the cheap direction to fail in.
const maxRememberedClients = 16384

// unseen returns the distinct (hour, client) pairs in events that this set
// does not already hold. Events with no client address contribute nothing.
func (c *clientHourSet) unseen(events []QueryEvent) []clientHour {
	c.mu.Lock()
	defer c.mu.Unlock()

	var (
		out  []clientHour
		dupe = map[clientHour]struct{}{}
	)
	for _, e := range events {
		if e.ClientIP == "" {
			continue
		}
		k := clientHour{hour: e.Time.UTC().Truncate(time.Hour).Unix(), ip: e.ClientIP}
		if _, ok := dupe[k]; ok {
			continue
		}
		dupe[k] = struct{}{}
		if k.hour == c.hour {
			if _, ok := c.seen[k.ip]; ok {
				continue
			}
		}
		out = append(out, k)
	}
	return out
}

// remember records pairs that are now known to be in the table.
func (c *clientHourSet) remember(pairs []clientHour) {
	if len(pairs) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range pairs {
		if k.hour > c.hour {
			// A new hour: what was remembered is about rows the window has
			// moved past, so it is dropped rather than kept for ever.
			c.hour = k.hour
			c.seen = make(map[string]struct{}, 256)
		}
		if k.hour != c.hour || c.seen == nil {
			continue
		}
		if len(c.seen) >= maxRememberedClients {
			continue
		}
		c.seen[k.ip] = struct{}{}
	}
}

func upsertClientHours(ctx context.Context, tx txExecer, pairs []clientHour) error {
	for _, k := range pairs {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO client_hourly (hour, client_ip) VALUES (?, ?)`,
			k.hour, k.ip); err != nil {
			return err
		}
	}
	return nil
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
	//
	// [total, blocked, errors] per row.
	counts := map[rollupKey][3]int{}
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
		switch e.Action {
		case ActionBlocked:
			c[1]++
		case ActionError:
			c[2]++
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
			INSERT INTO stats_hourly (hour, network_id, category, total, blocked, errors)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(hour, network_id, category) DO UPDATE SET
				total   = total + excluded.total,
				blocked = blocked + excluded.blocked,
				errors  = errors + excluded.errors`,
			k.hour, k.networkID, k.category, v[0], v[1], v[2]); err != nil {
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
	// Domain is a substring match, for the query log's search box.
	Domain string
	// ExactDomain matches one normalised name exactly, for an investigation
	// that has to land on the rows for that name and no other. Uses the
	// qname index where Domain's LIKE cannot.
	ExactDomain string
	ClientIP    string
	Since       time.Time
	Until       time.Time
	Cursor      int64 // exclusive insertion position; 0 starts at the beginning
	Limit       int
	Ascending   bool   // exports walk insertion order, including backdated events
	MaxID       *int64 // frozen export boundary; nil is an ordinary list
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
	if f.ExactDomain != "" {
		where = append(where, "qname = ?")
		args = append(args, f.ExactDomain)
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, unixMilli(f.Since))
	}
	if !f.Until.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, unixMilli(f.Until))
	}
	if f.Cursor < 0 {
		return nil, 0, ErrInvalidCursor
	}
	if f.Cursor > 0 {
		if f.Ascending {
			where = append(where, "id > ?")
		} else {
			where = append(where, "id < ?")
		}
		args = append(args, f.Cursor)
	}
	if f.MaxID != nil {
		where = append(where, "id <= ?")
		args = append(args, *f.MaxID)
	}
	order := "id DESC"
	if f.Ascending {
		order = "id ASC"
	}
	args = append(args, limit+1)

	// #nosec G202 -- where holds only hardcoded predicate fragments
	// ("network_id = ?"); every filter value is bound as a parameter in args.
	// Never append a fragment built from input here.
	q := `SELECT id, ts, client_ip, client_name, network_id, qname, qtype, action,
	             reason, category, source, proto, elapsed_ms, cached, dnssec, dnssec_obs, dnssec_source
	      FROM query_log WHERE ` + strings.Join(where, " AND ") + `
	      ORDER BY ` + order + ` LIMIT ?`

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
			&cached, &e.DNSSEC, &e.DNSSECObservationID, &e.DNSSECSource); err != nil {
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

// Totals is a queries/blocked/errors triple over some window.
//
// All three come from the same rollup rows, so they share a window and a
// scope and can be divided into one another. Errors is zero for any hour
// recorded before the column existed; see SettingStatsErrorsSince.
type Totals struct {
	Queries int64 `json:"queries"`
	Blocked int64 `json:"blocked"`
	Errors  int64 `json:"errors"`
}

// TotalsSince sums the rollups from t to now.
func (s *Store) TotalsSince(ctx context.Context, t time.Time) (Totals, error) {
	var out Totals
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(total), 0), COALESCE(SUM(blocked), 0), COALESCE(SUM(errors), 0)
		   FROM stats_hourly WHERE hour >= ?`,
		t.UTC().Truncate(time.Hour).Unix()).Scan(&out.Queries, &out.Blocked, &out.Errors)
	return out, err
}

// DistinctClientsSince counts the attributed client addresses seen since t.
//
// Read from client_hourly, so the cost is bounded by clients × hours rather
// than by traffic. Zero when client addresses are not being recorded, which
// the caller must report as "not measured" rather than as "no clients" — the
// overview carries the setting alongside for exactly that reason.
func (s *Store) DistinctClientsSince(ctx context.Context, t time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT client_ip) FROM client_hourly WHERE hour >= ?`,
		t.UTC().Truncate(time.Hour).Unix()).Scan(&n)
	return n, err
}

// AnyClientSince reports whether any device on the network has used the
// resolver since t.
//
// A bounded existence check rather than a count, because the only question
// asked of it is "has anything at all turned up yet?" and the honest answer
// costs one row. COUNT(DISTINCT client_ip) over the same window would visit
// every row in it — on the 1 vCPU reference deployment at a million queries a
// day, that is a full scan of the last 24 hours on every dashboard load, to
// produce a number nothing displays.
//
// Both cases are cheap. Where real clients exist the newest row is almost
// always one of them, so the scan stops immediately; where none exist there is
// nothing but loopback health checks to scan.
//
// Loopback is excluded deliberately. A container health check, `dnsdaddy
// doctor` and the operator's own dig from the server all arrive from
// 127.0.0.1, and counting them would tell somebody their network was using the
// resolver when the only thing that had ever queried it was the server itself.
//
// Always false when client-IP logging is off, because then there is nothing to
// look at — callers must not read that as "no clients". Overview reports the
// setting alongside it so the dashboard can tell the two apart.
func (s *Store) AnyClientSince(ctx context.Context, t time.Time) (bool, error) {
	// A zero time means "anything still retained", which is what a caller
	// asking "has this resolver ever served a device?" needs. Any fixed
	// window answers a different question, and on an upgrade after a quiet
	// period the two disagree.
	const filter = `client_ip != '' AND client_ip NOT LIKE '127.%' AND client_ip != '::1'`

	query := "SELECT EXISTS(SELECT 1 FROM query_log WHERE " + filter + " LIMIT 1)"
	var args []any
	if !t.IsZero() {
		query = "SELECT EXISTS(SELECT 1 FROM query_log WHERE ts >= ? AND " + filter + " LIMIT 1)"
		// query_log.ts is milliseconds, not seconds. Comparing against Unix()
		// here made every row look newer than any cutoff, so the 24-hour
		// window silently covered the entire retained log.
		args = append(args, unixMilli(t))
	}

	var found int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&found)
	return found == 1, err
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

// DefaultRetentionDays is the query-log window used when the operator has not
// configured one. Named rather than repeated because anything kept alongside a
// query-log row has to expire with it: an observation that outlives the query
// it explains is a dangling reference, and one that outlives the operator's
// retention setting is a promise broken by a diagnostic feature.
const DefaultRetentionDays = 7

// Prune deletes query-log rows and rollups past their retention windows.
// It returns the number of query-log rows removed.
func (s *Store) Prune(ctx context.Context, retentionDays, rollupDays int) (int64, error) {
	if retentionDays <= 0 {
		retentionDays = DefaultRetentionDays
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

	// Client presence expires with the query log, not with the rollups: it
	// names devices, and the operator's retention setting for device-naming
	// data is log.retention_days.
	if _, err := s.db.ExecContext(ctx, "DELETE FROM client_hourly WHERE hour < ?",
		time.Now().AddDate(0, 0, -retentionDays).UTC().Truncate(time.Hour).Unix()); err != nil {
		return removed, fmt.Errorf("prune client_hourly: %w", err)
	}

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
