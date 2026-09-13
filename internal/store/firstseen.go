package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// FirstSeen is one registered domain this installation has seen.
type FirstSeen struct {
	Domain     string    `json:"domain"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	QueryCount int64     `json:"queryCount"`
	// Certain reports that FirstSeen is the true first sighting on this
	// installation rather than possibly a restart after an eviction.
	//
	// True when the row predates the first eviction this index ever performed:
	// nothing had been evicted yet, so nothing could have been re-inserted.
	// False does not mean the row was evicted — only that this index cannot
	// prove it was not. That distinction matters to the one question the table
	// exists to answer, and a hunt that read a restart as "never seen here
	// before" would raise an alert about a domain the network has used for a
	// year.
	Certain bool `json:"certain"`
}

// FirstSeenTouch is one batched observation.
type FirstSeenTouch struct {
	Domain string
	// Count is how many queries for this domain the batch collapsed. A busy
	// name is one row update carrying its own multiplicity rather than N
	// round trips to SQLite.
	Count int64
	// At is when the batch observed it.
	At time.Time
}

// FirstSeenResult reports what a batch did, so the caller can keep counters
// without a second query.
type FirstSeenResult struct {
	Inserted int64
	Updated  int64
	// Rejected is domains that would have been new rows but were refused
	// because the caller's budget was spent.
	Rejected int64
}

// ApplyFirstSeen writes a batch of observations in one transaction.
//
// newBudget caps how many rows this batch may create; repeats of domains
// already in the table are always applied and never consume it. That split is
// the point: an attacker generating unlimited fresh names is bounded, while a
// network browsing the same few thousand domains is never throttled.
//
// A negative budget means unlimited, which is how a caller that has already
// done its own accounting opts out.
func (s *Store) ApplyFirstSeen(ctx context.Context, touches []FirstSeenTouch, newBudget int) (FirstSeenResult, error) {
	var res FirstSeenResult
	if len(touches) == 0 {
		return res, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()

	// Existing rows are updated; absent ones are inserted while the budget
	// lasts. Checked per domain rather than with a bulk upsert because the
	// budget only applies to one of the two outcomes, and an upsert cannot
	// tell the caller which it did without a second round trip anyway.
	for _, t := range touches {
		if t.Domain == "" || t.Count <= 0 {
			continue
		}
		at := unixMilli(t.At)

		upd, err := tx.ExecContext(ctx, `
			UPDATE first_seen_domains
			   SET last_seen = MAX(last_seen, ?), query_count = query_count + ?
			 WHERE domain = ?`, at, t.Count, t.Domain)
		if err != nil {
			return res, fmt.Errorf("update first_seen_domains: %w", err)
		}
		if n, _ := upd.RowsAffected(); n > 0 {
			res.Updated++
			continue
		}

		if newBudget == 0 {
			res.Rejected++
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO first_seen_domains (domain, first_seen, last_seen, query_count)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(domain) DO UPDATE SET
				last_seen   = MAX(last_seen, excluded.last_seen),
				query_count = query_count + excluded.query_count`,
			t.Domain, at, at, t.Count); err != nil {
			return res, fmt.Errorf("insert first_seen_domains: %w", err)
		}
		res.Inserted++
		if newBudget > 0 {
			newBudget--
		}
	}
	return res, tx.Commit()
}

// SettingFirstSeenFirstEviction records when this index first had to evict a
// row, as Unix milliseconds.
//
// One timestamp rather than a set of evicted names, because the set is the
// thing that cannot be bounded. It supports exactly one claim, and supports it
// exactly: a row created before this instant is the true first sighting. After
// it, unknown. See FirstSeen.Certain.
const SettingFirstSeenFirstEviction = "firstseen.first_eviction_at"

// EvictFirstSeen removes rows until at most maxRows remain, oldest last_seen
// first, and returns how many went.
//
// Oldest last_seen rather than lowest query_count: the question this table
// answers is "has this network seen this domain", and a domain nobody has
// asked for in months is the one whose absence is least likely to be noticed.
// Evicting by count would throw away a domain seen once yesterday in favour of
// one seen a thousand times last year, which inverts the signal.
//
// The first eviction stamps a watermark, which is what lets a later reader
// tell a genuine first sighting from a restart without anybody remembering
// which names went.
func (s *Store) EvictFirstSeen(ctx context.Context, maxRows int) (int64, error) {
	if maxRows < 0 {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM first_seen_domains
		 WHERE domain IN (
		       SELECT domain FROM first_seen_domains
		        ORDER BY last_seen ASC
		        LIMIT MAX(0, (SELECT COUNT(*) FROM first_seen_domains) - ?)
		 )`, maxRows)
	if err != nil {
		return 0, fmt.Errorf("evict first_seen_domains: %w", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		// INSERT OR IGNORE: only the first eviction sets the watermark, and a
		// concurrent second one must not move it forward — that would turn
		// rows already known to be genuine into unknowns.
		if _, err := s.db.ExecContext(ctx,
			"INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
			SettingFirstSeenFirstEviction, fmt.Sprint(unixMilli(time.Now())),
		); err != nil {
			return n, fmt.Errorf("record first eviction: %w", err)
		}
	}
	return n, nil
}

// FirstSeenEvictionWatermark returns when this index first evicted a row, or
// the zero time when it never has.
func (s *Store) FirstSeenEvictionWatermark(ctx context.Context) (time.Time, error) {
	v, err := s.GetSetting(ctx, SettingFirstSeenFirstEviction)
	if errors.Is(err, ErrNotFound) || v == "" {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	ms, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}, nil
	}
	return fromUnixMilli(ms), nil
}

// CountFirstSeen returns how many domains are indexed.
func (s *Store) CountFirstSeen(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM first_seen_domains").Scan(&n)
	return n, err
}

// LookupFirstSeen returns one domain's record, or ErrNotFound.
func (s *Store) LookupFirstSeen(ctx context.Context, domain string) (FirstSeen, error) {
	var (
		out         FirstSeen
		first, last int64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT domain, first_seen, last_seen, query_count
		  FROM first_seen_domains WHERE domain = ?`, domain,
	).Scan(&out.Domain, &first, &last, &out.QueryCount)
	if errors.Is(err, sql.ErrNoRows) {
		return FirstSeen{}, ErrNotFound
	}
	if err != nil {
		return FirstSeen{}, err
	}
	watermark, err := s.FirstSeenEvictionWatermark(ctx)
	if err != nil {
		return FirstSeen{}, err
	}
	out.FirstSeen = fromUnixMilli(first)
	out.LastSeen = fromUnixMilli(last)
	out.Certain = watermark.IsZero() || out.FirstSeen.Before(watermark)
	return out, nil
}

// maxFirstSeenPage bounds a listing regardless of what a caller asks for. The
// table can hold a hundred thousand rows and an unbounded list endpoint is a
// way to make the process allocate all of them.
const maxFirstSeenPage = 500

// RecentFirstSeen returns the most recently discovered domains, newest first.
func (s *Store) RecentFirstSeen(ctx context.Context, limit int) ([]FirstSeen, error) {
	if limit <= 0 || limit > maxFirstSeenPage {
		limit = maxFirstSeenPage
	}
	watermark, err := s.FirstSeenEvictionWatermark(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain, first_seen, last_seen, query_count
		  FROM first_seen_domains
		 ORDER BY first_seen DESC, domain ASC
		 LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]FirstSeen, 0, limit)
	for rows.Next() {
		var (
			fs          FirstSeen
			first, last int64
		)
		if err := rows.Scan(&fs.Domain, &first, &last, &fs.QueryCount); err != nil {
			return nil, err
		}
		fs.FirstSeen = fromUnixMilli(first)
		fs.LastSeen = fromUnixMilli(last)
		fs.Certain = watermark.IsZero() || fs.FirstSeen.Before(watermark)
		out = append(out, fs)
	}
	return out, rows.Err()
}
