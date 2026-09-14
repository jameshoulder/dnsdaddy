package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Lifecycle is what a feed's listing of one domain has done over time.
//
// Zero times mean unknown, never 1970. An installation that upgraded into this
// feature has no history for anything it was already blocking, and a record
// saying a domain was first listed on 1 January 1970 is worse than one saying
// nothing: the first is a fact an operator may act on, and it is false.
type Lifecycle struct {
	FeedID    string    `json:"feedId"`
	Indicator string    `json:"indicator"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	// ExpiresAt is when the feed said this listing stops being current. Zero
	// means the feed gave no expiry, which is every feed shipped today.
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
	// Live reports that this indicator was in the feed's most recent good
	// snapshot. False means the feed has stopped listing it: it is no longer
	// blocking, and the row is kept only as history.
	Live bool `json:"live"`
}

// LifecycleSnapshot is one feed's complete set of indicators, as of one
// successful refresh.
//
// Complete is the important word. Reconcile takes the absence of an indicator
// from this set as the feed having dropped it, so a partial snapshot would
// mark half a feed as no longer listed. That is why it is only ever built from
// a load that succeeded — see Manager.reconcileLifecycle.
type LifecycleSnapshot struct {
	FeedID string
	// At is the refresh time, used for LastSeen on everything present and for
	// FirstSeen on anything new.
	At time.Time
	// Indicators are the normalised domains this feed now lists, mapped to the
	// expiry the feed gave for each. A zero value means no expiry, which is
	// the case for every shipped feed format.
	Indicators map[string]time.Time
}

// LifecycleResult reports what one reconcile did.
type LifecycleResult struct {
	// Added is indicators this feed had never listed before.
	Added int
	// Refreshed is indicators it still lists.
	Refreshed int
	// Dropped is indicators it has stopped listing. Their rows keep their
	// times and stop being live.
	Dropped int
	// Rejected is indicators not recorded because the table is at its ceiling.
	// They still block — the live index is built from the feed, not from this
	// table — but their times are unknown.
	Rejected int
	// Evicted is off-live history discarded to make room.
	Evicted int
}

// lifecycleChunk is how many rows one transaction writes.
//
// A feed refresh can be a quarter of a million indicators, and SQLite takes one
// writer at a time. Doing that as a single transaction on a one-processor box
// holds the write lock for seconds, which the audit log taught us shows up as
// SQLITE_BUSY in whatever else is trying to write — a policy edit, the query
// log flushing. Chunking gives every other writer a gap.
const lifecycleChunk = 2000

// ReconcileLifecycle records one feed's snapshot against its stored history.
//
// The rules, all of which are load-bearing:
//
//   - An indicator the feed still lists keeps its FirstSeen and gets a new
//     LastSeen. FirstSeen is the whole point of the table and is never
//     rewritten.
//   - An indicator the feed has just started listing gets FirstSeen = LastSeen
//     = the refresh time.
//   - An indicator the feed has stopped listing goes off-live and keeps
//     everything it had. It is no longer blocking; it is still history.
//   - An indicator that reappears after a gap keeps its ORIGINAL FirstSeen,
//     because the row was never deleted. The exception is a row the retention
//     prune has removed, which cannot be distinguished from one that was never
//     seen — that is stated in the documentation rather than papered over.
//
// maxRows bounds the table. Past it, off-live history is discarded oldest
// first; if that is not enough, new indicators are not recorded and are
// counted. Live rows are never evicted to make room: they are the times a
// block happening right now would be explained with.
func (s *Store) ReconcileLifecycle(ctx context.Context, snap LifecycleSnapshot, maxRows int) (LifecycleResult, error) {
	var res LifecycleResult
	if snap.FeedID == "" {
		return res, errors.New("reconcile lifecycle: no feed")
	}
	if snap.At.IsZero() {
		snap.At = time.Now().UTC()
	}
	at := unixMilli(snap.At)

	// What this feed held before, so present/absent can be decided without
	// holding the whole table in memory twice.
	previous, err := s.feedIndicatorKeys(ctx, snap.FeedID)
	if err != nil {
		return res, err
	}

	// Room to insert, worked out once. Recomputing per chunk would let a
	// concurrent writer move the ceiling underneath the loop.
	room, evicted, err := s.makeLifecycleRoom(ctx, len(snap.Indicators), previous, maxRows)
	if err != nil {
		return res, err
	}
	res.Evicted = evicted

	keys := make([]string, 0, len(snap.Indicators))
	for k := range snap.Indicators {
		keys = append(keys, k)
	}

	for start := 0; start < len(keys); start += lifecycleChunk {
		end := min(start+lifecycleChunk, len(keys))
		if err := s.writeLifecycleChunk(ctx, snap, keys[start:end], at, previous, &room, &res); err != nil {
			return res, err
		}
	}

	// Everything this feed listed before and does not list now.
	dropped, err := s.markLifecycleDropped(ctx, snap.FeedID, snap.Indicators)
	if err != nil {
		return res, err
	}
	res.Dropped = dropped
	return res, nil
}

// writeLifecycleChunk writes one transaction's worth of indicators.
func (s *Store) writeLifecycleChunk(ctx context.Context, snap LifecycleSnapshot,
	keys []string, at int64, previous map[string]bool, room *int, res *LifecycleResult) error {

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, indicator := range keys {
		expires := int64(0)
		if e := snap.Indicators[indicator]; !e.IsZero() {
			expires = unixMilli(e)
		}

		if previous[indicator] {
			// Still listed. last_seen and expiry move; first_seen does not,
			// and is deliberately absent from this statement rather than being
			// set to itself — a column that is never written cannot be
			// rewritten by a later edit to this query.
			if _, err := tx.ExecContext(ctx, `
				UPDATE feed_indicators
				   SET last_seen = ?, expires_at = ?, live = 1
				 WHERE feed_id = ? AND indicator = ?`,
				at, expires, snap.FeedID, indicator); err != nil {
				return fmt.Errorf("refresh indicator: %w", err)
			}
			res.Refreshed++
			continue
		}

		if *room <= 0 {
			res.Rejected++
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO feed_indicators (feed_id, indicator, first_seen, last_seen, expires_at, live)
			VALUES (?, ?, ?, ?, ?, 1)`,
			snap.FeedID, indicator, at, at, expires); err != nil {
			return fmt.Errorf("record indicator: %w", err)
		}
		*room--
		res.Added++
	}
	return tx.Commit()
}

// feedIndicatorKeys reads which indicators a feed already has rows for,
// whether or not they are live.
func (s *Store) feedIndicatorKeys(ctx context.Context, feedID string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT indicator FROM feed_indicators WHERE feed_id = ?", feedID)
	if err != nil {
		return nil, fmt.Errorf("read feed indicators: %w", err)
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}

// makeLifecycleRoom reports how many new rows may be inserted, discarding
// off-live history oldest first if the ceiling needs it.
//
// Live rows are never touched. A row going off-live is the feed's decision; a
// row being evicted is this table running out of space, and spending the times
// behind a block that is happening right now to make room for history is the
// wrong trade in both directions.
func (s *Store) makeLifecycleRoom(ctx context.Context, incoming int, previous map[string]bool, maxRows int) (room, evicted int, err error) {
	if maxRows <= 0 {
		return incoming, 0, nil
	}

	var total int
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM feed_indicators").Scan(&total); err != nil {
		return 0, 0, fmt.Errorf("count feed indicators: %w", err)
	}

	// Only indicators without a row of their own need space. Feeds overlap
	// heavily between refreshes, so this is usually a handful even when the
	// snapshot is a quarter of a million names.
	wanted := incoming - len(previous)
	if wanted < 0 {
		wanted = 0
	}

	room = maxRows - total
	if room >= wanted {
		return wanted, 0, nil
	}

	need := wanted - room
	if need > 0 {
		r, err := s.db.ExecContext(ctx, `
			DELETE FROM feed_indicators
			 WHERE rowid IN (
			     SELECT rowid FROM feed_indicators
			      WHERE live = 0 ORDER BY last_seen ASC LIMIT ?)`, need)
		if err != nil {
			return 0, 0, fmt.Errorf("evict feed indicator history: %w", err)
		}
		n, _ := r.RowsAffected()
		evicted = int(n)
		room += evicted
	}
	if room < 0 {
		room = 0
	}
	return room, evicted, nil
}

// markLifecycleDropped takes every indicator this feed no longer lists off the
// live set, keeping its times.
func (s *Store) markLifecycleDropped(ctx context.Context, feedID string, current map[string]time.Time) (int, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT indicator FROM feed_indicators WHERE feed_id = ? AND live = 1", feedID)
	if err != nil {
		return 0, fmt.Errorf("read live indicators: %w", err)
	}
	var gone []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return 0, err
		}
		if _, still := current[k]; !still {
			gone = append(gone, k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(gone) == 0 {
		return 0, nil
	}

	dropped := 0
	for start := 0; start < len(gone); start += lifecycleChunk {
		end := min(start+lifecycleChunk, len(gone))
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return dropped, err
		}
		for _, k := range gone[start:end] {
			if _, err := tx.ExecContext(ctx,
				"UPDATE feed_indicators SET live = 0 WHERE feed_id = ? AND indicator = ?",
				feedID, k); err != nil {
				_ = tx.Rollback()
				return dropped, fmt.Errorf("drop indicator: %w", err)
			}
			dropped++
		}
		if err := tx.Commit(); err != nil {
			return dropped, err
		}
	}
	return dropped, nil
}

// LifecycleFor reads one feed's history for one indicator.
func (s *Store) LifecycleFor(ctx context.Context, feedID, indicator string) (Lifecycle, error) {
	l := Lifecycle{FeedID: feedID, Indicator: indicator}
	var first, last, expires int64
	var live int
	err := s.db.QueryRowContext(ctx, `
		SELECT first_seen, last_seen, expires_at, live
		  FROM feed_indicators WHERE feed_id = ? AND indicator = ?`,
		feedID, indicator).Scan(&first, &last, &expires, &live)
	if errors.Is(err, sql.ErrNoRows) {
		return l, ErrNotFound
	}
	if err != nil {
		return l, err
	}
	l.FirstSeen, l.LastSeen = fromUnixMilli(first), fromUnixMilli(last)
	if expires > 0 {
		l.ExpiresAt = fromUnixMilli(expires)
	}
	l.Live = live == 1
	return l, nil
}

// LoadLifecycle reads every live indicator's times, for attaching to a freshly
// built index.
//
// Live only, and that is the point: an off-live row describes something the
// feed has stopped listing, which by definition is not in the index being
// built. Reading them would be loading history nothing can look up.
func (s *Store) LoadLifecycle(ctx context.Context) (map[string]map[string]Lifecycle, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT feed_id, indicator, first_seen, expires_at
		  FROM feed_indicators WHERE live = 1`)
	if err != nil {
		return nil, fmt.Errorf("load lifecycle: %w", err)
	}
	defer rows.Close()

	out := map[string]map[string]Lifecycle{}
	for rows.Next() {
		var feedID, indicator string
		var first, expires int64
		if err := rows.Scan(&feedID, &indicator, &first, &expires); err != nil {
			return nil, err
		}
		byFeed := out[feedID]
		if byFeed == nil {
			byFeed = map[string]Lifecycle{}
			out[feedID] = byFeed
		}
		l := Lifecycle{FeedID: feedID, Indicator: indicator, Live: true,
			FirstSeen: fromUnixMilli(first)}
		if expires > 0 {
			l.ExpiresAt = fromUnixMilli(expires)
		}
		byFeed[indicator] = l
	}
	return out, rows.Err()
}

// PruneLifecycle removes off-live history older than the cutoff.
//
// Off-live only. A live row is the explanation for a block that could happen
// in the next second, and no retention window applies to it — it is current
// state rather than history.
//
// It also cannot reach a decision record. Those live in their own tables with
// their own retention, and the times on them were copied at the moment of the
// decision precisely so that nothing here can change what a past block was
// explained with.
func (s *Store) PruneLifecycle(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM feed_indicators WHERE live = 0 AND last_seen < ?", unixMilli(before))
	if err != nil {
		return 0, fmt.Errorf("prune feed indicators: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// LifecycleStats counts what the table holds.
type LifecycleStats struct {
	Live    int64
	History int64
	Feeds   int64
}

// CountLifecycle reports the table's shape for diagnostics and metrics.
func (s *Store) CountLifecycle(ctx context.Context) (LifecycleStats, error) {
	var st LifecycleStats
	err := s.db.QueryRowContext(ctx, `
		SELECT
		    COALESCE(SUM(CASE WHEN live = 1 THEN 1 ELSE 0 END), 0),
		    COALESCE(SUM(CASE WHEN live = 0 THEN 1 ELSE 0 END), 0),
		    COUNT(DISTINCT feed_id)
		  FROM feed_indicators`).Scan(&st.Live, &st.History, &st.Feeds)
	return st, err
}
