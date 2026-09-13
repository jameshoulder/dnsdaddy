package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func fsStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "fs.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, context.Background()
}

func touch(domain string, n int64, at time.Time) FirstSeenTouch {
	return FirstSeenTouch{Domain: domain, Count: n, At: at}
}

// TestAFirstSightingInsertsOneRow with first_seen equal to last_seen, which is
// what "seen once, just now" looks like.
func TestAFirstSightingInsertsOneRow(t *testing.T) {
	st, ctx := fsStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)

	res, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{touch("example.com", 1, now)}, -1)
	if err != nil {
		t.Fatalf("ApplyFirstSeen: %v", err)
	}
	if res.Inserted != 1 || res.Updated != 0 {
		t.Errorf("result = %+v, want one insert", res)
	}

	got, err := st.LookupFirstSeen(ctx, "example.com")
	if err != nil {
		t.Fatalf("LookupFirstSeen: %v", err)
	}
	if !got.FirstSeen.Equal(got.LastSeen) {
		t.Errorf("first_seen %v != last_seen %v on a first sighting", got.FirstSeen, got.LastSeen)
	}
	if got.QueryCount != 1 {
		t.Errorf("query_count = %d, want 1", got.QueryCount)
	}
	if !got.Certain {
		t.Error("a row on an index that has never evicted should be certain")
	}
}

// TestASecondSightingUpdatesWithoutMovingFirstSeen. If first_seen drifted the
// table would answer "when did we last see it" twice and the novelty question
// never.
func TestASecondSightingUpdatesWithoutMovingFirstSeen(t *testing.T) {
	st, ctx := fsStore(t)
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	t1 := time.Now().UTC().Truncate(time.Millisecond)

	if _, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{touch("example.com", 1, t0)}, -1); err != nil {
		t.Fatal(err)
	}
	res, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{touch("example.com", 1, t1)}, -1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 1 || res.Inserted != 0 {
		t.Errorf("result = %+v, want one update", res)
	}

	got, _ := st.LookupFirstSeen(ctx, "example.com")
	if !got.FirstSeen.Equal(t0) {
		t.Errorf("first_seen moved to %v, want %v", got.FirstSeen, t0)
	}
	if !got.LastSeen.Equal(t1) {
		t.Errorf("last_seen = %v, want %v", got.LastSeen, t1)
	}
	if got.QueryCount != 2 {
		t.Errorf("query_count = %d, want 2", got.QueryCount)
	}
}

// TestABatchCarriesItsOwnMultiplicity. A name asked 500 times between flushes
// is one row update carrying 500, not 500 round trips to SQLite.
func TestABatchCarriesItsOwnMultiplicity(t *testing.T) {
	st, ctx := fsStore(t)
	now := time.Now().UTC()

	if _, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{touch("busy.example", 500, now)}, -1); err != nil {
		t.Fatal(err)
	}
	got, _ := st.LookupFirstSeen(ctx, "busy.example")
	if got.QueryCount != 500 {
		t.Errorf("query_count = %d, want 500", got.QueryCount)
	}
}

// TestAnOutOfOrderBatchDoesNotRewindLastSeen. Batches flush concurrently with
// nothing ordering them, so a late one carrying an older timestamp must not
// make a domain look staler than it is — eviction picks by last_seen.
func TestAnOutOfOrderBatchDoesNotRewindLastSeen(t *testing.T) {
	st, ctx := fsStore(t)
	newer := time.Now().UTC().Truncate(time.Millisecond)
	older := newer.Add(-time.Hour)

	if _, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{touch("x.example", 1, newer)}, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{touch("x.example", 1, older)}, -1); err != nil {
		t.Fatal(err)
	}
	got, _ := st.LookupFirstSeen(ctx, "x.example")
	if !got.LastSeen.Equal(newer) {
		t.Errorf("last_seen rewound to %v, want %v", got.LastSeen, newer)
	}
	if got.QueryCount != 2 {
		t.Errorf("query_count = %d, want 2: the out-of-order batch still counted", got.QueryCount)
	}
}

// TestTheBudgetOnlyLimitsNewRows. That split is the whole bounding strategy:
// an attacker minting fresh names is capped while a network browsing the same
// few thousand domains is never throttled.
func TestTheBudgetOnlyLimitsNewRows(t *testing.T) {
	st, ctx := fsStore(t)
	now := time.Now().UTC()

	// Seed three known domains with no budget pressure.
	seed := []FirstSeenTouch{touch("a.example", 1, now), touch("b.example", 1, now), touch("c.example", 1, now)}
	if _, err := st.ApplyFirstSeen(ctx, seed, -1); err != nil {
		t.Fatal(err)
	}

	// Now a batch of the same three plus four new ones, with room for one.
	batch := append(seed, touch("n1.example", 1, now), touch("n2.example", 1, now),
		touch("n3.example", 1, now), touch("n4.example", 1, now))
	res, err := st.ApplyFirstSeen(ctx, batch, 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 3 {
		t.Errorf("updated %d known domains, want 3 — the budget throttled repeats", res.Updated)
	}
	if res.Inserted != 1 {
		t.Errorf("inserted %d, want 1", res.Inserted)
	}
	if res.Rejected != 3 {
		t.Errorf("rejected %d, want 3", res.Rejected)
	}

	n, _ := st.CountFirstSeen(ctx)
	if n != 4 {
		t.Errorf("%d rows, want 4", n)
	}
}

// TestAZeroBudgetStillUpdates. A full table must keep counting the domains it
// already knows, or a network at capacity stops recording activity entirely.
func TestAZeroBudgetStillUpdates(t *testing.T) {
	st, ctx := fsStore(t)
	now := time.Now().UTC()

	if _, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{touch("known.example", 1, now)}, -1); err != nil {
		t.Fatal(err)
	}
	res, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{
		touch("known.example", 5, now), touch("brand.new", 1, now),
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 1 || res.Inserted != 0 || res.Rejected != 1 {
		t.Errorf("result = %+v, want one update and one rejection", res)
	}
	got, _ := st.LookupFirstSeen(ctx, "known.example")
	if got.QueryCount != 6 {
		t.Errorf("query_count = %d, want 6", got.QueryCount)
	}
}

// TestEvictionRemovesTheStalestRows, not the least popular: the question is
// "has this network seen this domain", and a domain nobody has asked for in
// months is the one whose absence is least likely to be noticed.
func TestEvictionRemovesTheStalestRows(t *testing.T) {
	st, ctx := fsStore(t)
	base := time.Now().UTC().Add(-30 * 24 * time.Hour)

	// stale.example was seen a thousand times, long ago. fresh.example once,
	// recently. Eviction must take the stale one.
	if _, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{
		touch("stale.example", 1000, base),
		touch("middle.example", 1, base.Add(10*24*time.Hour)),
		touch("fresh.example", 1, time.Now().UTC()),
	}, -1); err != nil {
		t.Fatal(err)
	}

	n, err := st.EvictFirstSeen(ctx, 2)
	if err != nil {
		t.Fatalf("EvictFirstSeen: %v", err)
	}
	if n != 1 {
		t.Fatalf("evicted %d, want 1", n)
	}
	if _, err := st.LookupFirstSeen(ctx, "stale.example"); err != ErrNotFound {
		t.Error("the stalest row survived eviction")
	}
	if _, err := st.LookupFirstSeen(ctx, "fresh.example"); err != nil {
		t.Error("a fresh row was evicted")
	}
}

// TestEvictionIsANoOpBelowTheLimit, so a quiet installation never churns.
func TestEvictionIsANoOpBelowTheLimit(t *testing.T) {
	st, ctx := fsStore(t)
	now := time.Now().UTC()
	if _, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{touch("a.example", 1, now)}, -1); err != nil {
		t.Fatal(err)
	}
	n, err := st.EvictFirstSeen(ctx, 100)
	if err != nil || n != 0 {
		t.Errorf("evicted %d (err %v), want 0", n, err)
	}
	if at, _ := st.FirstSeenEvictionWatermark(ctx); !at.IsZero() {
		t.Error("a no-op eviction stamped the watermark")
	}
}

// TestTheWatermarkIsExactAboutWhatItKnows.
//
// This is the honesty property. After an eviction the index cannot say whether
// a given first_seen is a discovery or a restart — remembering every evicted
// name would be unbounded, and a bounded set would start calling restarts
// discoveries. What it can say exactly is that rows predating the FIRST
// eviction are genuine, because nothing had been evicted yet.
func TestTheWatermarkIsExactAboutWhatItKnows(t *testing.T) {
	st, ctx := fsStore(t)
	old := time.Now().UTC().Add(-48 * time.Hour)

	if _, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{
		touch("ancient.example", 1, old), touch("stale.example", 1, old.Add(-time.Hour)),
	}, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.EvictFirstSeen(ctx, 1); err != nil {
		t.Fatal(err)
	}
	at, err := st.FirstSeenEvictionWatermark(ctx)
	if err != nil || at.IsZero() {
		t.Fatalf("watermark = %v (err %v), want a timestamp", at, err)
	}

	// The survivor predates the eviction, so it is provably genuine.
	survivor, _ := st.LookupFirstSeen(ctx, "ancient.example")
	if !survivor.Certain {
		t.Error("a row created before the first eviction was reported as uncertain")
	}

	// Anything created now cannot be proven either way.
	if _, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{
		touch("after.example", 1, time.Now().UTC().Add(time.Second)),
	}, -1); err != nil {
		t.Fatal(err)
	}
	after, _ := st.LookupFirstSeen(ctx, "after.example")
	if after.Certain {
		t.Error("a row created after an eviction claimed to be a certain first sighting")
	}
}

// TestTheWatermarkNeverMovesForward. A later eviction must not turn rows
// already known to be genuine into unknowns.
func TestTheWatermarkNeverMovesForward(t *testing.T) {
	st, ctx := fsStore(t)
	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		if _, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{
			touch(fmt.Sprintf("d%d.example", i), 1, now.Add(time.Duration(i)*time.Second)),
		}, -1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.EvictFirstSeen(ctx, 4); err != nil {
		t.Fatal(err)
	}
	first, _ := st.FirstSeenEvictionWatermark(ctx)

	time.Sleep(5 * time.Millisecond)
	if _, err := st.EvictFirstSeen(ctx, 2); err != nil {
		t.Fatal(err)
	}
	second, _ := st.FirstSeenEvictionWatermark(ctx)
	if !second.Equal(first) {
		t.Errorf("watermark moved from %v to %v", first, second)
	}
}

// TestRecentFirstSeenIsNewestFirstAndCapped. An unbounded list endpoint over a
// hundred-thousand-row table is a way to make the process allocate all of it.
func TestRecentFirstSeenIsNewestFirstAndCapped(t *testing.T) {
	st, ctx := fsStore(t)
	base := time.Now().UTC().Add(-time.Hour)

	var batch []FirstSeenTouch
	for i := 0; i < 20; i++ {
		batch = append(batch, touch(fmt.Sprintf("d%02d.example", i), 1, base.Add(time.Duration(i)*time.Minute)))
	}
	if _, err := st.ApplyFirstSeen(ctx, batch, -1); err != nil {
		t.Fatal(err)
	}

	got, err := st.RecentFirstSeen(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d rows, want 5", len(got))
	}
	if got[0].Domain != "d19.example" {
		t.Errorf("newest is %q, want d19.example", got[0].Domain)
	}
	for i := 1; i < len(got); i++ {
		if got[i].FirstSeen.After(got[i-1].FirstSeen) {
			t.Errorf("row %d is newer than row %d", i, i-1)
		}
	}

	// An absurd limit is clamped rather than honoured.
	all, err := st.RecentFirstSeen(ctx, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) > maxFirstSeenPage {
		t.Errorf("returned %d rows for an unbounded request", len(all))
	}
}

// TestAnUnknownDomainIsNotFound, which callers must render as "unknown"
// rather than as "never seen before".
func TestAnUnknownDomainIsNotFound(t *testing.T) {
	st, ctx := fsStore(t)
	if _, err := st.LookupFirstSeen(ctx, "never.asked"); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// TestThePrunerDoesNotTouchTheIndex is the reason this table exists.
//
// If the query-log pruner reached it, the signal would reset every seven days
// and every domain on the network would look new again — which is precisely
// the approximation the index was built to replace.
func TestThePrunerDoesNotTouchTheIndex(t *testing.T) {
	st, ctx := fsStore(t)
	ancient := time.Now().UTC().AddDate(0, 0, -400).Truncate(time.Millisecond)

	if _, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{touch("old.example", 1, ancient)}, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Prune(ctx, 7, 90); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	got, err := st.LookupFirstSeen(ctx, "old.example")
	if err != nil {
		t.Fatal("a 400-day-old index row was deleted by the 7-day query-log prune")
	}
	if !got.FirstSeen.Equal(ancient) {
		t.Errorf("first_seen = %v, want %v", got.FirstSeen, ancient)
	}
}

// TestAnEmptyBatchIsCheap, because the worker flushes on a timer whether or
// not anything arrived.
func TestAnEmptyBatchIsCheap(t *testing.T) {
	st, ctx := fsStore(t)
	res, err := st.ApplyFirstSeen(ctx, nil, -1)
	if err != nil || res != (FirstSeenResult{}) {
		t.Errorf("empty batch returned %+v, %v", res, err)
	}
}

// TestAZeroCountTouchIsIgnored, so a bug upstream cannot create rows for
// domains nobody asked about.
func TestAZeroCountTouchIsIgnored(t *testing.T) {
	st, ctx := fsStore(t)
	now := time.Now().UTC()
	res, err := st.ApplyFirstSeen(ctx, []FirstSeenTouch{
		{Domain: "ghost.example", Count: 0, At: now},
		{Domain: "", Count: 5, At: now},
	}, -1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Inserted != 0 {
		t.Errorf("inserted %d rows from empty touches", res.Inserted)
	}
	if n, _ := st.CountFirstSeen(ctx); n != 0 {
		t.Errorf("%d rows exist, want 0", n)
	}
}
