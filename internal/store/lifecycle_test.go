package store

import (
	"context"
	"testing"
	"time"
)

// snap builds one feed's snapshot with no expiries, which is what every feed
// DNS Daddy ships produces.
func snap(feedID string, at time.Time, indicators ...string) LifecycleSnapshot {
	m := make(map[string]time.Time, len(indicators))
	for _, i := range indicators {
		m[i] = time.Time{}
	}
	return LifecycleSnapshot{FeedID: feedID, At: at, Indicators: m}
}

func mustLifecycle(t *testing.T, st *Store, feedID, indicator string) Lifecycle {
	t.Helper()
	l, err := st.LifecycleFor(context.Background(), feedID, indicator)
	if err != nil {
		t.Fatalf("LifecycleFor(%s, %s): %v", feedID, indicator, err)
	}
	return l
}

// TestFirstSeenSurvivesEveryRefresh.
//
// The single most important property in this file. A feed is re-downloaded
// twice a day, and if each refresh rewrote first_seen then every indicator
// would appear to have been listed twelve hours ago for ever — which is not
// merely useless, it is a confident false answer to the question the table
// exists for.
func TestFirstSeenSurvivesEveryRefresh(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	monday := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", monday, "evil.example"), 0); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		later := monday.Add(time.Duration(i) * 12 * time.Hour)
		if _, err := st.ReconcileLifecycle(ctx, snap("f_a", later, "evil.example"), 0); err != nil {
			t.Fatal(err)
		}
	}

	l := mustLifecycle(t, st, "f_a", "evil.example")
	if !l.FirstSeen.Equal(monday) {
		t.Errorf("first seen = %s after five refreshes, want %s", l.FirstSeen, monday)
	}
	want := monday.Add(60 * time.Hour)
	if !l.LastSeen.Equal(want) {
		t.Errorf("last seen = %s, want %s", l.LastSeen, want)
	}
	if !l.Live {
		t.Error("an indicator the feed still lists is not live")
	}
}

// TestADroppedIndicatorKeepsItsHistoryAndStopsBeingLive.
func TestADroppedIndicatorKeepsItsHistoryAndStopsBeingLive(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	monday := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	friday := monday.Add(4 * 24 * time.Hour)

	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", monday, "evil.example", "worse.example"), 0); err != nil {
		t.Fatal(err)
	}
	res, err := st.ReconcileLifecycle(ctx, snap("f_a", friday, "worse.example"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Dropped != 1 {
		t.Errorf("dropped = %d, want 1", res.Dropped)
	}

	gone := mustLifecycle(t, st, "f_a", "evil.example")
	if gone.Live {
		t.Error("an indicator the feed no longer lists is still marked live")
	}
	if !gone.FirstSeen.Equal(monday) {
		t.Errorf("first seen = %s, want the original %s — dropping is not forgetting",
			gone.FirstSeen, monday)
	}
	if !gone.LastSeen.Equal(monday) {
		t.Errorf("last seen = %s, want %s: the last time the feed actually said so",
			gone.LastSeen, monday)
	}
}

// TestAnIndicatorThatComesBackKeepsItsOriginalFirstSeen.
//
// The reappearance rule, and the reason rows are marked rather than deleted. A
// domain a feed dropped on Tuesday and re-listed on Friday has one history: an
// analyst asking "how long have we known about this?" wants March, not Friday.
//
// The honest limit is stated in the documentation and tested below: once the
// retention prune has removed an off-live row, a reappearance is
// indistinguishable from a first sighting, because there is nothing left to
// distinguish it from.
func TestAnIndicatorThatComesBackKeepsItsOriginalFirstSeen(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	march := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", march, "evil.example"), 0); err != nil {
		t.Fatal(err)
	}
	// Dropped.
	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", march.Add(24*time.Hour)), 0); err != nil {
		t.Fatal(err)
	}
	// Back, months later.
	june := march.Add(90 * 24 * time.Hour)
	res, err := st.ReconcileLifecycle(ctx, snap("f_a", june, "evil.example"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 0 {
		t.Errorf("a reappearance was counted as %d new indicators; it is the same one", res.Added)
	}
	if res.Refreshed != 1 {
		t.Errorf("refreshed = %d, want 1", res.Refreshed)
	}

	l := mustLifecycle(t, st, "f_a", "evil.example")
	if !l.FirstSeen.Equal(march) {
		t.Errorf("first seen = %s after a gap, want the original %s", l.FirstSeen, march)
	}
	if !l.LastSeen.Equal(june) {
		t.Errorf("last seen = %s, want %s", l.LastSeen, june)
	}
	if !l.Live {
		t.Error("a re-listed indicator is not live again")
	}
}

// TestTwoFeedsListingTheSameDomainKeepTheirOwnHistories.
//
// Merging them would produce a first-seen belonging to neither feed. URLhaus
// having carried a domain since March says nothing about when a phishing list
// picked it up, and an analyst reading one feed's claim needs that feed's
// dates.
func TestTwoFeedsListingTheSameDomainKeepTheirOwnHistories(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	march := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	june := march.Add(90 * 24 * time.Hour)

	if _, err := st.ReconcileLifecycle(ctx, snap("f_urlhaus", march, "evil.example"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReconcileLifecycle(ctx, snap("f_phish", june, "evil.example"), 0); err != nil {
		t.Fatal(err)
	}

	if got := mustLifecycle(t, st, "f_urlhaus", "evil.example").FirstSeen; !got.Equal(march) {
		t.Errorf("urlhaus first seen = %s, want %s", got, march)
	}
	if got := mustLifecycle(t, st, "f_phish", "evil.example").FirstSeen; !got.Equal(june) {
		t.Errorf("phishing list first seen = %s, want %s", got, june)
	}
}

// TestTheCeilingDiscardsHistoryAndNeverTheLiveSet.
//
// The 1 GB machine is the reason this ceiling exists, and the direction it
// evicts in is the whole design. An off-live row is history; a live row is the
// times behind a block that could happen in the next second. Spending the
// second to keep the first would be losing the answer to the question somebody
// is about to ask.
func TestTheCeilingDiscardsHistoryAndNeverTheLiveSet(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

	// Six indicators, then four of them dropped: four rows of history.
	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", base,
		"a.example", "b.example", "c.example", "d.example", "e.example", "f.example"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", base.Add(time.Hour),
		"e.example", "f.example"), 0); err != nil {
		t.Fatal(err)
	}

	// A second feed arrives with three new indicators into a table capped at 6.
	res, err := st.ReconcileLifecycle(ctx, snap("f_b", base.Add(2*time.Hour),
		"x.example", "y.example", "z.example"), 6)
	if err != nil {
		t.Fatal(err)
	}
	if res.Evicted == 0 {
		t.Fatal("nothing was evicted, so the ceiling did nothing")
	}

	// Both live indicators of the first feed survived.
	for _, ind := range []string{"e.example", "f.example"} {
		l, err := st.LifecycleFor(ctx, "f_a", ind)
		if err != nil {
			t.Fatalf("the live indicator %s was evicted to make room for history", ind)
		}
		if !l.Live || !l.FirstSeen.Equal(base) {
			t.Errorf("%s: live=%v first=%s, want live with its original time", ind, l.Live, l.FirstSeen)
		}
	}

	st2, err := st.CountLifecycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st2.Live+st2.History > 6 {
		t.Errorf("the table holds %d rows, above the ceiling of 6", st2.Live+st2.History)
	}
}

// TestPastTheCeilingNewIndicatorsAreRejectedRatherThanEvictingLiveOnes.
//
// When there is no history left to discard, the table stops recording rather
// than spending live rows. The cost is that those indicators have unknown
// times — which is exactly what the zero value means and what the API reports.
// They still block: the live index is built from the feed, never from here.
func TestPastTheCeilingNewIndicatorsAreRejectedRatherThanEvictingLiveOnes(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", base, "a.example", "b.example"), 2); err != nil {
		t.Fatal(err)
	}
	res, err := st.ReconcileLifecycle(ctx, snap("f_b", base, "x.example", "y.example"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rejected != 2 {
		t.Errorf("rejected = %d, want 2", res.Rejected)
	}
	if res.Added != 0 {
		t.Errorf("added = %d past a full table", res.Added)
	}
	for _, ind := range []string{"a.example", "b.example"} {
		if _, err := st.LifecycleFor(ctx, "f_a", ind); err != nil {
			t.Errorf("the live indicator %s was evicted for a new one", ind)
		}
	}
}

// TestThePruneTakesHistoryAndLeavesTheLiveSetAlone.
//
// Both rows here are equally old, and that is the point. An earlier version of
// this test kept the live row recent, so it survived the prune for being new
// rather than for being live — and the test passed with the liveness guard
// removed entirely, which made it worthless.
//
// The case that discriminates is a feed that has not refreshed for months: a
// disabled feed, or a resolver that was switched off over a long holiday. Its
// listings are still live and still blocking, served from the cached copy, and
// their dates are still the explanation for every one of those blocks. Age is
// not a reason to discard them; only the feed dropping them is.
func TestThePruneTakesHistoryAndLeavesTheLiveSetAlone(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-200 * 24 * time.Hour).Truncate(time.Millisecond)

	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", old, "gone.example", "here.example"), 0); err != nil {
		t.Fatal(err)
	}
	// gone.example is dropped. here.example is still listed — and neither has
	// been touched since, so they are the same age.
	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", old, "here.example"), 0); err != nil {
		t.Fatal(err)
	}

	before := mustLifecycle(t, st, "f_a", "here.example")
	if !before.Live {
		t.Fatal("here.example is not live, so this test proves nothing")
	}
	if before.LastSeen.After(time.Now().UTC().Add(-90 * 24 * time.Hour)) {
		t.Fatal("the live row is newer than the cutoff, so it would survive on age alone")
	}

	n, err := st.PruneLifecycle(ctx, time.Now().UTC().Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("pruned %d rows, want 1", n)
	}
	if _, err := st.LifecycleFor(ctx, "f_a", "gone.example"); err == nil {
		t.Error("old history survived the prune")
	}
	l, err := st.LifecycleFor(ctx, "f_a", "here.example")
	if err != nil {
		t.Fatalf("a listing a feed still carries was pruned for being old: %v", err)
	}
	if !l.FirstSeen.Equal(old) {
		t.Errorf("a current listing's first seen was changed to %s by the prune", l.FirstSeen)
	}
}

// TestAFeedThatDidNotLoadIsNotReconciled.
//
// Reconcile reads absence as "the feed dropped it", so handing it a snapshot
// from a download that failed would mark the whole feed as no longer listing
// anything — turning one bad HTTP response into a wholesale loss of history.
// The guard is at the caller, and this pins the reason: an empty snapshot is a
// meaningful instruction here, not a no-op.
func TestAFeedThatDidNotLoadIsNotReconciled(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", base, "a.example", "b.example"), 0); err != nil {
		t.Fatal(err)
	}
	res, err := st.ReconcileLifecycle(ctx, snap("f_a", base.Add(time.Hour)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Dropped != 2 {
		t.Fatalf("an empty snapshot dropped %d indicators, want 2 — if this ever "+
			"becomes a no-op, the caller's guard against reconciling a failed "+
			"download stops being the thing that protects history", res.Dropped)
	}
}

// TestAnExpiryIsStoredWhenAFeedGivesOneAndNotInventedWhenItDoesNot.
func TestAnExpiryIsStoredWhenAFeedGivesOneAndNotInventedWhenItDoesNot(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	expiry := base.Add(30 * 24 * time.Hour)

	if _, err := st.ReconcileLifecycle(ctx, LifecycleSnapshot{
		FeedID: "f_a", At: base,
		Indicators: map[string]time.Time{
			"timed.example":   expiry,
			"untimed.example": {},
		},
	}, 0); err != nil {
		t.Fatal(err)
	}

	if got := mustLifecycle(t, st, "f_a", "timed.example").ExpiresAt; !got.Equal(expiry) {
		t.Errorf("expiry = %s, want %s", got, expiry)
	}
	if got := mustLifecycle(t, st, "f_a", "untimed.example").ExpiresAt; !got.IsZero() {
		t.Errorf("an expiry of %s was invented for a feed that gave none", got)
	}
}

// TestLoadingForAnIndexReadsTheLiveSetOnly.
//
// An off-live row describes something the feed has stopped listing, which by
// definition is not in the index being built. Loading it would be carrying
// history in memory that nothing can look up.
func TestLoadingForAnIndexReadsTheLiveSetOnly(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", base, "live.example", "dead.example"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", base.Add(time.Hour), "live.example"), 0); err != nil {
		t.Fatal(err)
	}

	byFeed, err := st.LoadLifecycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := byFeed["f_a"]["live.example"]; !ok {
		t.Error("the live indicator was not loaded")
	}
	if _, ok := byFeed["f_a"]["dead.example"]; ok {
		t.Error("history was loaded into an index that cannot look it up")
	}
	if got := byFeed["f_a"]["live.example"].FirstSeen; !got.Equal(base) {
		t.Errorf("first seen = %s, want %s", got, base)
	}
}

// TestTimesAreStoredToTheMillisecond.
//
// The honest precision of this table, pinned so that it is a documented
// property rather than something a future test discovers by failing. A
// millisecond is far finer than anything this is used for — feeds refresh
// twice a day — but a caller comparing a stored time against a raw time.Now()
// needs to know the round trip is lossy.
func TestTimesAreStoredToTheMillisecond(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	precise := time.Date(2026, 3, 2, 9, 0, 0, 123_456_789, time.UTC)

	if _, err := st.ReconcileLifecycle(ctx, snap("f_a", precise, "evil.example"), 0); err != nil {
		t.Fatal(err)
	}
	got := mustLifecycle(t, st, "f_a", "evil.example").FirstSeen
	if want := precise.Truncate(time.Millisecond); !got.Equal(want) {
		t.Errorf("stored %s, want %s", got, want)
	}
	if got.Equal(precise) {
		t.Error("nanoseconds survived the round trip; this test no longer describes the storage")
	}
}
