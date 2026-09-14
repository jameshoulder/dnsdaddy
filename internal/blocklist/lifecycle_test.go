package blocklist

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func indexWith(entries map[string]Entry) *Index {
	b := NewBuilder(16)
	for d, e := range entries {
		b.Add(d, e)
	}
	return b.Build()
}

// TestAnExpiredListingCannotBlock.
//
// A feed publishing an expiry is saying the listing stops being current at
// that moment. Blocking past it would be acting on intelligence its own author
// has withdrawn — and the operator would have no way to find out, because
// every surface would still report the domain as listed.
func TestAnExpiredListingCannotBlock(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	enabled := map[string]bool{"malware": true}

	ix := indexWith(map[string]Entry{
		"live.example": {Category: "malware", FeedID: "f_a", FeedName: "A",
			ExpiresAtUnixMs: now.Add(24 * time.Hour).UnixMilli()},
		"expired.example": {Category: "malware", FeedID: "f_a", FeedName: "A",
			ExpiresAtUnixMs: now.Add(-time.Second).UnixMilli()},
		"undated.example": {Category: "malware", FeedID: "f_a", FeedName: "A"},
	})

	if _, ok := ix.lookupEnabledAt("expired.example", enabled, now); ok {
		t.Error("an expired listing blocked")
	}
	if _, ok := ix.lookupEnabledAt("live.example", enabled, now); !ok {
		t.Error("a listing that has not expired did not block")
	}
	// No expiry means it never expires, which is every feed shipped today.
	if _, ok := ix.lookupEnabledAt("undated.example", enabled, now); !ok {
		t.Error("a listing with no expiry was treated as expired")
	}
	// And the same entry blocks before its expiry and not after, so this is
	// about time rather than about the field being set at all.
	before := now.Add(-48 * time.Hour)
	if _, ok := ix.lookupEnabledAt("expired.example", enabled, before); !ok {
		t.Error("a listing did not block before its expiry")
	}
}

// TestAnExpiredClaimDoesNotShadowALiveParent.
//
// What expires is one claim, not the name. A subdomain whose listing has
// lapsed must fall through to a parent that is still listed, exactly as a
// subdomain listed under a category the policy does not enable already does.
func TestAnExpiredClaimDoesNotShadowALiveParent(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	ix := indexWith(map[string]Entry{
		"evil.example": {Category: "malware", FeedID: "f_a", FeedName: "A"},
		"login.evil.example": {Category: "malware", FeedID: "f_b", FeedName: "B",
			ExpiresAtUnixMs: now.Add(-time.Hour).UnixMilli()},
	})

	got, ok := ix.lookupEnabledAt("login.evil.example", map[string]bool{"malware": true}, now)
	if !ok {
		t.Fatal("an expired subdomain listing hid a parent that is still listed")
	}
	if got.FeedID != "f_a" {
		t.Errorf("blocked by %q, want the parent's feed f_a", got.FeedID)
	}
}

// TestListingDatesReachTheIndexAndSurviveARebuild.
//
// The end-to-end path: a refresh records what each feed lists, a later refresh
// reads the dates back, and an entry in the live index carries the date the
// feed first listed it rather than the date of the most recent download.
func TestListingDatesReachTheIndexAndSurviveARebuild(t *testing.T) {
	st := newLifecycleStore(t)
	ctx := context.Background()
	march := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

	if _, err := st.ReconcileLifecycle(ctx, store.LifecycleSnapshot{
		FeedID: "f_a", At: march,
		Indicators: map[string]time.Time{"evil.example": {}},
	}, 0); err != nil {
		t.Fatal(err)
	}

	byFeed, err := st.LoadLifecycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ix := indexWith(map[string]Entry{
		"evil.example": {Category: "malware", FeedID: "f_a", FeedName: "A"},
	})
	june := march.Add(90 * 24 * time.Hour)
	ix.ApplyLifecycle(map[string]int64{"f_a": june.UnixMilli()},
		func(feedID, domain string) (LifecycleTimes, bool) {
			l, ok := byFeed[feedID][domain]
			if !ok {
				return LifecycleTimes{}, false
			}
			return LifecycleTimes{FirstSeenUnixMs: l.FirstSeen.UnixMilli()}, true
		})

	e, ok := ix.Lookup("evil.example")
	if !ok {
		t.Fatal("not in the index")
	}
	if !e.FirstSeen().Equal(march) {
		t.Errorf("first seen = %s, want %s — the rebuild used its own time", e.FirstSeen(), march)
	}
	if got := ix.LastSeenFor("f_a"); !got.Equal(june) {
		t.Errorf("last seen = %s, want the refresh time %s", got, june)
	}
}

// TestAnIndexWithNoStoredDatesReportsUnknownRatherThan1970.
//
// The upgrade case. An installation that has been blocking for a year has no
// stored dates for anything, and every one of those entries must say "unknown"
// — not "first listed on 1 January 1970", which is a specific, actionable and
// false claim.
func TestAnIndexWithNoStoredDatesReportsUnknownRatherThan1970(t *testing.T) {
	ix := indexWith(map[string]Entry{
		"evil.example": {Category: "malware", FeedID: "f_a", FeedName: "A"},
	})
	ix.ApplyLifecycle(nil, nil)

	e, _ := ix.Lookup("evil.example")
	if !e.FirstSeen().IsZero() {
		t.Errorf("first seen = %s on an index with no stored dates, want the zero time", e.FirstSeen())
	}
	if !e.ExpiresAt().IsZero() {
		t.Errorf("expiry = %s, want the zero time", e.ExpiresAt())
	}
	if e.Expired(time.Now()) {
		t.Error("an entry with no expiry was treated as expired")
	}
	if got := ix.LastSeenFor("f_a"); !got.IsZero() {
		t.Errorf("last seen = %s, want the zero time", got)
	}
	// And it still blocks, because dates are bookkeeping and blocking is not.
	if _, ok := ix.LookupEnabled("evil.example", map[string]bool{"malware": true}); !ok {
		t.Error("an entry with no dates stopped blocking")
	}
}

// TestFurtherClaimsCarryTheirOwnFeedsDates.
//
// A domain two feeds both list has two histories, and the second feed's claim
// is the one a policy enabling only its category will block on. Stamping only
// the primary claim would leave that block explained with no dates at all, or
// worse, with the other feed's.
func TestFurtherClaimsCarryTheirOwnFeedsDates(t *testing.T) {
	march := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	june := march.Add(90 * 24 * time.Hour)

	b := NewBuilder(16)
	b.Add("evil.example", Entry{Category: "malware", FeedID: "f_mal", FeedName: "Malware list"})
	b.Add("evil.example", Entry{Category: "ads", FeedID: "f_ads", FeedName: "Ad list"})
	ix := b.Build()

	ix.ApplyLifecycle(nil, func(feedID, domain string) (LifecycleTimes, bool) {
		switch feedID {
		case "f_mal":
			return LifecycleTimes{FirstSeenUnixMs: march.UnixMilli()}, true
		case "f_ads":
			return LifecycleTimes{FirstSeenUnixMs: june.UnixMilli()}, true
		}
		return LifecycleTimes{}, false
	})

	primary, _ := ix.LookupEnabled("evil.example", map[string]bool{"malware": true})
	if !primary.FirstSeen().Equal(march) {
		t.Errorf("the malware claim reports %s, want %s", primary.FirstSeen(), march)
	}
	further, ok := ix.LookupEnabled("evil.example", map[string]bool{"ads": true})
	if !ok {
		t.Fatal("the further claim did not block an ads-only policy")
	}
	if !further.FirstSeen().Equal(june) {
		t.Errorf("the ad-list claim reports %s, want its own %s", further.FirstSeen(), june)
	}
}

// TestIndicatorsReportsEveryFeedsOwnClaims, because that is what a refresh
// hands the store and a missing claim would be read as the feed having dropped
// the domain.
func TestIndicatorsReportsEveryFeedsOwnClaims(t *testing.T) {
	b := NewBuilder(16)
	b.Add("evil.example", Entry{Category: "malware", FeedID: "f_mal", FeedName: "Malware list"})
	b.Add("evil.example", Entry{Category: "ads", FeedID: "f_ads", FeedName: "Ad list"})
	b.Add("tracker.example", Entry{Category: "ads", FeedID: "f_ads", FeedName: "Ad list"})
	ix := b.Build()

	got := ix.Indicators()
	if _, ok := got["f_mal"]["evil.example"]; !ok {
		t.Error("the primary claim's feed does not list the domain")
	}
	if _, ok := got["f_ads"]["evil.example"]; !ok {
		t.Error("the further claim's feed does not list the domain it claimed")
	}
	if len(got["f_ads"]) != 2 {
		t.Errorf("the ad list contributed %d indicators, want 2", len(got["f_ads"]))
	}
}

// newLifecycleStore opens a database for the tests above.
func newLifecycleStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestABrokenLifecycleStoreDoesNotStopTheResolverBlocking.
//
// The rule the whole subsystem is subordinate to: blocking is built from the
// feeds, and the listing dates only say when. An installation whose database
// is read-only, full, or momentarily locked keeps filtering — with dates that
// have gone stale, and a doctor check that says so.
//
// Refusing to publish an index because a history table was unwritable would
// turn a bookkeeping fault into a protection outage, which is the wrong
// failure by a wide margin.
func TestABrokenLifecycleStoreDoesNotStopTheResolverBlocking(t *testing.T) {
	st := newLifecycleStore(t)
	// Close it underneath, so every lifecycle call fails the way a database
	// on a full disk would.
	st.Close()

	m := &Manager{store: st, log: discardLogger()}
	b := NewBuilder(4)
	b.Add("evil.example", Entry{Category: "malware", FeedID: "f_a", FeedName: "A"})
	ix := b.Build()

	m.applyLifecycle(context.Background(), ix, []string{"f_a"})

	if _, ok := ix.LookupEnabled("evil.example", map[string]bool{"malware": true}); !ok {
		t.Error("a broken listing-date store stopped a domain being blocked")
	}
	if m.LifecycleFailures() == 0 {
		t.Error("a failure was not counted, so an operator has no way to know the dates are stale")
	}
	// And the dates are simply unknown, which is what the zero value means.
	e, _ := ix.Lookup("evil.example")
	if !e.FirstSeen().IsZero() {
		t.Errorf("first seen = %s, want unknown", e.FirstSeen())
	}
}

// TestAFeedThatDidNotLoadKeepsItsDates.
//
// A feed whose cached copy is missing or damaged contributed nothing to this
// index. Reconciling it against an empty set would read that as the feed
// having dropped everything, and one unreadable file would wipe a feed's whole
// history — silently, and at exactly the moment an operator most needs it.
func TestAFeedThatDidNotLoadKeepsItsDates(t *testing.T) {
	st := newLifecycleStore(t)
	ctx := context.Background()
	march := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

	if _, err := st.ReconcileLifecycle(ctx, store.LifecycleSnapshot{
		FeedID: "f_broken", At: march,
		Indicators: map[string]time.Time{"evil.example": {}},
	}, 0); err != nil {
		t.Fatal(err)
	}

	// A rebuild in which f_broken did not load, so it is absent from `loaded`
	// and contributes nothing to the index.
	m := &Manager{store: st, log: discardLogger()}
	b := NewBuilder(4)
	b.Add("other.example", Entry{Category: "malware", FeedID: "f_ok", FeedName: "OK"})
	m.applyLifecycle(ctx, b.Build(), []string{"f_ok"})

	l, err := st.LifecycleFor(ctx, "f_broken", "evil.example")
	if err != nil {
		t.Fatalf("the unreadable feed's history was deleted: %v", err)
	}
	if !l.Live {
		t.Error("a feed that could not be read was recorded as having dropped its domains")
	}
	if !l.FirstSeen.Equal(march) {
		t.Errorf("first seen = %s, want the original %s", l.FirstSeen, march)
	}

	// And a feed that DID load is reconciled, so this is a distinction rather
	// than the reconcile never running.
	if _, err := st.LifecycleFor(ctx, "f_ok", "other.example"); err != nil {
		t.Errorf("the feed that loaded was not recorded: %v", err)
	}
}

// TestConcurrentLookupsWhileTheIndexIsReplaced is the race-detector case: the
// refresh goroutine stamps dates onto a new index and swaps it in while query
// goroutines read the old one.
func TestConcurrentLookupsWhileTheIndexIsReplaced(t *testing.T) {
	holder := NewHolder()
	enabled := map[string]bool{"malware": true}
	build := func(first int64) *Index {
		b := NewBuilder(8)
		b.Add("evil.example", Entry{
			Category: "malware", FeedID: "f_a", FeedName: "A",
			FirstSeenUnixMs: first,
		})
		ix := b.Build()
		ix.ApplyLifecycle(map[string]int64{"f_a": first}, nil)
		return ix
	}
	holder.Store(build(1))

	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				ix := holder.Load()
				if e, ok := ix.LookupEnabled("evil.example", enabled); ok {
					_ = e.FirstSeen()
					_ = ix.LastSeenFor(e.FeedID)
				}
			}
		}()
	}
	for i := int64(2); i < 60; i++ {
		holder.Store(build(i))
	}
	close(done)
	wg.Wait()
}

// discardLogger keeps the manager's warnings out of the test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestCaseAndDotVariantsAreOneListing.
//
// The lifecycle table is keyed by the same normalised name the live index
// uses, so "EVIL.example.", "evil.example" and "Evil.Example" are one history
// rather than three. Two feeds spelling the same domain differently — and they
// do — must not produce a first-seen for each spelling, each one wrong.
func TestCaseAndDotVariantsAreOneListing(t *testing.T) {
	st := newLifecycleStore(t)
	ctx := context.Background()
	march := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

	// A feed file written in three spellings of one name.
	var lines string
	for _, spelling := range []string{"EVIL.example", "evil.example.", "Evil.Example"} {
		lines += spelling + "\n"
	}
	b := NewBuilder(8)
	e := Entry{Category: "malware", FeedID: "f_a", FeedName: "A"}
	n := 0
	for _, line := range splitLines(lines) {
		if d, ok := parseLine(line, FormatDomains); ok {
			b.Add(d, e)
			n++
		}
	}
	if n != 3 {
		t.Fatalf("the parser accepted %d of 3 spellings; this test is not exercising them", n)
	}
	ix := b.Build()

	if got := ix.Len(); got != 1 {
		t.Fatalf("the index holds %d domains for three spellings of one name", got)
	}

	m := &Manager{store: st, log: discardLogger()}
	m.applyLifecycle(ctx, ix, []string{"f_a"})

	// Exactly one row, under the normalised spelling.
	stats, err := st.CountLifecycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Live != 1 {
		t.Errorf("%d rows recorded for three spellings of one name, want 1", stats.Live)
	}
	if _, err := st.LifecycleFor(ctx, "f_a", "evil.example"); err != nil {
		t.Errorf("no row under the normalised name: %v", err)
	}

	// And a second refresh of a differently-spelled file does not create a
	// second history or reset the first.
	if _, err := st.ReconcileLifecycle(ctx, store.LifecycleSnapshot{
		FeedID: "f_a", At: march.Add(24 * time.Hour),
		Indicators: map[string]time.Time{"evil.example": {}},
	}, 0); err != nil {
		t.Fatal(err)
	}
	stats, err = st.CountLifecycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Live+stats.History != 1 {
		t.Errorf("%d rows after a second refresh, want 1", stats.Live+stats.History)
	}
}

// splitLines is a small helper so the test above reads like a feed file.
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
