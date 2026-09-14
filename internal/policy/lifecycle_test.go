package policy_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

var (
	march = time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	june  = march.Add(90 * 24 * time.Hour)
)

// datedEngine builds an engine over an index whose listings carry dates, and
// hands back the holder so the index can be replaced mid-test.
func datedEngine(t *testing.T, allow []string, listed map[string]string,
	firstSeen, lastSeen time.Time) (*policy.Engine, *blocklist.Holder, string) {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()

	b := blocklist.NewBuilder(len(listed))
	for domain, cat := range listed {
		e := blocklist.Entry{Category: cat, FeedID: "f_threat", FeedName: "Threat feed"}
		if !firstSeen.IsZero() {
			e.FirstSeenUnixMs = firstSeen.UnixMilli()
		}
		b.Add(domain, e)
	}
	ix := b.Build()
	seen := map[string]int64{}
	if !lastSeen.IsZero() {
		seen["f_threat"] = lastSeen.UnixMilli()
	}
	ix.ApplyLifecycle(seen, nil)

	holder := blocklist.NewHolder()
	holder.Store(ix)

	p, err := st.CreatePolicy(ctx, store.PolicyInput{
		Name:         ptr("Dated"),
		Categories:   &[]string{"malware"},
		AllowDomains: &allow,
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	e := policy.NewEngine(st, holder)
	if err := e.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return e, holder, p.ID
}

// TestABlockCarriesTheListingDatesFromTheIndexThatDecided.
func TestABlockCarriesTheListingDatesFromTheIndexThatDecided(t *testing.T) {
	e, _, pid := datedEngine(t, nil, map[string]string{"evil.example": "malware"}, march, june)

	d := e.Evaluate(pid, "evil.example")
	if !d.Blocked || d.Basis == nil {
		t.Fatalf("not blocked: %+v", d)
	}
	if !d.Basis.Listing.FirstSeen.Equal(march) {
		t.Errorf("first seen = %s, want %s", d.Basis.Listing.FirstSeen, march)
	}
	if !d.Basis.Listing.LastSeen.Equal(june) {
		t.Errorf("last seen = %s, want the feed's refresh time %s", d.Basis.Listing.LastSeen, june)
	}
	if !d.Basis.Listing.Known() {
		t.Error("a listing with dates reports itself as unknown")
	}
}

// TestABlockWithNoRecordedDatesSaysSoRatherThanClaiming1970.
//
// The upgrade case at the layer that hands dates to the record. An
// installation that has been blocking for a year has no stored history, and
// every one of those decisions must carry "unknown" rather than a zero
// timestamp that renders as 1 January 1970.
func TestABlockWithNoRecordedDatesSaysSoRatherThanClaiming1970(t *testing.T) {
	e, _, pid := datedEngine(t, nil, map[string]string{"evil.example": "malware"},
		time.Time{}, time.Time{})

	d := e.Evaluate(pid, "evil.example")
	if !d.Blocked || d.Basis == nil {
		t.Fatal("not blocked")
	}
	if d.Basis.Listing.Known() {
		t.Errorf("dates were reported as known: %+v", d.Basis.Listing)
	}
	if !d.Basis.Listing.FirstSeen.IsZero() {
		t.Errorf("first seen = %s, want the zero time", d.Basis.Listing.FirstSeen)
	}
}

// TestTheDatesOnADecisionDoNotChangeWhenTheIndexDoes.
//
// The load-bearing snapshot property, at the layer that copies. A decision
// made against Monday's index keeps Monday's dates after the index has been
// replaced — because they were copied onto the decision, not looked up from
// whatever happens to be live when somebody asks.
func TestTheDatesOnADecisionDoNotChangeWhenTheIndexDoes(t *testing.T) {
	e, holder, pid := datedEngine(t, nil, map[string]string{"evil.example": "malware"}, march, june)

	d := e.Evaluate(pid, "evil.example")
	if !d.Blocked || d.Basis == nil {
		t.Fatal("not blocked")
	}
	before := d.Basis.Listing

	// The feed drops the domain and the index is replaced under the engine.
	holder.Store(blocklist.NewBuilder(1).Build())

	if !d.Basis.Listing.FirstSeen.Equal(before.FirstSeen) {
		t.Errorf("first seen changed from %s to %s when the index was replaced",
			before.FirstSeen, d.Basis.Listing.FirstSeen)
	}
	if !d.Basis.Listing.FirstSeen.Equal(march) {
		t.Errorf("first seen = %s, want %s", d.Basis.Listing.FirstSeen, march)
	}
	// And the domain genuinely stopped blocking, so the index really did move
	// and this test is not passing on a stale snapshot.
	if again := e.Evaluate(pid, "evil.example"); again.Blocked {
		t.Error("the domain still blocks after being dropped from the index")
	}
}

// TestAnAllowListWinCarriesTheDatesOfWhatItBeat.
//
// "Why is this malware domain resolving?" is half-answered by naming the feed.
// The other half is how long it has been saying so: a listing from this
// morning and one from eighteen months ago call for different responses.
func TestAnAllowListWinCarriesTheDatesOfWhatItBeat(t *testing.T) {
	e, _, pid := datedEngine(t, []string{"vendor.example"},
		map[string]string{"vendor.example": "malware"}, march, june)

	d := e.Evaluate(pid, "vendor.example")
	if d.Blocked {
		t.Fatal("the allow-list did not win")
	}
	if d.Basis.OverrodeFeedName != "Threat feed" {
		t.Fatalf("the override names %q", d.Basis.OverrodeFeedName)
	}
	if !d.Basis.OverrodeListing.FirstSeen.Equal(march) {
		t.Errorf("the overridden listing's first seen = %s, want %s",
			d.Basis.OverrodeListing.FirstSeen, march)
	}
	if !d.Basis.OverrodeListing.LastSeen.Equal(june) {
		t.Errorf("the overridden listing's last seen = %s, want %s",
			d.Basis.OverrodeListing.LastSeen, june)
	}
}

// TestADomainGoneFromTheIndexCannotBlock.
//
// The primary aged-out mechanism, and it is deliberately not a date
// comparison: a domain the feed has stopped listing is simply not in the index
// the next rebuild produces, so there is nothing to match. This pins that,
// because an implementation that kept off-live indicators in memory to carry
// their history would also keep them blocking.
func TestADomainGoneFromTheIndexCannotBlock(t *testing.T) {
	e, holder, pid := datedEngine(t, nil,
		map[string]string{"evil.example": "malware", "worse.example": "malware"}, march, june)

	if d := e.Evaluate(pid, "evil.example"); !d.Blocked {
		t.Fatal("not blocking to begin with")
	}

	// A rebuild in which the feed no longer lists evil.example.
	b := blocklist.NewBuilder(1)
	b.Add("worse.example", blocklist.Entry{
		Category: "malware", FeedID: "f_threat", FeedName: "Threat feed",
		FirstSeenUnixMs: march.UnixMilli(),
	})
	holder.Store(b.Build())

	if d := e.Evaluate(pid, "evil.example"); d.Blocked {
		t.Error("a domain the feed has stopped listing still blocks")
	}
	if d := e.Evaluate(pid, "worse.example"); !d.Blocked {
		t.Error("a domain the feed still lists stopped blocking")
	}
}

// TestAnExpiredListingCannotBlockThroughThePolicyEngine, so the gate is in
// force on the path a real query takes rather than only in the index's own
// tests.
func TestAnExpiredListingCannotBlockThroughThePolicyEngine(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()

	b := blocklist.NewBuilder(2)
	b.Add("expired.example", blocklist.Entry{
		Category: "malware", FeedID: "f_threat", FeedName: "Threat feed",
		ExpiresAtUnixMs: time.Now().Add(-time.Hour).UnixMilli(),
	})
	b.Add("current.example", blocklist.Entry{
		Category: "malware", FeedID: "f_threat", FeedName: "Threat feed",
		ExpiresAtUnixMs: time.Now().Add(24 * time.Hour).UnixMilli(),
	})
	holder := blocklist.NewHolder()
	holder.Store(b.Build())

	p, err := st.CreatePolicy(ctx, store.PolicyInput{
		Name: ptr("Expiry"), Categories: &[]string{"malware"},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := policy.NewEngine(st, holder)
	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	if d := e.Evaluate(p.ID, "expired.example"); d.Blocked {
		t.Error("an expired listing blocked a real query")
	}
	if d := e.Evaluate(p.ID, "current.example"); !d.Blocked {
		t.Error("a listing that has not expired stopped blocking")
	}
}
