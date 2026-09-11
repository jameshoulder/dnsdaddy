package recursive

import (
	"net/netip"
	"testing"
	"time"
)

// The server preference table, tested directly.
//
// Directly rather than through a resolution, because the first attempt at this
// went through the laboratory and proved nothing: the "dead" nameserver name
// was glued to a live address, so no timeout ever happened and the test passed
// against a resolver with no memory at all. Ordering is an arithmetic property
// of this table and is worth testing where it can actually be observed.
// Survivability through a real hierarchy is covered separately by
// TestOneDeadNameserverAmongSeveralIsSurvivable.

func addr(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

type fakeClock struct{ at time.Time }

func (c *fakeClock) now() time.Time      { return c.at }
func (c *fakeClock) add(d time.Duration) { c.at = c.at.Add(d) }

// A server that failed is tried after one that answered.
//
// The defect this exists to prevent: servers tried in a fixed rotation, a dead
// one discovered by waiting for it to time out, and nothing learned — so the
// same timeout is paid again on the next query, and the next.
func TestAFailedServerSortsBehindAWorkingOne(t *testing.T) {
	c := &fakeClock{at: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	tbl := newServerTable(c.now)

	good, bad := addr("192.0.2.1:53"), addr("192.0.2.2:53")
	tbl.success(good, 20*time.Millisecond)
	tbl.failure(bad)

	got := tbl.order([]netip.AddrPort{bad, good})
	if got[0] != good {
		t.Errorf("order = %v, want the server that answered first", got)
	}
}

// Faster wins between two servers that both work.
func TestTheFasterServerIsPreferred(t *testing.T) {
	c := &fakeClock{at: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	tbl := newServerTable(c.now)

	near, far := addr("192.0.2.1:53"), addr("192.0.2.2:53")
	tbl.success(far, 300*time.Millisecond)
	tbl.success(near, 10*time.Millisecond)

	got := tbl.order([]netip.AddrPort{far, near})
	if got[0] != near {
		t.Errorf("order = %v, want the nearer server first", got)
	}
}

// One slow answer does not condemn a server.
//
// Smoothed rather than last-seen: a single slow reply is weather, not a
// property of the machine, and a resolver that reordered on every sample would
// oscillate.
func TestOneSlowAnswerDoesNotDisplaceAConsistentlyFastServer(t *testing.T) {
	c := &fakeClock{at: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	tbl := newServerTable(c.now)

	steady, blip := addr("192.0.2.1:53"), addr("192.0.2.2:53")
	for i := 0; i < 10; i++ {
		tbl.success(steady, 10*time.Millisecond)
		tbl.success(blip, 12*time.Millisecond)
	}
	// One bad afternoon for the second server.
	tbl.success(blip, 900*time.Millisecond)

	got := tbl.order([]netip.AddrPort{blip, steady})
	if got[0] != steady {
		t.Errorf("order = %v, want the steady server first", got)
	}
	// But it is not banished either: one sample moved it, it did not delete
	// it.
	if len(got) != 2 {
		t.Fatalf("order dropped a server: %v", got)
	}
}

// A penalty decays, so a recovered server comes back.
//
// Never retrying a failed server would be wrong twice: it would strand a zone
// whose servers all failed during an outage of ours, and it would let anyone
// who can drop packets to one server pin all this resolver's traffic onto
// another.
func TestAPenaltyDecaysSoARecoveredServerReturns(t *testing.T) {
	c := &fakeClock{at: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	tbl := newServerTable(c.now)

	fell, other := addr("192.0.2.1:53"), addr("192.0.2.2:53")
	tbl.success(fell, 5*time.Millisecond)
	tbl.success(other, 40*time.Millisecond)
	tbl.failure(fell)

	if got := tbl.order([]netip.AddrPort{fell, other}); got[0] != other {
		t.Fatalf("immediately after a failure the order is %v, want the other server first", got)
	}

	// A minute later the penalty has gone and its faster round trip wins
	// again.
	c.add(time.Minute)
	if got := tbl.order([]netip.AddrPort{fell, other}); got[0] != fell {
		t.Errorf("a minute after one failure the order is %v; the penalty is not decaying "+
			"and a server that recovered would never be tried first again", got)
	}
}

// A success clears the penalty rather than making the server serve it out.
func TestASuccessClearsThePenaltyItHasDisproved(t *testing.T) {
	c := &fakeClock{at: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	tbl := newServerTable(c.now)

	a, b := addr("192.0.2.1:53"), addr("192.0.2.2:53")
	tbl.success(a, 5*time.Millisecond)
	tbl.success(b, 40*time.Millisecond)
	for i := 0; i < 5; i++ {
		tbl.failure(a)
	}
	if got := tbl.order([]netip.AddrPort{a, b}); got[0] != b {
		t.Fatalf("after five failures the order is %v", got)
	}

	tbl.success(a, 5*time.Millisecond)
	if got := tbl.order([]netip.AddrPort{a, b}); got[0] != a {
		t.Errorf("order after a success is %v; a server that is demonstrably working "+
			"is still serving out a penalty it has disproved", got)
	}
}

// An untried server sorts ahead of one known to be slow and behind one known to
// be fast.
//
// So a zone that adds a nameserver gets it used rather than having to earn its
// way past everything with a measurement, and a working fast server is not
// displaced by an untried one on every query.
func TestAnUntriedServerSortsBetweenFastAndSlow(t *testing.T) {
	c := &fakeClock{at: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	tbl := newServerTable(c.now)

	fast, slow, untried := addr("192.0.2.1:53"), addr("192.0.2.2:53"), addr("192.0.2.3:53")
	tbl.success(fast, 5*time.Millisecond)
	tbl.success(slow, 400*time.Millisecond)

	got := tbl.order([]netip.AddrPort{slow, untried, fast})
	if got[0] != fast {
		t.Errorf("order = %v, want the measured fast server first", got)
	}
	if got[1] != untried {
		t.Errorf("order = %v, want the untried server ahead of the known-slow one", got)
	}
}

// The ordering is stable, so a failure is reproducible.
func TestTheOrderingIsDeterministicForUnmeasuredServers(t *testing.T) {
	c := &fakeClock{at: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	tbl := newServerTable(c.now)

	in := []netip.AddrPort{addr("192.0.2.3:53"), addr("192.0.2.1:53"), addr("192.0.2.2:53")}
	first := tbl.order(in)
	for i := 0; i < 5; i++ {
		got := tbl.order(in)
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("the order varies between calls: %v then %v", first, got)
			}
		}
	}
	// And the caller's slice is untouched: it comes from a cached delegation
	// that every other resolution shares.
	if in[0] != addr("192.0.2.3:53") {
		t.Errorf("order reordered the caller's slice in place: %v", in)
	}
}

// The table is bounded. Addresses arrive from delegations, which arrive from
// the network, so this is a budget rather than an expectation.
func TestTheServerTableIsBounded(t *testing.T) {
	c := &fakeClock{at: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	tbl := newServerTable(c.now)

	for i := 0; i < maxServerStats*2; i++ {
		c.add(time.Millisecond)
		tbl.success(netip.AddrPortFrom(netip.AddrFrom4([4]byte{
			10, byte(i >> 16), byte(i >> 8), byte(i),
		}), 53), 10*time.Millisecond)
	}

	tbl.mu.Lock()
	size := len(tbl.by)
	tbl.mu.Unlock()

	if size > maxServerStats {
		t.Errorf("the table holds %d entries, past its bound of %d", size, maxServerStats)
	}
	if size == 0 {
		t.Error("the table evicted everything")
	}
}

// A delegation is held for as long as the parent said, not for a flat ten
// minutes.
//
// The value this replaces was hardcoded and wrong in both directions. A zone
// with a two-day NS TTL was re-resolved a hundred and forty times more often
// than it asked to be; a zone with a sixty-second one — the shape of a zone in
// the middle of moving its nameservers — was held for ten times too long,
// pointing at servers that may no longer serve it.
func TestADelegationIsHeldForTheLifetimeTheParentGave(t *testing.T) {
	c := &fakeClock{at: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	cache := NewCache(CacheOptions{Now: c.now, MaxTTL: 48 * time.Hour})

	glue := map[string][]netip.Addr{
		"ns1.example.com.": {netip.MustParseAddr("192.0.2.1")},
	}
	// Sixty seconds, as a zone mid-migration publishes.
	cache.PutDelegation("example.com.", []string{"ns1.example.com."}, glue, 60)

	if _, _, ok := cache.BestDelegation("www.example.com."); !ok {
		t.Fatal("the delegation was not cached at all")
	}
	c.add(90 * time.Second)
	if zone, _, ok := cache.BestDelegation("www.example.com."); ok {
		t.Errorf("a delegation with a 60-second TTL was still served for %s after "+
			"90 seconds; the resolver would be using nameservers the parent has "+
			"stopped pointing at", zone)
	}

	// And a long-lived one is kept, rather than being discarded on a schedule
	// of our own choosing.
	cache.PutDelegation("example.org.", []string{"ns1.example.org."},
		map[string][]netip.Addr{"ns1.example.org.": {netip.MustParseAddr("192.0.2.2")}},
		2*24*3600)
	c.add(time.Hour)
	if _, _, ok := cache.BestDelegation("www.example.org."); !ok {
		t.Error("a delegation with a two-day TTL was discarded after an hour")
	}
}

// A zero TTL does not turn every query into a walk from the root.
//
// A bound against a hostile input rather than a lifetime of our own choosing. A
// zone publishing NS records with a TTL of zero — by accident or on purpose —
// would otherwise aim a denial of service at this resolver and at the root
// servers, one walk per query for as long as it liked.
func TestAZeroDelegationTTLIsFlooredRatherThanObeyed(t *testing.T) {
	c := &fakeClock{at: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	cache := NewCache(CacheOptions{Now: c.now})

	cache.PutDelegation("example.com.", []string{"ns1.example.com."},
		map[string][]netip.Addr{"ns1.example.com.": {netip.MustParseAddr("192.0.2.1")}}, 0)

	if _, _, ok := cache.BestDelegation("www.example.com."); !ok {
		t.Fatal("a zero-TTL delegation was not cached at all; every query under " +
			"this zone would walk from the root")
	}
	c.add(minDelegationTTL + time.Second)
	if _, _, ok := cache.BestDelegation("www.example.com."); ok {
		t.Error("the floor became a lifetime; a zero-TTL delegation outlived its floor")
	}
}
