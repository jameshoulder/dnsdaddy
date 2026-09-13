package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/firstseen"
	"github.com/jameshoulder/dnsdaddy/internal/ratelimit"
	"github.com/jameshoulder/dnsdaddy/internal/rebind"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// indexed builds a harness whose handler carries a running first-seen index
// sharing the harness's store.
func indexed(t *testing.T, h *testHarness, cfg firstseen.Config) *firstseen.Index {
	t.Helper()
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 10 * time.Millisecond
	}
	idx := firstseen.New(h.store, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	go idx.Run(ctx)
	t.Cleanup(func() { cancel(); idx.Wait() })
	return idx
}

// waitRows blocks until the index has written at least n rows.
func waitRows(t *testing.T, st *store.Store, n int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err := st.CountFirstSeen(context.Background())
		if err != nil {
			t.Fatalf("CountFirstSeen: %v", err)
		}
		if got >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	got, _ := st.CountFirstSeen(context.Background())
	t.Fatalf("index reached %d rows, want at least %d", got, n)
}

func rows(t *testing.T, st *store.Store) int64 {
	t.Helper()
	n, err := st.CountFirstSeen(context.Background())
	if err != nil {
		t.Fatalf("CountFirstSeen: %v", err)
	}
	return n
}

// TestTheIndexDoesNotChangeTheWire is the load-bearing test of this PR.
//
// This engine is observe-only, which is a claim about bytes. The same query
// answered by a handler with an index and one without must produce responses
// that are identical field for field — rcode, flags, every record — because
// the moment a statistics table can alter an answer it stops being a
// statistics table and becomes an undocumented filter.
func TestTheIndexDoesNotChangeTheWire(t *testing.T) {
	ctx := context.Background()

	without := newHarness(t, map[string]string{"evil.example": "malware"})
	with := newHarness(t, map[string]string{"evil.example": "malware"})
	idx := indexed(t, with, firstseen.Config{})
	with.handler.firstSeen = idx

	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{"example.com", dns.TypeA},
		{"example.com", dns.TypeAAAA},
		{"evil.example", dns.TypeA},    // blocked by policy
		{"nothing.example", dns.TypeA}, // resolves, no answer records
		{"printer", dns.TypeA},         // no registered domain
		{"deep.a.b.example.co.uk", dns.TypeA},
	} {
		a := without.handler.Handle(ctx, query(tc.name, tc.qtype), clientMeta("10.0.0.1"))
		b := with.handler.Handle(ctx, query(tc.name, tc.qtype), clientMeta("10.0.0.1"))

		if a == nil || b == nil {
			t.Fatalf("%s: one handler returned no response (%v / %v)", tc.name, a, b)
		}
		// Message IDs are random per query, so compare everything else.
		b.Id = a.Id
		if a.String() != b.String() {
			t.Errorf("%s/%s: the index changed the answer\nwithout:\n%s\nwith:\n%s",
				tc.name, dns.TypeToString[tc.qtype], a.String(), b.String())
		}
	}

	// And the index did its job while changing nothing.
	waitRows(t, with.store, 1)
	if rows(t, without.store) != 0 {
		t.Error("the index-less handler wrote index rows")
	}
}

// TestABlockedNameIsStillIndexed. Novelty of a blocked name is exactly what a
// hunt wants — a device suddenly asking for a never-before-seen domain that
// the blocklist happens to know is more interesting, not less. The index is
// not a blocklist.
func TestABlockedNameIsStillIndexed(t *testing.T) {
	h := newHarness(t, map[string]string{"evil.example": "malware"})
	h.handler.firstSeen = indexed(t, h, firstseen.Config{})
	ctx := context.Background()

	resp := h.handler.Handle(ctx, query("evil.example", dns.TypeA), clientMeta("10.0.0.2"))
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("the name was not blocked (rcode %s); the test proves nothing",
			dns.RcodeToString[resp.Rcode])
	}
	waitRows(t, h.store, 1)

	if _, err := h.store.LookupFirstSeen(ctx, "evil.example"); err != nil {
		t.Error("a blocked name was not indexed")
	}
}

// TestAResolutionFailureIsStillIndexed. The question was asked and the name
// was observed; whether an upstream could answer it is a different fact.
func TestAResolutionFailureIsStillIndexed(t *testing.T) {
	// An upstream that nothing is listening on: every lookup fails.
	h := newHarnessAgainstUpstream(t, "127.0.0.1:1")
	h.handler.firstSeen = indexed(t, h, firstseen.Config{})
	ctx := context.Background()

	resp := h.handler.Handle(ctx, query("unreachable.example", dns.TypeA), clientMeta("10.0.0.3"))
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL to index, got %s", dns.RcodeToString[resp.Rcode])
	}
	waitRows(t, h.store, 1)
	if _, err := h.store.LookupFirstSeen(ctx, "unreachable.example"); err != nil {
		t.Error("a name whose resolution failed was not indexed")
	}
}

// TestAnACLRefusedClientCannotGrowTheIndex. A source that may not use this
// resolver at all must not be able to write to its tables — otherwise the
// index is a way for an unauthorised client to consume disk, which is the same
// objection that keeps the ACL refusal out of the query log.
func TestAnACLRefusedClientCannotGrowTheIndex(t *testing.T) {
	h := newHarness(t, nil)
	h.handler.acl = clientacl.Compute([]string{"10.0.0.0/8"}, false, nil)
	h.handler.firstSeen = indexed(t, h, firstseen.Config{})
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		resp := h.handler.Handle(ctx, query("refused.example", dns.TypeA), clientMeta("203.0.113.9"))
		if resp.Rcode != dns.RcodeRefused {
			t.Fatalf("client was not refused: %s", dns.RcodeToString[resp.Rcode])
		}
	}
	// One permitted query so we are measuring the absence of the others
	// rather than an index that never worked.
	h.handler.Handle(ctx, query("allowed.example", dns.TypeA), clientMeta("10.0.0.4"))
	waitRows(t, h.store, 1)
	time.Sleep(60 * time.Millisecond)

	if n := rows(t, h.store); n != 1 {
		t.Errorf("%d rows, want only the permitted query's", n)
	}
	if _, err := h.store.LookupFirstSeen(ctx, "refused.example"); err == nil {
		t.Error("an ACL-refused name was indexed")
	}
}

// TestARateLimitedClientCannotGrowTheIndex, the deliberate choice of the two
// the brief offered: a client already being refused for asking too fast should
// not also get to fill the table. Its first, admitted query is indexed.
func TestARateLimitedClientCannotGrowTheIndex(t *testing.T) {
	h := newHarness(t, nil)
	h.handler.limiter = ratelimit.New(ratelimit.Config{Rate: 0.001, Burst: 1, MaxClients: 16})
	h.handler.firstSeen = indexed(t, h, firstseen.Config{})
	ctx := context.Background()

	h.handler.Handle(ctx, query("first.example", dns.TypeA), clientMeta("10.0.0.5"))
	for i := 0; i < 40; i++ {
		resp := h.handler.Handle(ctx, query("throttled.example", dns.TypeA), clientMeta("10.0.0.5"))
		if resp.Rcode != dns.RcodeRefused {
			t.Fatalf("query %d was not rate limited", i)
		}
	}
	waitRows(t, h.store, 1)
	time.Sleep(60 * time.Millisecond)

	if _, err := h.store.LookupFirstSeen(ctx, "throttled.example"); err == nil {
		t.Error("a rate-limited name was indexed")
	}
	if n := rows(t, h.store); n != 1 {
		t.Errorf("%d rows, want 1", n)
	}
}

// TestARebindingFilteredAnswerIsStillIndexed. The name was asked and observed;
// what we did to the addresses in the reply is a separate decision.
func TestARebindingFilteredAnswerIsStillIndexed(t *testing.T) {
	h := newHarnessAgainstUpstream(t, rebindingUpstream(t), func(o *HandlerOptions) {
		o.Rebinding = filtering(t, rebind.EmptyNXDOMAIN)
	})
	h.handler.firstSeen = indexed(t, h, firstseen.Config{})
	ctx := context.Background()

	resp := h.handler.Handle(ctx, query("rebound.example", dns.TypeAAAA), clientMeta("10.0.0.6"))
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("the answer was not emptied by the filter (rcode %s)", dns.RcodeToString[resp.Rcode])
	}
	waitRows(t, h.store, 1)
	if _, err := h.store.LookupFirstSeen(ctx, "rebound.example"); err != nil {
		t.Error("a name whose addresses were filtered was not indexed")
	}
}

// TestACacheHitStillTouchesTheIndex. Novelty is about names asked, not names
// that missed cache: a domain queried a thousand times and served from cache
// nine hundred of them has been asked a thousand times.
func TestACacheHitStillTouchesTheIndex(t *testing.T) {
	h := newHarnessWithCache(t, rebindingUpstream(t))
	h.handler.firstSeen = indexed(t, h, firstseen.Config{})
	ctx := context.Background()

	for i := 0; i < 6; i++ {
		h.handler.Handle(ctx, query("cached.example", dns.TypeA), clientMeta("10.0.0.7"))
	}
	waitRows(t, h.store, 1)
	time.Sleep(80 * time.Millisecond)

	rec, err := h.store.LookupFirstSeen(ctx, "cached.example")
	if err != nil {
		t.Fatal(err)
	}
	if rec.QueryCount < 2 {
		t.Errorf("query_count = %d; cache hits appear not to reach the index", rec.QueryCount)
	}
}

// TestTheIndexIsInstallationWideNotPerNetwork.
//
// Two networks asking the same registered domain share one row and one
// first_seen. That is a deliberate choice: "has anything on this installation
// ever asked for this" is the question a hunt is actually asking, and
// per-network rows would multiply the table by the number of networks while
// making the common case harder to answer. Documented in algorithms.md.
func TestTheIndexIsInstallationWideNotPerNetwork(t *testing.T) {
	h := newHarness(t, nil)
	h.handler.firstSeen = indexed(t, h, firstseen.Config{})
	ctx := context.Background()

	if _, err := h.store.CreateNetwork(ctx, store.NetworkInput{
		Name: ptrString("Lab"), PolicyID: ptrString("p_strict"), CIDRs: &[]string{"10.7.0.0/16"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	h.handler.Handle(ctx, query("shared.example", dns.TypeA), clientMeta("10.1.0.1"))
	waitRows(t, h.store, 1)
	first, err := h.store.LookupFirstSeen(ctx, "shared.example")
	if err != nil {
		t.Fatal(err)
	}

	h.handler.Handle(ctx, query("shared.example", dns.TypeA), clientMeta("10.7.0.1"))
	time.Sleep(80 * time.Millisecond)

	if n := rows(t, h.store); n != 1 {
		t.Errorf("%d rows for one domain across two networks, want 1", n)
	}
	second, _ := h.store.LookupFirstSeen(ctx, "shared.example")
	if !second.FirstSeen.Equal(first.FirstSeen) {
		t.Error("the second network reset first_seen")
	}
}

// TestANilIndexLeavesResolutionUntouched. "Off" is a nil pointer, so the
// handler must not have grown a branch that behaves differently.
func TestANilIndexLeavesResolutionUntouched(t *testing.T) {
	h := newHarness(t, nil)
	h.handler.firstSeen = nil
	ctx := context.Background()

	for i := 0; i < 20; i++ {
		resp := h.handler.Handle(ctx, query("example.com", dns.TypeA), clientMeta("10.0.0.8"))
		if resp == nil || resp.Rcode == dns.RcodeServerFailure {
			t.Fatalf("query %d failed with no index configured", i)
		}
	}
	if h.handler.FirstSeenIndex() != nil {
		t.Error("FirstSeenIndex() is not nil on a handler with no index")
	}
}

// TestNamesWithNoRegistrationDoNotReachTheTable through the handler, because
// a network's own search suffix is the loudest thing that would otherwise
// fill it.
func TestNamesWithNoRegistrationDoNotReachTheTable(t *testing.T) {
	h := newHarness(t, nil)
	idx := indexed(t, h, firstseen.Config{})
	h.handler.firstSeen = idx
	ctx := context.Background()

	for _, n := range []string{"printer", "wpad.corp.local", "nas.home"} {
		h.handler.Handle(ctx, query(n, dns.TypeA), clientMeta("10.0.0.9"))
	}
	h.handler.Handle(ctx, query("real.example", dns.TypeA), clientMeta("10.0.0.9"))
	waitRows(t, h.store, 1)
	time.Sleep(80 * time.Millisecond)

	if n := rows(t, h.store); n != 1 {
		t.Errorf("%d rows, want only real.example", n)
	}
	if idx.Stats().Dropped["invalid"] != 3 {
		t.Errorf("invalid drops = %d, want 3", idx.Stats().Dropped["invalid"])
	}
}

// Prune isolation is pinned at the store layer, in
// TestThePrunerDoesNotTouchTheIndex, and deliberately not duplicated here. An
// end-to-end version would write a row with last_seen of now and then prune
// against a seven-day cutoff, which cannot reach it whatever the pruner does —
// it would pass against a pruner that wipes the table on any older row, and a
// test that cannot fail is worse than no test. The store test ages its row to
// 400 days and does fail when the pruner is made to touch the index.

// TestIndexingCostsNothingOnTheAnswerPathWhenTheWriterIsStuck.
//
// The buffer is bounded and drops. With nothing draining it, a burst of
// queries must still be answered at full speed rather than waiting on SQLite.
func TestIndexingCostsNothingOnTheAnswerPathWhenTheWriterIsStuck(t *testing.T) {
	h := newHarness(t, nil)
	// Built but never Run: nothing drains the channel.
	h.handler.firstSeen = firstseen.New(h.store,
		firstseen.Config{BufferSize: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			if resp := h.handler.Handle(ctx, query("stuck.example", dns.TypeA), clientMeta("10.0.0.11")); resp == nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("resolution blocked behind a full first-seen buffer")
	}
	if h.handler.FirstSeenIndex().Stats().Dropped["full"] == 0 {
		t.Error("the buffer never reported a drop, so it was not actually full")
	}
}
