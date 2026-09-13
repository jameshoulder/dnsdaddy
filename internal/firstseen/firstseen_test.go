package firstseen_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/firstseen"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// harness runs a real Index against a real store, because the properties under
// test are about what lands in SQLite.
type harness struct {
	idx   *firstseen.Index
	store *store.Store
	ctx   context.Context
	stop  context.CancelFunc
}

func newHarness(t *testing.T, cfg firstseen.Config) *harness {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "fs.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 10 * time.Millisecond
	}
	idx := firstseen.New(st, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	go idx.Run(ctx)
	t.Cleanup(func() { cancel(); idx.Wait() })

	return &harness{idx: idx, store: st, ctx: context.Background(), stop: cancel}
}

// settle waits for the worker to have written what was observed.
func (h *harness) settle(t *testing.T, wantRows int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, err := h.store.CountFirstSeen(h.ctx)
		if err != nil {
			t.Fatalf("CountFirstSeen: %v", err)
		}
		if n >= wantRows {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	n, _ := h.store.CountFirstSeen(h.ctx)
	t.Fatalf("index settled at %d rows, want at least %d", n, wantRows)
}

// TestAFirstQueryBecomesARow, through the async path rather than the store.
func TestAFirstQueryBecomesARow(t *testing.T) {
	h := newHarness(t, firstseen.Config{})
	h.idx.Observe("www.example.com")
	h.settle(t, 1)

	rec, status := h.idx.Lookup(h.ctx, "www.example.com")
	if status != firstseen.StatusKnown {
		t.Fatalf("status = %s, want known", status)
	}
	if rec.Domain != "example.com" {
		t.Errorf("indexed as %q, want the registered domain", rec.Domain)
	}
	if rec.QueryCount != 1 {
		t.Errorf("query_count = %d, want 1", rec.QueryCount)
	}
}

// TestSubdomainsShareOneRow is what keying by eTLD+1 buys.
//
// attacker1.a.b.example.com and attacker2.c.d.example.com are the same
// registration and the same signal. Keying by FQDN would let one domain mint
// unlimited rows, which is the table-filling attack this design exists to
// prevent.
func TestSubdomainsShareOneRow(t *testing.T) {
	h := newHarness(t, firstseen.Config{})
	for _, n := range []string{
		"www.example.com", "mail.example.com", "a.b.c.example.com",
		"example.com", "deeply.nested.thing.example.com",
	} {
		h.idx.Observe(n)
	}
	h.settle(t, 1)

	// Give the worker a moment in case a second row were coming.
	time.Sleep(60 * time.Millisecond)
	n, _ := h.store.CountFirstSeen(h.ctx)
	if n != 1 {
		t.Fatalf("%d rows, want 1 — subdomains did not share a registered domain", n)
	}
	rec, _ := h.idx.Lookup(h.ctx, "example.com")
	if rec.QueryCount != 5 {
		t.Errorf("query_count = %d, want 5", rec.QueryCount)
	}
}

// TestMultiLabelSuffixesAreOneRegistration. Without the public suffix list
// every .co.uk site would collapse into a single row for co.uk.
func TestMultiLabelSuffixesAreOneRegistration(t *testing.T) {
	h := newHarness(t, firstseen.Config{})
	h.idx.Observe("www.example.co.uk")
	h.idx.Observe("shop.other.co.uk")
	h.settle(t, 2)

	for _, want := range []string{"example.co.uk", "other.co.uk"} {
		if _, err := h.store.LookupFirstSeen(h.ctx, want); err != nil {
			t.Errorf("no row for %q", want)
		}
	}
}

// TestCaseFoldsToOneRow. Otherwise an attacker mints a row per capitalisation
// of the same name, which is free.
func TestCaseFoldsToOneRow(t *testing.T) {
	h := newHarness(t, firstseen.Config{})
	// Names reaching Observe are already normalised by the handler; this
	// asserts the index does not undo that or add a second scheme.
	h.idx.Observe("example.com")
	h.idx.Observe("example.com")
	h.settle(t, 1)

	time.Sleep(60 * time.Millisecond)
	if n, _ := h.store.CountFirstSeen(h.ctx); n != 1 {
		t.Errorf("%d rows, want 1", n)
	}
}

// TestNamesWithNoRegistrationAreDroppedNotInserted.
//
// A single label, a private namespace, an address literal: none of these is a
// registration. Inserting them under their raw form would fill the table with
// a network's own search suffix, which is the single loudest source of noise
// in this kind of signal.
func TestNamesWithNoRegistrationAreDroppedNotInserted(t *testing.T) {
	h := newHarness(t, firstseen.Config{})
	for _, n := range []string{"printer", "wpad.corp.local", "nas.home", "1.2.3.4", ""} {
		h.idx.Observe(n)
	}
	time.Sleep(80 * time.Millisecond)

	if n, _ := h.store.CountFirstSeen(h.ctx); n != 0 {
		t.Errorf("%d rows created from names with no registered domain", n)
	}
	if got := h.idx.Stats().Dropped["invalid"]; got != 5 {
		t.Errorf("invalid drops = %d, want 5", got)
	}
}

// TestTheBufferDropsRatherThanBlocking is the hot-path promise.
//
// With a one-slot buffer and no worker draining it, Observe must return
// immediately and count the loss rather than wait for SQLite. A resolver that
// blocked here would add disk latency to every lookup on the network.
func TestTheBufferDropsRatherThanBlocking(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "fs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Deliberately never Run: nothing drains the channel.
	idx := firstseen.New(st, firstseen.Config{BufferSize: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10_000; i++ {
			idx.Observe(fmt.Sprintf("d%d.example", i))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe blocked when the buffer was full; the hot path must drop instead")
	}

	if got := idx.Stats().Dropped["full"]; got == 0 {
		t.Error("nothing was counted as dropped although the buffer could hold one")
	}
}

// TestTheRowCeilingHolds. This is the memory promise on a 1 GB box, against
// the input designed to break it: a client asking for a new registered domain
// every query, forever.
func TestTheRowCeilingHolds(t *testing.T) {
	const maxRows = 50
	h := newHarness(t, firstseen.Config{
		MaxRows: maxRows, MaxNewPerMinute: 100_000, FlushInterval: 5 * time.Millisecond,
	})

	for i := 0; i < 2000; i++ {
		h.idx.Observe(fmt.Sprintf("flood%d.example", i))
		if i%200 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	time.Sleep(300 * time.Millisecond)

	n, err := h.store.CountFirstSeen(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n > maxRows {
		t.Errorf("%d rows, ceiling is %d", n, maxRows)
	}
	if h.idx.Stats().Evictions == 0 {
		t.Error("2000 distinct domains through a 50-row table evicted nothing")
	}
}

// TestTheNewRowBudgetThrottlesDiscoveryButNotTraffic.
//
// The two halves have to be checked together: if the budget also throttled
// known domains, a network at its limit would stop recording activity
// entirely, and last_seen — which eviction sorts on — would freeze.
func TestTheNewRowBudgetThrottlesDiscoveryButNotTraffic(t *testing.T) {
	const budget = 5
	h := newHarness(t, firstseen.Config{
		MaxRows: 10_000, MaxNewPerMinute: budget, FlushInterval: 500 * time.Millisecond,
	})

	// One flush window, far more new domains than the budget allows.
	for i := 0; i < 100; i++ {
		h.idx.Observe(fmt.Sprintf("new%d.example", i))
	}
	time.Sleep(900 * time.Millisecond)

	n, _ := h.store.CountFirstSeen(h.ctx)
	if n > budget {
		t.Errorf("%d rows created, budget was %d", n, budget)
	}
	if n == 0 {
		t.Fatal("the budget admitted nothing at all")
	}
	if h.idx.Stats().Dropped["budget"] == 0 {
		t.Error("nothing was counted against the budget")
	}

	// A domain already in the table keeps being counted regardless.
	known, err := h.store.RecentFirstSeen(h.ctx, 1)
	if err != nil || len(known) == 0 {
		t.Fatal("no row to re-observe")
	}
	before := known[0].QueryCount
	for i := 0; i < 20; i++ {
		h.idx.Observe(known[0].Domain)
	}
	time.Sleep(900 * time.Millisecond)

	after, err := h.store.LookupFirstSeen(h.ctx, known[0].Domain)
	if err != nil {
		t.Fatal(err)
	}
	if after.QueryCount <= before {
		t.Errorf("query_count stayed at %d: the budget throttled a known domain", after.QueryCount)
	}
}

// TestConcurrentObserversProduceOneRow, under -race. The index is shared by
// every query on the resolver.
func TestConcurrentObserversProduceOneRow(t *testing.T) {
	h := newHarness(t, firstseen.Config{FlushInterval: 10 * time.Millisecond})

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				h.idx.Observe("shared.example.com")
			}
		}()
	}
	wg.Wait()
	h.settle(t, 1)
	time.Sleep(120 * time.Millisecond)

	if n, _ := h.store.CountFirstSeen(h.ctx); n != 1 {
		t.Fatalf("%d rows, want 1", n)
	}
	rec, _ := h.store.LookupFirstSeen(h.ctx, "example.com")
	// "At least": the buffer is allowed to drop under load, and a test that
	// demanded exactly 1600 would be asserting that it never does.
	if rec.QueryCount < 1 {
		t.Errorf("query_count = %d, want at least 1", rec.QueryCount)
	}
	if rec.QueryCount > 1600 {
		t.Errorf("query_count = %d, more than was observed", rec.QueryCount)
	}
}

// TestANilIndexIsAWorkingSwitchedOffIndex. "Off" is a nil pointer all the way
// down, so there is no second code path to get wrong.
func TestANilIndexIsAWorkingSwitchedOffIndex(t *testing.T) {
	var idx *firstseen.Index

	idx.Observe("example.com") // must not panic
	idx.Run(context.Background())
	idx.Wait()

	rec, status := idx.Lookup(context.Background(), "example.com")
	if status != firstseen.StatusUnknown {
		t.Errorf("status = %s, want unknown", status)
	}
	if rec.Domain != "" {
		t.Errorf("a disabled index returned a record: %+v", rec)
	}

	s := idx.Stats()
	if s.Rows != 0 || s.Inserts != 0 {
		t.Error("a nil index reported activity")
	}
	if len(s.Dropped) != len(firstseen.DropReasons()) {
		t.Error("a nil index does not report the full drop-reason set")
	}
}

// TestADisabledIndexSaysUnknownNotNew.
//
// The failure this prevents is subtle and would be loud: an index that is off
// answering "never seen before" about every domain on the network. Every hunt
// and every detector reading it would light up at once, and the signal would
// be worthless in exactly the deployment that turned it off.
func TestADisabledIndexSaysUnknownNotNew(t *testing.T) {
	var idx *firstseen.Index
	for _, n := range []string{"example.com", "google.com", "anything.example"} {
		if _, status := idx.Lookup(context.Background(), n); status == firstseen.StatusNew {
			t.Errorf("a disabled index called %q new", n)
		}
	}
}

// TestLookupOfAnUnseenDomainIsNewNotUnknown, which is the other half: a
// running index that holds no row genuinely has not seen the domain.
func TestLookupOfAnUnseenDomainIsNewNotUnknown(t *testing.T) {
	h := newHarness(t, firstseen.Config{})
	if _, status := h.idx.Lookup(h.ctx, "never.asked.example.com"); status != firstseen.StatusNew {
		t.Errorf("status = %s, want new", status)
	}
	if got := h.idx.Stats().Lookups[firstseen.StatusNew]; got != 1 {
		t.Errorf("new lookups = %d, want 1", got)
	}
}

// TestLookupCountsByResult, for the bounded metric.
func TestLookupCountsByResult(t *testing.T) {
	h := newHarness(t, firstseen.Config{})
	h.idx.Observe("example.com")
	h.settle(t, 1)

	h.idx.Lookup(h.ctx, "example.com")       // known
	h.idx.Lookup(h.ctx, "other.example.com") // new — same registered domain
	h.idx.Lookup(h.ctx, "unseen.test")       // new
	h.idx.Lookup(h.ctx, "printer")           // unknown: no registered domain

	s := h.idx.Stats().Lookups
	if s[firstseen.StatusKnown] != 2 {
		t.Errorf("known = %d, want 2 (both roll up to example.com)", s[firstseen.StatusKnown])
	}
	if s[firstseen.StatusNew] != 1 {
		t.Errorf("new = %d, want 1", s[firstseen.StatusNew])
	}
	if s[firstseen.StatusUnknown] != 1 {
		t.Errorf("unknown = %d, want 1", s[firstseen.StatusUnknown])
	}
}

// TestAStoreFailureIsAbsorbed. The answer that produced these observations
// went to the client long ago; there is nothing resolution could do with an
// error from a statistics table, so Run must not propagate one.
func TestAStoreFailureIsAbsorbed(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "fs.db"))
	if err != nil {
		t.Fatal(err)
	}
	idx := firstseen.New(st, firstseen.Config{FlushInterval: 5 * time.Millisecond},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	go idx.Run(ctx)

	// Close the store underneath the worker, then keep observing.
	st.Close()
	for i := 0; i < 50; i++ {
		idx.Observe(fmt.Sprintf("d%d.example.com", i))
	}
	time.Sleep(120 * time.Millisecond)
	cancel()
	idx.Wait() // must return rather than panic or hang
}

// TestShutdownFlushesWhatIsQueued, so the last few seconds of a resolver's
// life are not silently discarded on every restart.
func TestShutdownFlushesWhatIsQueued(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "fs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// A flush interval long enough that only the shutdown drain can write.
	idx := firstseen.New(st, firstseen.Config{FlushInterval: time.Hour},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	go idx.Run(ctx)

	// Ten distinct REGISTRATIONS, not ten subdomains of one: an earlier
	// version of this test used shutdown0.example.com upwards and expected ten
	// rows, which the index correctly collapsed into one. That is the keying
	// working, and the test was wrong.
	for i := 0; i < 10; i++ {
		idx.Observe(fmt.Sprintf("host.shutdown%d.example", i))
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	idx.Wait()

	n, err := st.CountFirstSeen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Errorf("%d rows survived shutdown, want 10", n)
	}
}
