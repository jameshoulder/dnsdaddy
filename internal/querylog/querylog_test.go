package querylog

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func newTestLogger(t *testing.T, opts Options) (*Logger, *store.Store, context.CancelFunc) {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	l := New(st, opts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	go l.Run(ctx)

	return l, st, cancel
}

func event(domain, action string) store.QueryEvent {
	return store.QueryEvent{
		Time:      time.Now().UTC(),
		NetworkID: "n_default",
		Domain:    domain,
		QType:     "A",
		Action:    action,
	}
}

func TestRecordAndFlush(t *testing.T) {
	l, st, cancel := newTestLogger(t, Options{BufferSize: 64, FlushIntervalMS: 20})
	defer cancel()

	l.Record(event("example.com", store.ActionAllowed), true)
	l.Record(event("evil.com", store.ActionBlocked), true)

	waitFor(t, func() bool {
		rows, _, err := st.ListQueries(context.Background(), store.QueryFilter{Limit: 10})
		return err == nil && len(rows) == 2
	}, "events were never flushed to the store")
}

func TestRecordNeverBlocks(t *testing.T) {
	// The whole point of the buffer: a stalled writer must not add latency to
	// DNS resolution. With a tiny buffer and no draining, Record must still
	// return promptly and simply drop.
	l := New(nil, Options{BufferSize: 2}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			l.Record(event("example.com", store.ActionAllowed), true)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked when the buffer was full; this would stall the DNS hot path")
	}

	_, _, dropped := l.Stats()
	if dropped == 0 {
		t.Error("no events were counted as dropped, so the drop path is not being exercised")
	}
}

func TestRollupOnlyDoesNotStoreRows(t *testing.T) {
	l, st, cancel := newTestLogger(t, Options{BufferSize: 64, FlushIntervalMS: 20})
	defer cancel()

	l.Record(event("private.example", store.ActionAllowed), false)

	waitFor(t, func() bool {
		totals, err := st.TotalsSince(context.Background(), time.Now().Add(-time.Hour))
		return err == nil && totals.Queries == 1
	}, "the rollup was never written")

	rows, _, err := st.ListQueries(context.Background(), store.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListQueries: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("got %d stored rows, want 0 when persistence is off", len(rows))
	}

	waitFor(t, func() bool {
		_, rollups, _ := l.Stats()
		return rollups == 1
	}, "the rollup counter was never updated")
}

func TestBatchesLargeBursts(t *testing.T) {
	l, st, cancel := newTestLogger(t, Options{
		BufferSize: 4096, FlushIntervalMS: 20, MaxBatchRows: 32,
	})
	defer cancel()

	const n = 500
	for i := 0; i < n; i++ {
		l.Record(event("example.com", store.ActionAllowed), true)
	}

	waitFor(t, func() bool {
		written, _, dropped := l.Stats()
		return written+dropped == n
	}, "not every event was accounted for")

	written, _, dropped := l.Stats()
	if dropped != 0 {
		t.Errorf("%d events dropped from a burst that fits in the buffer", dropped)
	}
	if written != n {
		t.Errorf("written = %d, want %d", written, n)
	}

	totals, err := st.TotalsSince(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("TotalsSince: %v", err)
	}
	if totals.Queries != n {
		t.Errorf("rollup total = %d, want %d", totals.Queries, n)
	}
}

func TestDrainsOnShutdown(t *testing.T) {
	// A restart must not silently lose the last few seconds of activity.
	l, st, cancel := newTestLogger(t, Options{BufferSize: 512, FlushIntervalMS: 60_000})

	for i := 0; i < 20; i++ {
		l.Record(event("example.com", store.ActionAllowed), true)
	}

	cancel()
	l.Wait()

	rows, _, err := st.ListQueries(context.Background(), store.QueryFilter{Limit: 100})
	if err != nil {
		t.Fatalf("ListQueries: %v", err)
	}
	if len(rows) != 20 {
		t.Errorf("got %d rows after shutdown, want 20 — queued events were lost", len(rows))
	}
}

func TestConcurrentRecorders(t *testing.T) {
	l, _, cancel := newTestLogger(t, Options{BufferSize: 4096, FlushIntervalMS: 10})
	defer cancel()

	const workers, each = 8, 200
	done := make(chan struct{}, workers)
	for w := 0; w < workers; w++ {
		go func() {
			for i := 0; i < each; i++ {
				l.Record(event("example.com", store.ActionAllowed), true)
			}
			done <- struct{}{}
		}()
	}
	for w := 0; w < workers; w++ {
		<-done
	}

	waitFor(t, func() bool {
		written, _, dropped := l.Stats()
		return written+dropped == workers*each
	}, "events went missing under concurrent recording")
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}
