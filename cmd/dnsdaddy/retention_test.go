package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// TestRetentionReachesDNSSECObservations.
//
// A DNSSEC observation row names the domain it validated, exactly as a
// query-log row does. `PruneDNSSECObservations` existed and compiled and was
// tested in isolation, and the retention job never called it — so an operator
// who set `log.retention_days: 7` and switched observation on would have kept
// every domain they looked up for ever, in a table they enabled to measure
// DNSSEC. A store method that is never called looks exactly like one that
// works, which is why this test runs the retention pass rather than the
// method.
func TestRetentionReachesDNSSECObservations(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	cfg := config.Default()
	cfg.Log.RetentionDays = 7

	old := store.DNSSECObservation{
		ID: "old", Time: time.Now().AddDate(0, 0, -30),
		Domain: "expired.test", QType: "A", Status: "secure",
	}
	fresh := store.DNSSECObservation{
		ID: "fresh", Time: time.Now().Add(-time.Hour),
		Domain: "kept.test", QType: "A", Status: "secure",
	}
	if err := st.InsertDNSSECObservations(ctx, []store.DNSSECObservation{old, fresh}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	pruneOnce(ctx, st, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	rows, err := st.ListDNSSECObservations(ctx, store.DNSSECObservationFilter{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows after retention, want 1", len(rows))
	}
	if rows[0].Domain != "kept.test" {
		t.Fatalf("retention kept %q; the row past the window survived", rows[0].Domain)
	}
}

// TestObservationRetentionFollowsTheQueryLogDefault.
//
// With no window configured the query log falls back to a default rather than
// keeping everything, and observations have to fall back to the same one.
// Reading an unset value as "no expiry" is how a privacy setting turns into
// unbounded growth.
func TestObservationRetentionFollowsTheQueryLogDefault(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	cfg := config.Default()
	cfg.Log.RetentionDays = 0

	if err := st.InsertDNSSECObservations(ctx, []store.DNSSECObservation{{
		ID: "old", Time: time.Now().AddDate(0, 0, -store.DefaultRetentionDays-1),
		Domain: "expired.test", QType: "A", Status: "secure",
	}}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	pruneOnce(ctx, st, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	rows, err := st.ListDNSSECObservations(ctx, store.DNSSECObservationFilter{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("an unset retention window kept %d rows for ever", len(rows))
	}
}
