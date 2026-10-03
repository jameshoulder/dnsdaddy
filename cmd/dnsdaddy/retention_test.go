package main

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
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

// seedExpired puts one row past its window and one inside it into each of the
// three tables whose pruning used to be skipped when an earlier step failed.
func seedExpired(t *testing.T, ctx context.Context, st *store.Store) {
	t.Helper()
	old, fresh := time.Now().AddDate(0, 0, -60), time.Now().Add(-time.Hour)

	if err := st.InsertDNSSECObservations(ctx, []store.DNSSECObservation{
		{ID: "obs-old", Time: old, Domain: "expired.test", QType: "A", Status: "secure"},
		{ID: "obs-fresh", Time: fresh, Domain: "kept.test", QType: "A", Status: "secure"},
	}); err != nil {
		t.Fatalf("insert observations: %v", err)
	}
	if err := st.InsertFindings(ctx, []store.Finding{
		{ID: "finding-old", Time: old, EventType: "x", Severity: "low", Detail: "{}"},
		{ID: "finding-fresh", Time: fresh, EventType: "x", Severity: "low", Detail: "{}"},
	}); err != nil {
		t.Fatalf("insert findings: %v", err)
	}
	for id, at := range map[string]time.Time{"decision-old": old, "decision-fresh": fresh} {
		d := store.Decision{ID: id, Time: at, Action: "block", Rule: "test"}
		d.Subject.Value = "blocked.test"
		if _, err := st.RecordDecision(ctx, d, nil); err != nil {
			t.Fatalf("record decision: %v", err)
		}
	}
}

// dropTable removes a table through a second connection, which is the
// cheapest honest way to make exactly one retention step fail.
func dropTable(t *testing.T, path, table string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatalf("open second connection: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("DROP TABLE " + table); err != nil {
		t.Fatalf("drop %s: %v", table, err)
	}
}

// TestRetentionStepFailureDoesNotStopTheRest.
//
// The pass used to return on the first of two failures: a query-log prune
// that failed skipped observations, findings, decisions, evidence, cached
// intelligence and sessions, and a findings prune that failed skipped
// everything after findings. Each of those tables has its own retention window
// in docs/privacy.md, so one stuck table quietly suspended the promise for all
// the others — with an error in the log about a different table.
func TestRetentionStepFailureDoesNotStopTheRest(t *testing.T) {
	for _, tc := range []struct {
		broken string // the table whose step is made to fail
		step   string // the name that step reports
	}{
		{broken: "query_log", step: "query_log"},
		{broken: "findings", step: "findings"},
	} {
		t.Run(tc.broken, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.db")
			st, err := store.Open(path)
			if err != nil {
				t.Fatalf("store.Open: %v", err)
			}
			defer st.Close()

			ctx := context.Background()
			cfg := config.Default()
			seedExpired(t, ctx, st)
			dropTable(t, path, tc.broken)

			failed := pruneOnce(ctx, st, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

			if len(failed) != 1 || failed[0] != tc.step {
				t.Fatalf("failed steps = %v, want exactly [%s]", failed, tc.step)
			}

			obs, err := st.ListDNSSECObservations(ctx, store.DNSSECObservationFilter{Limit: 10})
			if err != nil {
				t.Fatalf("list observations: %v", err)
			}
			if len(obs) != 1 || obs[0].Domain != "kept.test" {
				t.Errorf("observations after the pass = %d rows; the expired one survived a %s failure", len(obs), tc.broken)
			}

			if n, err := st.CountDecisions(ctx); err != nil {
				t.Fatalf("count decisions: %v", err)
			} else if n != 1 {
				t.Errorf("decisions after the pass = %d, want 1; the expired one survived a %s failure", n, tc.broken)
			}

			if tc.broken != "findings" {
				if _, err := st.GetFinding(ctx, "finding-old"); err == nil {
					t.Errorf("the expired finding survived a %s failure", tc.broken)
				}
				if _, err := st.GetFinding(ctx, "finding-fresh"); err != nil {
					t.Errorf("a finding inside its window was removed: %v", err)
				}
			}
		})
	}
}

// A clean pass reports no failed steps, which is what lets the caller record
// it as a success.
func TestRetentionCleanPassReportsNoFailures(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	seedExpired(t, ctx, st)
	if failed := pruneOnce(ctx, st, config.Default(), slog.New(slog.NewTextHandler(io.Discard, nil))); len(failed) != 0 {
		t.Fatalf("a clean pass reported failed steps: %v", failed)
	}
}

func TestRetentionStatusSeparatesRunningFromSucceeding(t *testing.T) {
	var s retentionStatus
	if snap := s.RetentionSnapshot(); snap.Sweeps != 0 || !snap.LastRun.IsZero() || !snap.LastSuccess.IsZero() {
		t.Fatalf("a job that has not run reported activity: %+v", snap)
	}

	first := time.Unix(1_790_000_000, 0)
	s.record(first, nil)
	snap := s.RetentionSnapshot()
	if snap.Sweeps != 1 || snap.FailedSweeps != 0 || !snap.LastRun.Equal(first) || !snap.LastSuccess.Equal(first) || snap.LastFailedSteps != 0 {
		t.Fatalf("after a clean pass: %+v", snap)
	}

	// A pass with a failed step ran, and must not move the last success: the
	// gap between the two is what says retention has stopped working.
	second := first.Add(time.Hour)
	s.record(second, []string{"query_log", "findings"})
	snap = s.RetentionSnapshot()
	if snap.Sweeps != 2 || snap.FailedSweeps != 1 || !snap.LastRun.Equal(second) || !snap.LastSuccess.Equal(first) || snap.LastFailedSteps != 2 {
		t.Fatalf("after a failed pass: %+v", snap)
	}

	// runRetention is handed nil in tests that do not care; that must not panic.
	var none *retentionStatus
	none.record(second, nil)
}

// TestUnboundedRetentionIsAnnouncedAtStartup.
//
// A zero does not mean the same thing in each retention setting, and nothing
// said so: it is the default window for the query log and the rollups, and
// "never delete" for findings and decision records. An operator who writes 0
// to keep less ends up keeping more. This does not change what a zero does —
// it makes the effective behaviour visible where the operator will see it.
func TestUnboundedRetentionIsAnnouncedAtStartup(t *testing.T) {
	capture := func(mutate func(*config.Config)) string {
		var buf bytes.Buffer
		cfg := config.Default()
		mutate(&cfg)
		warnUnboundedRetention(cfg, slog.New(slog.NewTextHandler(&buf, nil)))
		return buf.String()
	}

	if out := capture(func(*config.Config) {}); out != "" {
		t.Errorf("the shipped defaults all expire, and still produced a warning:\n%s", out)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{"findings kept for ever", func(c *config.Config) { c.Detection.RetentionDays = 0 }, "findings are never deleted"},
		{"decisions kept for ever", func(c *config.Config) { c.Log.DecisionRetentionDays = 0 }, "decision records are never deleted"},
		{"negative decisions window", func(c *config.Config) { c.Log.DecisionRetentionDays = -1 }, "decision records are never deleted"},
		{"query log falls back", func(c *config.Config) { c.Log.RetentionDays = 0 }, "effective_days=7"},
		{"rollups fall back", func(c *config.Config) { c.Log.RollupDays = 0 }, "effective_days=90"},
	} {
		out := capture(tc.mutate)
		if !strings.Contains(out, "level=WARN") || !strings.Contains(out, tc.want) {
			t.Errorf("%s: want a warning containing %q, got:\n%s", tc.name, tc.want, out)
		}
	}

	// A disabled collector can still have historical records. Its effective
	// window must be disclosed without claiming those records were deleted.
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"detection off", func(c *config.Config) { c.Detection.Enabled = false; c.Detection.RetentionDays = 0 }},
		{"decision records off", func(c *config.Config) { c.Log.DecisionRecords = false; c.Log.DecisionRetentionDays = 0 }},
		{"query log off", func(c *config.Config) { c.Log.QueryLog = false; c.Log.RetentionDays = 0 }},
	} {
		if out := capture(tc.mutate); !strings.Contains(out, "level=WARN") {
			t.Errorf("%s: historic retention policy was hidden", tc.name)
		}
	}
}

func TestDisabledCollectionDoesNotHideOrEraseHistoricRetention(t *testing.T) {
	for _, zero := range []bool{false, true} {
		st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		seedExpired(t, ctx, st)
		cfg := config.Default()
		cfg.Detection.Enabled = false
		cfg.Log.DecisionRecords = false
		cfg.Log.QueryLog = false
		var log bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&log, nil))
		if zero {
			cfg.Detection.RetentionDays = 0
			cfg.Log.DecisionRetentionDays = 0
		}
		warnUnboundedRetention(cfg, logger)
		if failed := pruneOnce(ctx, st, cfg, logger); len(failed) != 0 {
			t.Fatalf("prune: %v", failed)
		}
		n, err := st.CountDecisions(ctx)
		if err != nil {
			t.Fatal(err)
		}
		want := int64(1)
		if zero {
			want = 2
		}
		if n != want {
			t.Fatalf("zero=%v decisions=%d want=%d", zero, n, want)
		}
		_, oldErr := st.GetFinding(ctx, "finding-old")
		if zero && oldErr != nil {
			t.Fatal("zero expiry deleted historic finding")
		}
		if !zero && oldErr == nil {
			t.Fatal("disabled detection prevented normal expiry")
		}
		if zero && (!strings.Contains(log.String(), "findings are never deleted") || !strings.Contains(log.String(), "decision records are never deleted")) {
			t.Fatalf("historic data retention was not disclosed: %s", log.String())
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
