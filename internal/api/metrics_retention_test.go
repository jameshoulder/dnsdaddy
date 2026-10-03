package api

import (
	"strings"
	"testing"
	"time"
)

type fixedRetention struct{ snap RetentionSnapshot }

func (f fixedRetention) RetentionSnapshot() RetentionSnapshot { return f.snap }

// The retention windows in docs/privacy.md are a statement about a background
// job, and these series are the only way to check that statement against a
// running process without reading its log.
func TestRetentionMetricsReportWhetherTheJobRanAndSucceeded(t *testing.T) {
	h := newHarness(t)
	h.login()

	// No job wired in: no series. A retention counter reading zero on a
	// process that has no retention job would be a false reassurance.
	if body := h.getMetrics(); strings.Contains(body, "dnsdaddy_retention_") {
		t.Fatal("retention series were exported with no retention job to report on")
	}

	// Started, first pass not finished yet. The counters exist; the two
	// timestamps do not, because 0 would read as "last succeeded in 1970" and
	// fire every staleness alert for the first minute after a restart.
	h.api.Retention = fixedRetention{}
	body := h.getMetrics()
	for _, want := range []string{
		"dnsdaddy_retention_sweeps_total 0",
		"dnsdaddy_retention_sweep_failures_total 0",
		"dnsdaddy_retention_last_failed_steps 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("before the first pass: missing %q", want)
		}
	}
	for _, absent := range []string{
		"dnsdaddy_retention_last_run_timestamp_seconds",
		"dnsdaddy_retention_last_success_timestamp_seconds",
	} {
		if strings.Contains(body, absent) {
			t.Errorf("before the first pass: %s was exported with no value to report", absent)
		}
	}

	// Three passes, the latest of which failed two steps. The last success is
	// older than the last run, which is the gap an alert is written against.
	lastRun := time.Unix(1_790_000_000, 0)
	lastSuccess := lastRun.Add(-time.Hour)
	h.api.Retention = fixedRetention{RetentionSnapshot{
		Sweeps: 3, FailedSweeps: 1, LastRun: lastRun, LastSuccess: lastSuccess, LastFailedSteps: 2,
	}}
	body = h.getMetrics()
	for _, want := range []string{
		"dnsdaddy_retention_sweeps_total 3",
		"dnsdaddy_retention_sweep_failures_total 1",
		"dnsdaddy_retention_last_failed_steps 2",
		"dnsdaddy_retention_last_run_timestamp_seconds 1790000000",
		"dnsdaddy_retention_last_success_timestamp_seconds 1789996400",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("after a failed pass: missing %q", want)
		}
	}
}
