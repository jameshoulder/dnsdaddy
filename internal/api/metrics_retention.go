package api

import (
	"fmt"
	"strings"
	"time"
)

// RetentionStats is the reporting face of the retention job.
//
// Read-only: the API reports what the job did and never triggers a pass.
type RetentionStats interface {
	RetentionSnapshot() RetentionSnapshot
}

// RetentionSnapshot is what the retention job has done since the process
// started. Counts and times only — nothing here names a table's contents.
type RetentionSnapshot struct {
	// Sweeps counts finished passes, clean or not.
	Sweeps uint64
	// FailedSweeps counts passes in which at least one step failed. The other
	// steps of such a pass still ran.
	FailedSweeps uint64
	// LastRun is when the most recent pass finished. Zero until the first one,
	// which runs about a minute after startup.
	LastRun time.Time
	// LastSuccess is when a pass last finished with no failed step.
	LastSuccess time.Time
	// LastFailedSteps is how many steps failed in the most recent pass.
	LastFailedSteps int
}

// writeRetentionMetrics exports whether the retention job is running and
// whether it is succeeding.
//
// docs/privacy.md states how long each kind of record is kept. These series
// are how an operator checks that statement against the running process
// instead of taking it on trust: alert when the last success is more than a
// couple of hours old, or when the failure counter moves.
//
// The two timestamps are omitted until they have a value. A gauge reading 0
// would say the job last succeeded in 1970, and every "seconds since last
// success" alert would fire for the first minute after each restart.
func (a *API) writeRetentionMetrics(b *strings.Builder) {
	if a.Retention == nil {
		return
	}
	s := a.Retention.RetentionSnapshot()

	metric(b, "dnsdaddy_retention_sweeps_total", "Retention passes finished since process start", "counter",
		fmt.Sprintf("dnsdaddy_retention_sweeps_total %d", s.Sweeps))
	metric(b, "dnsdaddy_retention_sweep_failures_total", "Retention passes in which at least one step failed; expired data may still be stored", "counter",
		fmt.Sprintf("dnsdaddy_retention_sweep_failures_total %d", s.FailedSweeps))
	metric(b, "dnsdaddy_retention_last_failed_steps", "Steps that failed in the most recent retention pass", "gauge",
		fmt.Sprintf("dnsdaddy_retention_last_failed_steps %d", s.LastFailedSteps))
	if !s.LastRun.IsZero() {
		metric(b, "dnsdaddy_retention_last_run_timestamp_seconds", "When the most recent retention pass finished", "gauge",
			fmt.Sprintf("dnsdaddy_retention_last_run_timestamp_seconds %d", s.LastRun.Unix()))
	}
	if !s.LastSuccess.IsZero() {
		metric(b, "dnsdaddy_retention_last_success_timestamp_seconds", "When a retention pass last finished with no failed step", "gauge",
			fmt.Sprintf("dnsdaddy_retention_last_success_timestamp_seconds %d", s.LastSuccess.Unix()))
	}
}
