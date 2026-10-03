package main

import (
	"log/slog"
	"sync"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/api"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// retentionStatus records what the retention job last did, so that "is the
// data I said I would delete actually being deleted?" has an answer that does
// not depend on reading the log.
//
// The job used to be observable only through what it removed: a pass that
// deleted nothing logged nothing, which is also exactly what a job that had
// stopped running looked like. A privacy document that states retention windows
// is making a promise about this goroutine, and a promise nobody can check is
// the kind that gets broken quietly.
//
// In memory, deliberately. It answers "since this process started", restarts
// reset it, and the first pass runs a minute after boot — so a scrape always
// has a recent answer without a write to the database every hour.
type retentionStatus struct {
	mu   sync.Mutex
	snap api.RetentionSnapshot
}

// record notes one finished pass and the steps that failed in it.
func (r *retentionStatus) record(at time.Time, failed []string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snap.Sweeps++
	r.snap.LastRun = at
	r.snap.LastFailedSteps = len(failed)
	if len(failed) > 0 {
		r.snap.FailedSweeps++
		return
	}
	r.snap.LastSuccess = at
}

// RetentionSnapshot implements api.RetentionStats.
func (r *retentionStatus) RetentionSnapshot() api.RetentionSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snap
}

// warnUnboundedRetention says, once at startup, which retained data this
// configuration never deletes or deletes on a window the operator did not
// write.
//
// The four retention settings do not read a zero the same way, and none of
// these behaviours was written down:
//
//	log.retention_days            0 or less → the 7-day default
//	log.rollup_days               0 or less → the 90-day default
//	detection.retention_days      0         → findings are never deleted
//	log.decision_retention_days   0 or less → decisions are never deleted
//
// Someone who writes 0 meaning "keep nothing" therefore gets a week of query
// history and findings and decisions kept for ever, with nothing to tell them
// so. This does not change what any value does — a configuration that worked
// keeps working, and deleting data an operator believed they were keeping is
// not a thing to do in a patch release. It makes the effective behaviour
// visible, which is the part that was missing.
func warnUnboundedRetention(cfg config.Config, log *slog.Logger) {
	if cfg.Log.RetentionDays <= 0 {
		log.Warn("log.retention_days is non-positive, which applies the default window rather than keeping nothing or keeping everything",
			"configured", cfg.Log.RetentionDays,
			"effective_days", store.DefaultRetentionDays,
			"to_stop_storing_queries", "set log.query_log: false")
	}
	if cfg.Log.RollupDays <= 0 {
		log.Warn("log.rollup_days is not a positive number, so the default applies",
			"configured", cfg.Log.RollupDays,
			"effective_days", store.DefaultRollupDays)
	}
	if cfg.Detection.RetentionDays <= 0 {
		log.Warn("detection.retention_days is non-positive, so findings are never deleted; they hold domains and client addresses",
			"configured", cfg.Detection.RetentionDays,
			"collection_enabled", cfg.Detection.Enabled,
			"historical_data", "disabling collection does not erase previously stored findings",
			"to_expire_them", "set detection.retention_days to a positive number of days",
			"to_stop_creating_them", "set detection.enabled: false")
	}
	if cfg.Log.DecisionRetentionDays <= 0 {
		log.Warn("log.decision_retention_days is not a positive number, so decision records are never deleted; they hold domains and client addresses",
			"configured", cfg.Log.DecisionRetentionDays,
			"collection_enabled", cfg.Log.DecisionRecords,
			"historical_data", "disabling collection does not erase previously stored decisions",
			"to_expire_them", "set log.decision_retention_days to a positive number of days",
			"to_stop_creating_them", "set log.decision_records: false")
	}
}
