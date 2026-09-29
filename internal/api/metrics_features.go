package api

import (
	"context"
	"fmt"
	"strings"
)

// These series deliberately have no client, domain, URL or error-text labels.
// Counts are sufficient to detect loss; investigation belongs behind the API.
func (a *API) writeLearningMetrics(b *strings.Builder) {
	featureMetric(b, "dnsdaddy_learning_enabled", "Whether a local learner is configured in this process", "gauge", boolGauge(a.Learning != nil || a.LearningError != ""))
	featureMetric(b, "dnsdaddy_learning_available", "Whether the optional local learner started successfully", "gauge", boolGauge(a.Learning != nil))
	if a.Learning == nil {
		return
	}
	s := a.Learning.Status()
	featureMetric(b, "dnsdaddy_learning_running", "Whether the local learning worker is running", "gauge", boolGauge(s.Running))
	featureMetric(b, "dnsdaddy_learning_clients_tracked", "Current bounded local client baselines, including warming clients", "gauge", s.Clients.Tracked)
	featureMetric(b, "dnsdaddy_learning_clients_ready", "Local baselines with sufficient sample history; not a security efficacy measure", "gauge", s.Clients.Ready)
	featureMetric(b, "dnsdaddy_learning_clients_warming", "Local baselines still collecting eligible history", "gauge", s.Clients.Warming)
	featureMetric(b, "dnsdaddy_learning_clients_capacity", "Maximum retained local client baselines", "gauge", s.Clients.Max)
	featureMetric(b, "dnsdaddy_learning_clients_evicted_total", "Local client models evicted since process start", "counter", s.Clients.Evicted)
	featureMetric(b, "dnsdaddy_learning_queue_depth", "Observations awaiting local model processing", "gauge", s.Queue.Depth)
	featureMetric(b, "dnsdaddy_learning_queue_capacity", "Maximum queued learning observations", "gauge", s.Queue.Capacity)
	featureMetric(b, "dnsdaddy_learning_warmup_windows", "Minimum accepted windows before local anomaly scoring", "gauge", s.WarmupWindows)
	featureMetric(b, "dnsdaddy_learning_warmup_seconds", "Minimum elapsed accepted history before local anomaly scoring", "gauge", s.WarmupSeconds)
	featureMetric(b, "dnsdaddy_learning_window_seconds", "Local model aggregation window", "gauge", s.WindowSeconds)
	featureMetric(b, "dnsdaddy_learning_min_window_queries", "Minimum successful samples in an eligible window", "gauge", s.MinWindowQueries)
	for _, v := range []struct {
		name, help string
		value      uint64
	}{
		{"received", "Observation handoff attempts since process start", s.Observations.Received},
		{"processed", "Observations processed by the local worker since start", s.Observations.Processed},
		{"dropped", "Observation handoffs rejected by bounds or shutdown since start", s.Observations.Dropped},
		{"invalid", "Invalid observations rejected by the local worker since start", s.Observations.Invalid},
		{"blocked", "Policy-blocked observations excluded from normal training since start", s.Observations.Blocked},
		{"errors", "Unsuccessful observations excluded from normal training since start", s.Observations.Errors},
		{"late", "Out-of-order observations not folded into closed history since start", s.Observations.Late},
		{"window_overflow", "Observations beyond per-window accumulation bounds since start", s.Observations.WindowOverflow},
		{"unique_saturated", "Windows reaching the unique-domain hash bound since start", s.Observations.UniqueSaturated},
		{"privacy_skipped", "Queries withheld by global or policy privacy settings since start", s.Observations.PrivacySkipped},
	} {
		featureMetric(b, "dnsdaddy_learning_"+v.name+"_total", v.help, "counter", v.value)
	}
	for _, v := range []struct {
		name, help string
		value      uint64
	}{
		{"completed", "Completed sampled local windows since start", s.Windows.Completed},
		{"trained", "Local windows accepted for model fitting since start", s.Windows.Trained},
		{"quarantined", "Local windows withheld from model training since start", s.Windows.Quarantined},
		{"insufficient", "Local windows with too few successful samples since start", s.Windows.Insufficient},
		{"anomalous", "Local windows crossing the experimental anomaly gate since start", s.Windows.Anomalous},
		{"evicted_pending", "Open local windows lost to bounded client eviction since start", s.Windows.EvictedPending},
	} {
		featureMetric(b, "dnsdaddy_learning_windows_"+v.name+"_total", v.help, "counter", v.value)
	}
	featureMetric(b, "dnsdaddy_learning_restart_discarded_windows", "Open windows reported by the loaded checkpoint and discarded at this restart", "gauge", s.Windows.RestartDiscarded)
	featureMetric(b, "dnsdaddy_learning_state_loaded", "Whether a version-compatible fitted model was loaded", "gauge", boolGauge(s.Persistence.Loaded))
	featureMetric(b, "dnsdaddy_learning_save_errors_total", "Local model checkpoint errors since start", "counter", s.Persistence.SaveErrors)
	featureMetric(b, "dnsdaddy_learning_findings_emitted_total", "Experimental local findings successfully passed to storage since start", "counter", s.FindingsEmitted)
	featureMetric(b, "dnsdaddy_learning_finding_errors_total", "Experimental local findings that failed storage since start", "counter", s.FindingErrors)
	featureMetric(b, "dnsdaddy_learning_findings_suppressed_total", "Repeated local findings suppressed by cooldown since start", "counter", s.FindingSuppressed)
	if !s.Persistence.LastSavedAt.IsZero() {
		featureMetric(b, "dnsdaddy_learning_last_saved_timestamp_seconds", "Last successful local model checkpoint", "gauge", s.Persistence.LastSavedAt.Unix())
	}
}

func (a *API) writeProtectionMetrics(b *strings.Builder) {
	featureMetric(b, "dnsdaddy_protection_available", "Whether resolver protection controls are available", "gauge", boolGauge(a.Protection != nil))
	if a.Protection == nil {
		return
	}
	cfg := a.Protection.Config()
	c := a.Protection.Counters()
	featureMetric(b, "dnsdaddy_rate_limit_enabled", "Effective per-client rate-limit switch", "gauge", boolGauge(cfg.RateLimit.Enabled))
	featureMetric(b, "dnsdaddy_rate_limit_qps", "Configured per-client rate in queries per second", "gauge", cfg.RateLimit.QPS)
	featureMetric(b, "dnsdaddy_rate_limit_burst", "Configured per-client token bucket burst", "gauge", cfg.RateLimit.Burst)
	featureMetric(b, "dnsdaddy_rate_limit_clients_tracked", "Current bounded per-client token buckets", "gauge", c.TrackedClients)
	featureMetric(b, "dnsdaddy_rate_limit_clients_capacity", "Maximum retained per-client token buckets", "gauge", cfg.RateLimit.MaxClients)
	featureMetric(b, "dnsdaddy_rate_limited_total", "Queries refused by per-client or overflow rate limits since start", "counter", c.RateLimited)
	featureMetric(b, "dnsdaddy_rate_limit_overflow_total", "Queries assigned to the shared overflow bucket at client capacity since start", "counter", c.RateOverflow)
	featureMetric(b, "dnsdaddy_rebinding_enabled", "Effective DNS rebinding protection switch", "gauge", boolGauge(cfg.Rebinding.Enabled))
	featureMetric(b, "dnsdaddy_rebinding_blocked_total", "Answers rejected by DNS rebinding protection since start", "counter", c.RebindingBlocked)
}

func (a *API) writeNativeMetrics(b *strings.Builder, state DNSSECRuntimeState) {
	s := state.Native
	for _, v := range []struct {
		name, help string
		value      uint64
	}{
		{"queries", "Native client resolutions since this runtime was activated", s.Queries},
		{"secure", "Native answers validated as secure since activation", s.Secure},
		{"insecure", "Native answers with authenticated insecurity since activation", s.Insecure},
		{"bogus", "Native answers rejected as bogus since activation", s.Bogus},
		{"indeterminate", "Native answers whose validation could not be completed since activation", s.Indeterminate},
		{"checking_disabled", "Native queries whose client requested DNSSEC checking disabled since activation", s.CheckingDisabled},
		{"resolution_failures", "Native recursion failures since activation", s.ResolutionFailures},
		{"limit_rejected", "Native queries rejected by the in-flight bound since activation", s.LimitRejected},
		{"panics", "Native client panics contained since activation", s.Panics},
	} {
		featureMetric(b, "dnsdaddy_dnssec_native_"+v.name+"_total", v.help, "counter", v.value)
	}
	featureMetric(b, "dnsdaddy_dnssec_native_inflight", "Current native client resolutions", "gauge", s.Inflight)
	featureMetric(b, "dnsdaddy_dnssec_native_inflight_peak", "Peak concurrent native client resolutions since activation", "gauge", s.InflightPeak)
	featureMetric(b, "dnsdaddy_dnssec_native_inflight_limit", "Maximum concurrent native client resolutions", "gauge", s.MaxInflight)
	featureMetric(b, "dnsdaddy_dnssec_native_stored_total", "Native client observations persisted since process start", "counter", state.NativeWriter.Written)
	featureMetric(b, "dnsdaddy_dnssec_native_unrecorded_total", "Native client observations lost before storage since process start", "counter", state.NativeWriter.Dropped)
	featureMetric(b, "dnsdaddy_dnssec_native_write_errors_total", "Native observation storage batches that failed since process start", "counter", state.NativeWriter.Errors)
}

func (a *API) writeWebhookMetrics(ctx context.Context, b *strings.Builder) {
	if a.Store == nil {
		return
	}
	s, err := a.Store.GetWebhookStats(ctx)
	if err != nil {
		featureMetric(b, "dnsdaddy_webhook_stats_available", "Whether persistent webhook counters could be read", "gauge", 0)
		return
	}
	featureMetric(b, "dnsdaddy_webhook_stats_available", "Whether persistent webhook counters could be read", "gauge", 1)
	if cfg, err := a.Store.GetWebhookConfig(ctx); err == nil {
		featureMetric(b, "dnsdaddy_webhook_enabled", "Effective optional webhook delivery switch", "gauge", boolGauge(cfg.Enabled))
		featureMetric(b, "dnsdaddy_webhook_queue_capacity", "Configured persistent webhook outbox limit", "gauge", cfg.MaxQueue)
	}
	featureMetric(b, "dnsdaddy_webhook_queue_depth", "Events in the persistent webhook outbox", "gauge", s.QueueDepth)
	for _, v := range []struct {
		name  string
		value uint64
	}{
		{"queued", s.Queued}, {"attempted", s.Attempted}, {"delivered", s.Delivered}, {"failed", s.Failed}, {"dropped", s.Dropped}, {"retried", s.Retried},
	} {
		featureMetric(b, "dnsdaddy_webhook_"+v.name+"_total", "Persistent webhook "+v.name+" total since webhook storage was created", "counter", v.value)
	}
	if s.LastSuccessAt != nil {
		featureMetric(b, "dnsdaddy_webhook_last_success_timestamp_seconds", "Last successful webhook delivery in persistent history", "gauge", s.LastSuccessAt.Unix())
	}
	if s.LastFailureAt != nil {
		featureMetric(b, "dnsdaddy_webhook_last_failure_timestamp_seconds", "Last failed webhook delivery in persistent history", "gauge", s.LastFailureAt.Unix())
	}
	featureMetric(b, "dnsdaddy_webhook_last_http_status", "Last HTTP status recorded for webhook delivery; zero means none", "gauge", s.LastHTTPStatus)
}

func featureMetric(b *strings.Builder, name, help, kind string, value any) {
	metric(b, name, help, kind, fmt.Sprintf("%s %v", name, value))
}
