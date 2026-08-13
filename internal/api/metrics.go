package api

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/version"
)

// handleMetrics writes Prometheus text-format metrics.
//
// Hand-rolled rather than pulling in the Prometheus client library: the metric
// set is small and fixed, and on a 1 GB box every megabyte of dependency is a
// megabyte not spent on the blocklist index.
func (a *API) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder

	queries, blocked, errs := a.DNS.Stats()
	collapsed, upstreamFailures := a.Resolver.Stats()
	cacheSize, hits, misses := a.Resolver.Cache().Stats()
	written, rollups, dropped := a.QueryLog.Stats()

	metric(&b, "dnsdaddy_build_info", "Build metadata", "gauge",
		fmt.Sprintf("dnsdaddy_build_info{version=%q} 1", version.String()))

	metric(&b, "dnsdaddy_queries_total", "DNS questions received", "counter",
		fmt.Sprintf("dnsdaddy_queries_total %d", queries))
	metric(&b, "dnsdaddy_blocked_total", "DNS questions blocked by policy", "counter",
		fmt.Sprintf("dnsdaddy_blocked_total %d", blocked))
	metric(&b, "dnsdaddy_errors_total", "DNS questions that failed to resolve", "counter",
		fmt.Sprintf("dnsdaddy_errors_total %d", errs))

	metric(&b, "dnsdaddy_cache_entries", "Answers currently cached", "gauge",
		fmt.Sprintf("dnsdaddy_cache_entries %d", cacheSize))
	metric(&b, "dnsdaddy_cache_hits_total", "Cache hits", "counter",
		fmt.Sprintf("dnsdaddy_cache_hits_total %d", hits))
	metric(&b, "dnsdaddy_cache_misses_total", "Cache misses", "counter",
		fmt.Sprintf("dnsdaddy_cache_misses_total %d", misses))

	metric(&b, "dnsdaddy_inflight_collapsed_total", "Duplicate concurrent queries served from a single upstream flight", "counter",
		fmt.Sprintf("dnsdaddy_inflight_collapsed_total %d", collapsed))
	metric(&b, "dnsdaddy_upstream_failures_total", "Queries where every upstream failed", "counter",
		fmt.Sprintf("dnsdaddy_upstream_failures_total %d", upstreamFailures))

	inflightNow, inflightPeak, limitTimeouts := a.Resolver.InflightStats()
	metric(&b, "dnsdaddy_upstream_inflight_current", "Upstream exchanges running right now, bounded by dns.max_inflight", "gauge",
		fmt.Sprintf("dnsdaddy_upstream_inflight_current %d", inflightNow))
	metric(&b, "dnsdaddy_upstream_inflight_peak", "Highest concurrent upstream exchanges observed since start", "gauge",
		fmt.Sprintf("dnsdaddy_upstream_inflight_peak %d", inflightPeak))
	metric(&b, "dnsdaddy_upstream_inflight_limit_timeouts_total", "Requests that gave up waiting for a free upstream concurrency slot", "counter",
		fmt.Sprintf("dnsdaddy_upstream_inflight_limit_timeouts_total %d", limitTimeouts))

	var upstreamLines []string
	for _, u := range a.Resolver.Upstreams() {
		q, e, avg := u.Stats()
		upstreamLines = append(upstreamLines,
			fmt.Sprintf("dnsdaddy_upstream_queries_total{upstream=%q} %d", u.Spec, q),
			fmt.Sprintf("dnsdaddy_upstream_errors_total{upstream=%q} %d", u.Spec, e),
			fmt.Sprintf("dnsdaddy_upstream_latency_ms_avg{upstream=%q} %.2f", u.Spec, avg))
	}
	if len(upstreamLines) > 0 {
		metric(&b, "dnsdaddy_upstream_queries_total", "Queries sent to each upstream", "counter",
			upstreamLines...)
	}

	metric(&b, "dnsdaddy_blocklist_domains", "Domains in the active blocklist index", "gauge",
		fmt.Sprintf("dnsdaddy_blocklist_domains %d", a.Lists.Load().Len()))

	var catLines []string
	for cat, n := range a.Lists.Load().CountsByCategory() {
		catLines = append(catLines, fmt.Sprintf("dnsdaddy_blocklist_category_domains{category=%q} %d", cat, n))
	}
	if len(catLines) > 0 {
		metric(&b, "dnsdaddy_blocklist_category_domains", "Indexed domains per category", "gauge", catLines...)
	}

	metric(&b, "dnsdaddy_querylog_written_total", "Query-log rows persisted", "counter",
		fmt.Sprintf("dnsdaddy_querylog_written_total %d", written))
	metric(&b, "dnsdaddy_querylog_rollup_only_total", "Events counted without a stored row", "counter",
		fmt.Sprintf("dnsdaddy_querylog_rollup_only_total %d", rollups))
	metric(&b, "dnsdaddy_querylog_dropped_total", "Events dropped because the buffer was full", "counter",
		fmt.Sprintf("dnsdaddy_querylog_dropped_total %d", dropped))

	// Detection engine. dnsdaddy_detection_dropped_total is the one to alert
	// on: it counts observations the engine never saw because its queue was
	// full, which means a detection gap rather than an absence of findings.
	if lines := detectionStatsLines(a.Detector); len(lines) > 0 {
		metric(&b, "dnsdaddy_detection_observations_total",
			"Queries handed to the behavioural detection engine", "counter", lines...)

		var findingLines []string
		for _, c := range a.Detector.Counts() {
			findingLines = append(findingLines,
				fmt.Sprintf("dnsdaddy_detection_finding_events_total{event_type=%q,severity=%q} %d",
					c.EventType, string(c.Severity), c.Count))
		}
		if len(findingLines) > 0 {
			metric(&b, "dnsdaddy_detection_finding_events_total",
				"Findings emitted, by event type and severity", "counter", findingLines...)
		}
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	metric(&b, "dnsdaddy_memory_bytes", "Memory obtained from the OS", "gauge",
		fmt.Sprintf("dnsdaddy_memory_bytes %d", ms.Sys))
	metric(&b, "dnsdaddy_goroutines", "Active goroutines", "gauge",
		fmt.Sprintf("dnsdaddy_goroutines %d", runtime.NumGoroutine()))
	metric(&b, "dnsdaddy_uptime_seconds", "Seconds since start", "gauge",
		fmt.Sprintf("dnsdaddy_uptime_seconds %d", int64(time.Since(a.StartedAt).Seconds())))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	// Prometheus exposition format, not HTML: html/template would corrupt it.
	// The only externally-influenced values are feed names and upstream specs,
	// both operator-configured, and both are emitted through %q which escapes
	// quotes and backslashes. Content-Type plus nosniff stops a browser
	// reinterpreting the body as markup.
	if _, err := w.Write([]byte(b.String())); err != nil {
		a.Log.Debug("write metrics", "error", err)
	}
}

func metric(b *strings.Builder, name, help, typ string, lines ...string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
}
