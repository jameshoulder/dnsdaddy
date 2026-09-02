package api

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
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

	// A rising count here means clients are being turned away on their source
	// address — the difference between "the resolver is broken" and "the
	// resolver is working and does not believe it should answer you". It is
	// deliberately not labelled by address: the refusal path writes no query
	// log, so an unauthorised source cannot fill the disk, and giving it a
	// metric label would reintroduce exactly that.
	metric(&b, "dnsdaddy_client_refused_total", "DNS questions refused because the source address is not permitted to use this resolver", "counter",
		fmt.Sprintf("dnsdaddy_client_refused_total %d", a.DNS.RefusedClients()))

	// Client-access shape. Counts only: an alert wants to know that the number
	// of publicly permitted ranges went from nought to one, not which address
	// it was. A label per client IP would be an unbounded cardinality
	// explosion and a copy of the network's addressing in every scrape.
	a.writeAccessMetrics(r.Context(), &b)

	// External providers. Emitted only when the feature is on: a series that
	// exists and reads zero would tell an operator their providers answered
	// nothing, when in fact they have none.
	a.writeIntelMetrics(&b)

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

// writeAccessMetrics exports the shape of the effective client ACL.
//
// Bounded by construction: four gauges, no labels. The temptation with an ACL
// is to label by CIDR so a dashboard can list them, and that is exactly how a
// metrics endpoint acquires one series per network and then one per client.
// The values here answer the questions monitoring should ask — is anything
// permitted at all, and has public exposure changed — and the dashboard and
// /api/v1/diagnostics answer the rest, authenticated.
func (a *API) writeAccessMetrics(ctx context.Context, b *strings.Builder) {
	// Everything derivable from the live snapshot is written first and
	// unconditionally. A database hiccup must not put a gap in a series an
	// operator is alerting on — "the number of publicly permitted ranges
	// stopped being reported" and "it went to zero" look the same on a graph
	// and mean opposite things.
	acl := a.ClientACL.Current()

	permitted := map[string]bool{}
	for _, g := range acl.Grants() {
		permitted[g.NetworkID] = true
	}

	metric(b, "dnsdaddy_networks_resolver_permitted", "Networks permitted to query the resolver", "gauge",
		fmt.Sprintf("dnsdaddy_networks_resolver_permitted %d", len(permitted)))
	metric(b, "dnsdaddy_client_acl_prefixes", "Address ranges in the effective client ACL, from configuration and the dashboard combined", "gauge",
		fmt.Sprintf("dnsdaddy_client_acl_prefixes %d", len(acl.Effective())))
	// Distinct ranges, not grants: a range permitted from configuration and
	// from the dashboard at once is one exposure, and a gauge that doubled
	// there would page somebody over a change that did not happen.
	metric(b, "dnsdaddy_client_acl_public_prefixes", "Distinct permitted address ranges that are reachable from the public internet", "gauge",
		fmt.Sprintf("dnsdaddy_client_acl_public_prefixes %d", len(acl.PublicPrefixes())))
	metric(b, "dnsdaddy_client_acl_unrestricted", "1 when no client ACL is configured and every source address is accepted", "gauge",
		fmt.Sprintf("dnsdaddy_client_acl_unrestricted %d", boolGauge(acl.Unrestricted())))

	// The total needs the database, and is the one value worth omitting rather
	// than guessing at.
	networks, err := a.Store.ListNetworks(ctx)
	if err != nil {
		a.Log.Debug("count networks for metrics", "error", err)
		return
	}
	metric(b, "dnsdaddy_networks_total", "Networks configured in the dashboard", "gauge",
		fmt.Sprintf("dnsdaddy_networks_total %d", len(networks)))
}

func boolGauge(b bool) int {
	if b {
		return 1
	}
	return 0
}

// writeIntelMetrics exports the external-intelligence engine's counters.
//
// Labelled by provider, which is the one place in this file where a label is
// worth its cardinality: providers are configured by hand in a dashboard,
// there are a handful of them, and the question an alert wants to ask —
// "which provider's circuit is open" — cannot be asked without the name.
// The label is the provider's ID rather than its name: an operator renaming a
// provider must not break a series, and a name is free text that would need
// escaping.
func (a *API) writeIntelMetrics(b *strings.Builder) {
	if a.Providers == nil {
		return
	}
	stats := a.Providers.Stats()

	// The mode as a gauge, because it is the single most important thing about
	// this feature and "did somebody change it" is the alert worth having.
	metric(b, "dnsdaddy_intel_reputation_mode", "How much say external providers have over resolution: 0 off, 1 cache only, 2 blocking", "gauge",
		fmt.Sprintf("dnsdaddy_intel_reputation_mode %d", stats.Mode.Rank()))

	metric(b, "dnsdaddy_intel_cache_entries", "Cached external verdicts held in memory", "gauge",
		fmt.Sprintf("dnsdaddy_intel_cache_entries %d", stats.CacheSize))
	metric(b, "dnsdaddy_intel_cache_hits_total", "Verdict lookups answered from the cache", "counter",
		fmt.Sprintf("dnsdaddy_intel_cache_hits_total %d", stats.CacheHits))
	metric(b, "dnsdaddy_intel_cache_misses_total", "Verdict lookups the cache could not answer", "counter",
		fmt.Sprintf("dnsdaddy_intel_cache_misses_total %d", stats.CacheMisses))

	metric(b, "dnsdaddy_intel_queue_depth", "Provider lookups waiting for a worker", "gauge",
		fmt.Sprintf("dnsdaddy_intel_queue_depth %d", stats.QueueDepth))
	metric(b, "dnsdaddy_intel_lookups_completed_total", "Provider lookups finished", "counter",
		fmt.Sprintf("dnsdaddy_intel_lookups_completed_total %d", stats.Completed))
	// The number worth alerting on. Dropping is deliberate — a full queue must
	// never put back-pressure on the DNS path — but a rising count means
	// providers are slower than the query rate and verdicts are not being
	// cached, so the feature is costing more than it returns.
	metric(b, "dnsdaddy_intel_lookups_dropped_total", "Provider lookups discarded because the queue was full", "counter",
		fmt.Sprintf("dnsdaddy_intel_lookups_dropped_total %d", stats.Dropped))

	instances := a.Providers.Instances()
	var (
		calls    []string
		failures []string
		latency  []string
		breaker  []string
		usable   []string
	)
	for _, inst := range instances {
		id := escapeLabel(inst.ID)
		usable = append(usable, fmt.Sprintf("dnsdaddy_intel_provider_usable{provider_id=%q} %d",
			id, boolGauge(inst.Usable())))
		if inst.Client == nil {
			continue
		}
		s := inst.Client.Stats()
		calls = append(calls, fmt.Sprintf("dnsdaddy_intel_provider_calls_total{provider_id=%q} %d", id, s.Calls))
		failures = append(failures, fmt.Sprintf("dnsdaddy_intel_provider_failures_total{provider_id=%q} %d", id, s.Failures))
		latency = append(latency, fmt.Sprintf("dnsdaddy_intel_provider_mean_latency_ms{provider_id=%q} %d", id, s.MeanLatencyMS))
		breaker = append(breaker, fmt.Sprintf("dnsdaddy_intel_provider_circuit_open{provider_id=%q} %d",
			id, boolGauge(s.Breaker != apiprovider.BreakerClosed)))
	}

	metric(b, "dnsdaddy_intel_providers_total", "External providers configured", "gauge",
		fmt.Sprintf("dnsdaddy_intel_providers_total %d", len(instances)))
	if len(usable) > 0 {
		metric(b, "dnsdaddy_intel_provider_usable", "1 when a provider is enabled, built and callable", "gauge", usable...)
	}
	if len(calls) > 0 {
		metric(b, "dnsdaddy_intel_provider_calls_total", "Requests sent to a provider", "counter", calls...)
		metric(b, "dnsdaddy_intel_provider_failures_total", "Requests to a provider that failed", "counter", failures...)
		metric(b, "dnsdaddy_intel_provider_mean_latency_ms", "Mean round-trip time to a provider", "gauge", latency...)
		metric(b, "dnsdaddy_intel_provider_circuit_open", "1 when a provider is being skipped because its circuit breaker is open", "gauge", breaker...)
	}
}

// escapeLabel makes a value safe inside a Prometheus label.
//
// Provider IDs are generated and contain neither of these, so this never fires
// today. It is here because the alternative is an exposition format that a
// scraper rejects with a parse error nobody traces back to a database row.
func escapeLabel(v string) string {
	if !strings.ContainsAny(v, `\"`+"\n") {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}
