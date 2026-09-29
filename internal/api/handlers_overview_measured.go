package api

import (
	"context"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// This file builds Overview.Measured: the overview's factual companion.
//
// The headline fields on Overview predate it and keep their names and their
// meanings, because the REST API promises that within v1 a field is never
// repurposed. Several of them are coarser than their names suggest —
// protectedNetworks counts configured networks, threatsBlocked24h counts every
// block whatever the category — and the dashboard already labels them
// conservatively. Rather than quietly redefine them, this block states each
// underlying measurement separately, with its window, its scope and, where a
// number cannot be measured, the reason it cannot.
//
// The rule for every field here: it is a count of something specific, taken
// over a stated window, and nothing in it is a verdict about whether anything
// is protected. No field combines two scopes, and no field is invented when
// the measurement is unavailable.

// OverviewMeasured is the factual block on the overview.
type OverviewMeasured struct {
	Window    MeasuredWindow    `json:"window"`
	Networks  MeasuredNetworks  `json:"networks"`
	Clients   MeasuredClients   `json:"clients"`
	Filtering MeasuredFiltering `json:"filtering"`
	Feeds     MeasuredFeeds     `json:"feeds"`
	Outcomes  MeasuredOutcomes  `json:"outcomes"`
	Resolver  MeasuredResolver  `json:"resolver"`
}

// MeasuredWindow states the period every windowed count below covers.
type MeasuredWindow struct {
	Hours      int       `json:"hours"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	MeasuredAt time.Time `json:"measuredAt"`
	// Source names where the windowed counts come from. Hourly rollups are
	// written whether or not per-query rows are, so a privacy setting that
	// disables the query log does not blank them.
	Source string `json:"source"`
	// RollupRetentionDays bounds how far back a longer window could reach.
	RollupRetentionDays int `json:"rollupRetentionDays"`
}

// MeasuredNetworks separates the several things "networks" can mean.
type MeasuredNetworks struct {
	// Configured is every network row, the built-in catch-all included.
	Configured int `json:"configured"`
	// Enabled is how many of those are switched on.
	Enabled int `json:"enabled"`
	// ResolverPermitted is how many enabled networks carry their own
	// permission to query the resolver. The catch-all is excluded: its switch
	// admits unmatched clients inside the configured pool rather than
	// granting ranges of its own. Same rule as Overview.permittedNetworks.
	ResolverPermitted int `json:"resolverPermitted"`
	// AdHocAccess reports whether unmatched clients inside the configured
	// pool are served at all.
	AdHocAccess bool `json:"adHocAccess"`
	// WithBlockingPolicy is how many enabled networks are assigned a policy
	// that has any category or domain blocking configured. MonitorOnly is
	// the rest: their clients are attributed and logged, and nothing is
	// blocked for them.
	WithBlockingPolicy int `json:"withBlockingPolicy"`
	MonitorOnly        int `json:"monitorOnly"`
	// WithTrafficInWindow is how many configured networks recorded at least
	// one query in the window. A configured network is not an observed one.
	WithTrafficInWindow int `json:"withTrafficInWindow"`
}

// MeasuredClients is what can be said about devices, and why it might be
// nothing.
type MeasuredClients struct {
	// Attribution reports whether client addresses are recorded at all.
	Attribution bool `json:"attribution"`
	// ObservedInWindow is the number of distinct attributed client addresses
	// seen in the window, or null when it cannot be measured.
	ObservedInWindow *int64 `json:"observedInWindow"`
	// Unavailable says why ObservedInWindow is null, and is empty otherwise.
	Unavailable string `json:"unavailable,omitempty"`
	// EverSeen is Overview.hasSeenClients, restated here so the two client
	// facts sit together.
	EverSeen bool `json:"everSeen"`
}

// MeasuredFiltering describes what is configured, not what happened.
type MeasuredFiltering struct {
	Policies int `json:"policies"`
	// BlockingPolicies have at least one category or block-list entry.
	BlockingPolicies int `json:"blockingPolicies"`
	// BlockingPoliciesAssigned are the blocking policies some enabled network
	// actually uses. A blocking policy nobody is assigned to protects nobody.
	BlockingPoliciesAssigned int `json:"blockingPoliciesAssigned"`
	MonitorOnlyPolicies      int `json:"monitorOnlyPolicies"`
	// CustomBlockingPolicies carry operator block-list entries, which block
	// with or without a feed index.
	CustomBlockingPolicies int `json:"customBlockingPolicies"`
	// CategoryBlockingAvailable reports that the feed index holds anything.
	// A policy's category selections block nothing while it is empty.
	CategoryBlockingAvailable bool `json:"categoryBlockingAvailable"`
	IndexedDomains            int  `json:"indexedDomains"`
}

// MeasuredFeeds is the state of the intelligence sources, counted.
type MeasuredFeeds struct {
	Configured int `json:"configured"`
	Enabled    int `json:"enabled"`
	// Loaded is how many enabled feeds have a cached copy in the index that
	// is answering queries right now. The only count here that says a feed
	// is contributing to filtering.
	Loaded int `json:"loaded"`
	// Failing is how many enabled feeds' most recent refresh attempt failed.
	// A failing feed may still be loaded from an earlier download.
	Failing int `json:"failing"`
	// NeverDownloaded is how many enabled feeds have no successful download.
	NeverDownloaded int        `json:"neverDownloaded"`
	LastSuccessAt   *time.Time `json:"lastSuccessAt"`
	LastAttemptAt   *time.Time `json:"lastAttemptAt"`
	Refreshing      bool       `json:"refreshing"`
}

// MeasuredOutcomes counts what happened to queries in the window.
type MeasuredOutcomes struct {
	Queries int64 `json:"queries"`
	Blocked int64 `json:"blocked"`
	// BlockedByClass splits Blocked by what kind of decision each block was.
	// Every class is present, at zero where nothing happened, and the values
	// sum to Blocked. See catalog.BlockClasses for the meaning of each.
	BlockedByClass map[string]int64 `json:"blockedByClass"`
	Errors         MeasuredErrors   `json:"errors"`
}

// MeasuredErrors is the failed-resolution count and how complete it is.
type MeasuredErrors struct {
	Count int64 `json:"count"`
	// MeasuredSince is when this database began counting errors, or null
	// when every retained hour has been counted. Set on an upgraded
	// installation; hours before it read zero because nothing counted them.
	MeasuredSince *time.Time `json:"measuredSince"`
	// Complete reports that every hour in the window was counted.
	Complete bool `json:"complete"`
}

// MeasuredResolver keeps a windowed rate and the process's lifetime counters
// apart, because dividing one by the other is how the old resolverStatus went
// wrong.
type MeasuredResolver struct {
	ErrorRate  MeasuredRate       `json:"errorRate"`
	SinceStart MeasuredSinceStart `json:"sinceStart"`
}

// MeasuredRate is a ratio with its own numerator, denominator and window, or
// a stated reason it could not be computed.
type MeasuredRate struct {
	Available bool `json:"available"`
	// Unavailable says why, and is empty when Available.
	Unavailable string  `json:"unavailable,omitempty"`
	Numerator   int64   `json:"numerator"`
	Denominator int64   `json:"denominator"`
	Ratio       float64 `json:"ratio"`
	WindowHours int     `json:"windowHours"`
}

// MeasuredSinceStart is the process's cumulative counters, scoped to its own
// uptime and nothing else.
type MeasuredSinceStart struct {
	UptimeSeconds int64  `json:"uptimeSeconds"`
	Queries       uint64 `json:"queries"`
	Blocked       uint64 `json:"blocked"`
	Errors        uint64 `json:"errors"`
	Refused       uint64 `json:"refused"`
	// CoversWindow reports that the process has been up for at least the
	// window, so its counters and the windowed counts describe overlapping
	// periods. When false the two must not be compared.
	CoversWindow bool `json:"coversWindow"`
}

// overviewInputs are the reads handleOverview already makes, passed in so the
// measured block adds bounded queries rather than repeating them.
type overviewInputs struct {
	now      time.Time
	window   time.Duration
	totals   store.Totals
	networks []store.Network
	policies []store.Policy
	everSeen bool
}

// measuredOverview builds the block. Every additional read is bounded — a
// handful of rollup rows, the feed table, the presence table — and a failure
// in any of them fails the overview rather than producing a block with a
// silently invented zero.
func (a *API) measuredOverview(ctx context.Context, in overviewInputs) (OverviewMeasured, error) {
	from := in.now.Add(-in.window)
	hours := int(in.window / time.Hour)
	m := OverviewMeasured{
		Window: MeasuredWindow{
			Hours:               hours,
			From:                from.UTC(),
			To:                  in.now.UTC(),
			MeasuredAt:          in.now.UTC(),
			Source:              "hourly_rollups",
			RollupRetentionDays: a.Config.Log.RollupDays,
		},
	}

	// --- networks and filtering -------------------------------------------
	blocking := map[string]bool{}
	for _, p := range in.policies {
		isBlocking := len(p.Categories) > 0 || len(p.BlockDomains) > 0
		blocking[p.ID] = isBlocking
		m.Filtering.Policies++
		if isBlocking {
			m.Filtering.BlockingPolicies++
		} else {
			m.Filtering.MonitorOnlyPolicies++
		}
		if len(p.BlockDomains) > 0 {
			m.Filtering.CustomBlockingPolicies++
		}
	}
	m.Filtering.IndexedDomains = a.Lists.Load().Len()
	m.Filtering.CategoryBlockingAvailable = m.Filtering.IndexedDomains > 0

	assigned := map[string]bool{}
	for _, n := range in.networks {
		m.Networks.Configured++
		if !n.Enabled {
			continue
		}
		m.Networks.Enabled++
		if n.ID != clientacl.DefaultNetworkID && n.AllowResolver {
			m.Networks.ResolverPermitted++
		}
		if blocking[n.PolicyID] {
			m.Networks.WithBlockingPolicy++
			assigned[n.PolicyID] = true
		} else {
			m.Networks.MonitorOnly++
		}
	}
	m.Filtering.BlockingPoliciesAssigned = len(assigned)
	m.Networks.AdHocAccess = a.ClientACL.Current().AdHocAccess()

	activity, err := a.Store.NetworkActivitySince(ctx, from)
	if err != nil {
		return m, err
	}
	for _, n := range in.networks {
		if act, ok := activity[n.ID]; ok && act.Queries > 0 {
			m.Networks.WithTrafficInWindow++
		}
	}

	// --- clients ------------------------------------------------------------
	m.Clients.Attribution = a.Config.Log.QueryLog && a.Config.Log.LogClientIP
	m.Clients.EverSeen = in.everSeen
	if m.Clients.Attribution {
		n, err := a.Store.DistinctClientsSince(ctx, from)
		if err != nil {
			return m, err
		}
		m.Clients.ObservedInWindow = &n
	} else {
		m.Clients.Unavailable = "client addresses are not recorded (log.query_log and log.log_client_ip must both be on)"
	}

	// --- feeds ----------------------------------------------------------------
	feeds, err := a.Store.ListFeeds(ctx)
	if err != nil {
		return m, err
	}
	loads := a.Feeds.FeedLoads()
	m.Feeds.Refreshing = a.Feeds.Refreshing()
	for _, f := range feeds {
		m.Feeds.Configured++
		if !f.Enabled {
			continue
		}
		m.Feeds.Enabled++
		if loads[f.ID].Loaded {
			m.Feeds.Loaded++
		}
		if f.LastError != "" {
			m.Feeds.Failing++
		}
		if f.LastSuccess == nil {
			m.Feeds.NeverDownloaded++
		} else if m.Feeds.LastSuccessAt == nil || f.LastSuccess.After(*m.Feeds.LastSuccessAt) {
			t := *f.LastSuccess
			m.Feeds.LastSuccessAt = &t
		}
		if f.LastRefresh != nil && (m.Feeds.LastAttemptAt == nil || f.LastRefresh.After(*m.Feeds.LastAttemptAt)) {
			t := *f.LastRefresh
			m.Feeds.LastAttemptAt = &t
		}
	}

	// --- outcomes -------------------------------------------------------------
	m.Outcomes.Queries = in.totals.Queries
	m.Outcomes.Blocked = in.totals.Blocked
	m.Outcomes.BlockedByClass = make(map[string]int64, len(catalog.BlockClasses()))
	for _, c := range catalog.BlockClasses() {
		m.Outcomes.BlockedByClass[c] = 0
	}
	byCategory, err := a.Store.ThreatsByCategory(ctx, from)
	if err != nil {
		return m, err
	}
	var classified int64
	for _, c := range byCategory {
		m.Outcomes.BlockedByClass[catalog.ClassOfBlock(c.Category)] += c.Count
		classified += c.Count
	}
	// Blocks recorded with no category at all are not in the per-category
	// rows. They are still blocks, and the classes must sum to the total.
	if rest := in.totals.Blocked - classified; rest > 0 {
		m.Outcomes.BlockedByClass[catalog.ClassUnclassified] += rest
	}

	m.Outcomes.Errors.Count = in.totals.Errors
	m.Outcomes.Errors.Complete = true
	if raw, err := a.Store.GetSetting(ctx, store.SettingStatsErrorsSince); err == nil && raw != "" {
		if since, perr := time.Parse(time.RFC3339, raw); perr == nil {
			since = since.UTC()
			m.Outcomes.Errors.MeasuredSince = &since
			// Rollups are keyed by the hour, so counting is complete for
			// the window once the hour in which it began has passed out
			// of it.
			m.Outcomes.Errors.Complete = !since.Truncate(time.Hour).After(from.UTC().Truncate(time.Hour))
		}
	}

	// --- resolver -------------------------------------------------------------
	m.Resolver.ErrorRate = MeasuredRate{
		WindowHours: hours,
		Numerator:   in.totals.Errors,
		Denominator: in.totals.Queries,
	}
	switch {
	case in.totals.Queries == 0:
		m.Resolver.ErrorRate.Unavailable = "no queries in the window"
	case !m.Outcomes.Errors.Complete:
		m.Resolver.ErrorRate.Unavailable = "errors have only been counted since " +
			m.Outcomes.Errors.MeasuredSince.Format(time.RFC3339) + "; the window is not fully covered"
	default:
		m.Resolver.ErrorRate.Available = true
		m.Resolver.ErrorRate.Ratio = float64(in.totals.Errors) / float64(in.totals.Queries)
	}

	queries, blocked, errs := a.DNS.Stats()
	uptime := in.now.Sub(a.StartedAt)
	m.Resolver.SinceStart = MeasuredSinceStart{
		UptimeSeconds: int64(uptime.Seconds()),
		Queries:       queries,
		Blocked:       blocked,
		Errors:        errs,
		Refused:       a.DNS.RefusedClients(),
		CoversWindow:  uptime >= in.window,
	}
	return m, nil
}
