package api

import (
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/httpx"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/jameshoulder/dnsdaddy/internal/version"
)

// HealthResponse is the unauthenticated liveness payload. It deliberately
// exposes no configuration — just enough for a monitor or status page to tell
// whether the resolver is answering.
type HealthResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	BlocklistSize int    `json:"blocklistSize"`
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	size := a.Lists.Load().Len()
	status := "ok"
	// An empty index means feeds have never loaded; the resolver still works
	// but it is not protecting anyone, and a monitor should say so.
	if size == 0 {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:        status,
		Version:       version.String(),
		UptimeSeconds: int64(time.Since(a.StartedAt).Seconds()),
		BlocklistSize: size,
	})
}

// Overview is the dashboard's headline block.
type Overview struct {
	ProtectionStatus  string     `json:"protectionStatus"`
	ResolverStatus    string     `json:"resolverStatus"`
	Queries24h        int64      `json:"queries24h"`
	ThreatsBlocked24h int64      `json:"threatsBlocked24h"`
	BlockRate24h      float64    `json:"blockRate24h"`
	ProtectedNetworks int        `json:"protectedNetworks"`
	ActivePolicies    int        `json:"activePolicies"`
	BlocklistDomains  int        `json:"blocklistDomains"`
	LastFeedRefresh   *time.Time `json:"lastFeedRefresh"`
	UptimeSeconds     int64      `json:"uptimeSeconds"`
	Version           string     `json:"version"`

	// HasSeenClients reports whether any non-loopback client has used the
	// resolver in the last 24 hours. False on a fresh install means nothing on
	// the network has pointed at it yet, which is the most common reason a new
	// operator thinks it is broken.
	HasSeenClients bool `json:"hasSeenClients"`
	// ClientAttribution reports whether client addresses are recorded at all.
	// When it is false, ClientsSeen24h is always zero and means nothing —
	// without this flag the dashboard would tell an operator who has
	// deliberately turned off client logging that no device is using their
	// resolver, forever.
	ClientAttribution bool `json:"clientAttribution"`
}

func (a *API) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	totals, err := a.Store.TotalsSince(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	networks, err := a.Store.ListNetworks(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	policies, err := a.Store.ListPolicies(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	blocklistSize := a.Lists.Load().Len()

	attribution := a.Config.Log.QueryLog && a.Config.Log.LogClientIP
	seenClients := false
	if attribution {
		if seen, err := a.Store.AnyClientSince(ctx, time.Now().Add(-24*time.Hour)); err == nil {
			seenClients = seen
		} else {
			// Not fatal: the rest of the overview is still worth serving, and
			// a missing count is reported as "unknown" rather than "none".
			a.Log.Debug("check for observed clients", "error", err)
			attribution = false
		}
	}

	// "Protected" requires both a loaded blocklist and at least one policy
	// actually enforcing a category. A resolver with feeds loaded but every
	// policy set to monitor-only is not protecting anyone, and saying so is
	// more useful than a green tick.
	enforcing := false
	for _, p := range policies {
		if len(p.Categories) > 0 || len(p.BlockDomains) > 0 {
			enforcing = true
			break
		}
	}

	protection := "protected"
	switch {
	case blocklistSize == 0:
		protection = "offline"
	case !enforcing:
		protection = "degraded"
	}

	_, _, resolverErrors := a.DNS.Stats()
	resolverStatus := "operational"
	if resolverErrors > 0 && totals.Queries > 0 {
		if float64(resolverErrors)/float64(totals.Queries) > 0.05 {
			resolverStatus = "degraded"
		}
	}

	var blockRate float64
	if totals.Queries > 0 {
		blockRate = float64(totals.Blocked) / float64(totals.Queries) * 100
	}

	// Prefer the in-memory value, but fall back to the database so a restart
	// does not make well-maintained feeds look like they have never run.
	var lastRefresh *time.Time
	if t := a.Feeds.LastRefresh(); !t.IsZero() {
		lastRefresh = &t
	} else if t, err := a.Store.LastFeedRefresh(ctx); err == nil && !t.IsZero() {
		lastRefresh = &t
	}

	writeJSON(w, http.StatusOK, Overview{
		ProtectionStatus:  protection,
		ResolverStatus:    resolverStatus,
		Queries24h:        totals.Queries,
		ThreatsBlocked24h: totals.Blocked,
		BlockRate24h:      round2(blockRate),
		ProtectedNetworks: len(networks),
		ActivePolicies:    len(policies),
		BlocklistDomains:  blocklistSize,
		LastFeedRefresh:   lastRefresh,
		UptimeSeconds:     int64(time.Since(a.StartedAt).Seconds()),
		Version:           version.String(),
		HasSeenClients:    seenClients,
		ClientAttribution: attribution,
	})
}

func (a *API) handleQueryActivity(w http.ResponseWriter, r *http.Request) {
	hours := intParam(r, "hours", 24)
	buckets, err := a.Store.QueryActivity(r.Context(), hours)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"buckets": buckets})
}

// CategoryBreakdown pairs a category count with its display metadata so the
// dashboard does not have to duplicate the catalog.
type CategoryBreakdown struct {
	Category string `json:"category"`
	Label    string `json:"label"`
	Count    int64  `json:"count"`
}

func (a *API) handleThreatsByCategory(w http.ResponseWriter, r *http.Request) {
	hours := intParam(r, "hours", 24)
	counts, err := a.Store.ThreatsByCategory(r.Context(), time.Now().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	out := make([]CategoryBreakdown, 0, len(counts))
	for _, c := range counts {
		label := c.Category
		if cat, ok := catalog.CategoryByID(c.Category); ok {
			label = cat.Label
		} else if c.Category == "custom" {
			label = "Custom block-list"
		}
		out = append(out, CategoryBreakdown{Category: c.Category, Label: label, Count: c.Count})
	}
	writeJSON(w, http.StatusOK, map[string]any{"categories": out})
}

func (a *API) handleTopBlocked(w http.ResponseWriter, r *http.Request) {
	days := intParam(r, "days", 7)
	limit := intParam(r, "limit", 10)
	rows, err := a.Store.TopBlockedDomains(r.Context(), time.Now().AddDate(0, 0, -days), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []store.TopBlocked{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": rows})
}

func (a *API) handleQueryLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.QueryFilter{
		NetworkID: q.Get("networkId"),
		Action:    q.Get("action"),
		Category:  q.Get("category"),
		Domain:    q.Get("domain"),
		ClientIP:  q.Get("clientIp"),
		Limit:     intParam(r, "limit", 100),
	}
	if c := q.Get("cursor"); c != "" {
		if v, err := strconv.ParseInt(c, 10, 64); err == nil {
			f.Cursor = v
		}
	}
	if h := intParam(r, "hours", 0); h > 0 {
		f.Since = time.Now().Add(-time.Duration(h) * time.Hour)
	}

	events, next, err := a.Store.ListQueries(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"queries":    events,
		"nextCursor": next,
	})
}

func (a *API) handleCategories(w http.ResponseWriter, r *http.Request) {
	counts := a.Lists.Load().CountsByCategory()
	type row struct {
		catalog.Category
		IndexedDomains int `json:"indexedDomains"`
	}
	out := make([]row, 0, len(catalog.Categories))
	for _, c := range catalog.Categories {
		out = append(out, row{Category: c, IndexedDomains: counts[c.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"categories": out})
}

// ResolverInfo tells an operator exactly what to type into their firewall.
type ResolverInfo struct {
	ListenUDP string            `json:"listenUdp"`
	ListenTCP string            `json:"listenTcp"`
	ListenDoT string            `json:"listenDot"`
	DoHURL    string            `json:"dohUrl"`
	Upstreams []UpstreamStatus  `json:"upstreams"`
	Networks  []NetworkEndpoint `json:"networks"`
}

// UpstreamStatus reports per-forwarder health.
type UpstreamStatus struct {
	Spec         string  `json:"spec"`
	Protocol     string  `json:"protocol"`
	Address      string  `json:"address"`
	Queries      uint64  `json:"queries"`
	Errors       uint64  `json:"errors"`
	AvgLatencyMS float64 `json:"avgLatencyMs"`
}

// NetworkEndpoint is the per-network DoH URL a roaming device should use.
type NetworkEndpoint struct {
	NetworkID string `json:"networkId"`
	Name      string `json:"name"`
	DoHURL    string `json:"dohUrl"`
}

func (a *API) handleResolvers(w http.ResponseWriter, r *http.Request) {
	base := a.Config.HTTP.BaseURL
	if base == "" {
		// Fall back to the host the operator reached us on, which is right far
		// more often than a guess at the public hostname would be.
		scheme := "http"
		if httpx.IsHTTPS(r, a.TrustedProxies) {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}

	info := ResolverInfo{
		ListenUDP: a.Config.DNS.ListenUDP,
		ListenTCP: a.Config.DNS.ListenTCP,
		ListenDoT: a.Config.DNS.ListenDoT,
		DoHURL:    base + "/dns-query",
	}

	for _, u := range a.Resolver.Upstreams() {
		q, e, avg := u.Stats()
		info.Upstreams = append(info.Upstreams, UpstreamStatus{
			Spec:         u.Spec,
			Protocol:     u.Protocol,
			Address:      u.Address,
			Queries:      q,
			Errors:       e,
			AvgLatencyMS: round2(avg),
		})
	}

	networks, err := a.Store.ListNetworks(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, n := range networks {
		if n.Token == "" {
			continue
		}
		info.Networks = append(info.Networks, NetworkEndpoint{
			NetworkID: n.ID,
			Name:      n.Name,
			DoHURL:    base + "/dns-query/" + n.Token,
		})
	}

	writeJSON(w, http.StatusOK, info)
}

// Settings is the effective runtime configuration, for display. It is
// read-only: configuration lives in the YAML file and environment so that a
// deployment is reproducible from its config, not from database state.
type Settings struct {
	Version         string  `json:"version"`
	DataDir         string  `json:"dataDir"`
	QueryLog        bool    `json:"queryLog"`
	LogClientIP     bool    `json:"logClientIp"`
	RetentionDays   int     `json:"retentionDays"`
	RollupDays      int     `json:"rollupDays"`
	CacheEnabled    bool    `json:"cacheEnabled"`
	CacheMaxEntries int     `json:"cacheMaxEntries"`
	CacheEntries    int     `json:"cacheEntries"`
	CacheHitRate    float64 `json:"cacheHitRate"`
	FeedRefresh     string  `json:"feedRefreshInterval"`
	UpstreamMode    string  `json:"upstreamMode"`
	QueryLogRows    int64   `json:"queryLogRows"`
	MemoryMB        float64 `json:"memoryMb"`
	Goroutines      int     `json:"goroutines"`
	UptimeSeconds   int64   `json:"uptimeSeconds"`
}

func (a *API) handleSettings(w http.ResponseWriter, r *http.Request) {
	size, hits, misses := a.Resolver.Cache().Stats()
	var hitRate float64
	if total := hits + misses; total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	rows, err := a.Store.CountQueryLogRows(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	writeJSON(w, http.StatusOK, Settings{
		Version:         version.String(),
		DataDir:         a.Config.DataDir,
		QueryLog:        a.Config.Log.QueryLog,
		LogClientIP:     a.Config.Log.LogClientIP,
		RetentionDays:   a.Config.Log.RetentionDays,
		RollupDays:      a.Config.Log.RollupDays,
		CacheEnabled:    a.Config.Cache.Enabled,
		CacheMaxEntries: a.Config.Cache.MaxEntries,
		CacheEntries:    size,
		CacheHitRate:    round2(hitRate),
		FeedRefresh:     a.Config.Feeds.RefreshInterval.String(),
		UpstreamMode:    a.Config.DNS.UpstreamMode,
		QueryLogRows:    rows,
		MemoryMB:        round2(float64(ms.Sys) / (1 << 20)),
		Goroutines:      runtime.NumGoroutine(),
		UptimeSeconds:   int64(time.Since(a.StartedAt).Seconds()),
	})
}

func intParam(r *http.Request, name string, def int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}
