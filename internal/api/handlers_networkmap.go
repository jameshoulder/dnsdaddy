package api

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// GET /api/v1/network-map — authenticated read-only DNS Security Map graph.
//
// Aggregates retained query_log rows into network → client → domain
// relationships for a bounded time window. Does not resolve DNS, enrich
// externally, mutate policy or invent topology. Findings are listed
// separately and never create "queried" edges.

type networkMapResponse struct {
	SchemaVersion     int       `json:"schemaVersion"`
	GeneratedAt       time.Time `json:"generatedAt"`
	RequestedHours    int       `json:"requestedHours,omitempty"`
	EffectiveFrom     time.Time `json:"effectiveFrom"`
	EffectiveTo       time.Time `json:"effectiveTo"`
	QueryLog          bool      `json:"queryLog"`
	ClientAttribution bool      `json:"clientAttribution"`
	RetentionDays     int       `json:"retentionDays"`
	Available         bool      `json:"available"`
	Unavailable       string    `json:"unavailable,omitempty"`
	Limitations       []string  `json:"limitations"`
	EdgeMeaning       string    `json:"edgeMeaning"`
	store.NetworkMapGraph
	ResolverStatus *networkMapResolverStatus `json:"resolverStatus,omitempty"`
}

type networkMapResolverStatus struct {
	Note string `json:"note"`
	Mode string `json:"mode,omitempty"`
}

func (a *API) handleNetworkMap(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	q := r.URL.Query()

	hours := 1
	useFifteen := q.Get("window") == "15m" || (q.Get("minutes") == "15" && q.Get("hours") == "" && q.Get("since") == "")
	if raw := q.Get("hours"); raw != "" {
		h, err := strconv.Atoi(raw)
		if err != nil || h < 0 || h > 24*7 {
			writeError(w, http.StatusBadRequest, "hours must be between 0 and 168")
			return
		}
		hours = h
	}

	var since, until time.Time
	var err error
	if useFifteen && q.Get("since") == "" {
		since = now.Add(-15 * time.Minute).UTC().Truncate(time.Millisecond)
		until = now
		hours = 0
	} else {
		since, until, err = requestTimeWindow(q, now, hours)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	retention := a.Config.Log.RetentionDays
	if retention <= 0 {
		retention = store.DefaultRetentionDays
	}
	retentionFloor := now.Add(-time.Duration(retention) * 24 * time.Hour)
	if since.IsZero() || since.Before(retentionFloor) {
		since = retentionFloor
	}
	if until.IsZero() {
		until = now
	}

	networkID := strings.TrimSpace(q.Get("networkId"))
	action := strings.TrimSpace(q.Get("action"))
	switch action {
	case "", store.ActionAllowed, store.ActionBlocked, store.ActionError:
	default:
		writeError(w, http.StatusBadRequest, "action must be empty, allowed, blocked or error")
		return
	}

	var clientIP string
	if raw := strings.TrimSpace(q.Get("client")); raw != "" {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "client must be an IP address")
			return
		}
		clientIP = addr.String()
	}
	var domain string
	if raw := strings.TrimSpace(q.Get("domain")); raw != "" {
		d := domainutil.Normalize(raw)
		if d == "" {
			writeError(w, http.StatusBadRequest, "domain must be a normalised DNS name")
			return
		}
		domain = d
	}
	search := strings.TrimSpace(q.Get("search"))
	if len(search) > 200 {
		writeError(w, http.StatusBadRequest, "search is too long")
		return
	}

	maxClients, maxDomains, maxEdges, maxSource := 0, 0, 0, 0
	if raw := q.Get("maxClients"); raw != "" {
		maxClients, err = strconv.Atoi(raw)
		if err != nil || maxClients < 1 {
			writeError(w, http.StatusBadRequest, "maxClients must be a positive integer")
			return
		}
	}
	if raw := q.Get("maxDomains"); raw != "" {
		maxDomains, err = strconv.Atoi(raw)
		if err != nil || maxDomains < 1 {
			writeError(w, http.StatusBadRequest, "maxDomains must be a positive integer")
			return
		}
	}
	if raw := q.Get("maxEdges"); raw != "" {
		maxEdges, err = strconv.Atoi(raw)
		if err != nil || maxEdges < 1 {
			writeError(w, http.StatusBadRequest, "maxEdges must be a positive integer")
			return
		}
	}
	if raw := q.Get("maxSourceRows"); raw != "" {
		maxSource, err = strconv.Atoi(raw)
		if err != nil || maxSource < 1 {
			writeError(w, http.StatusBadRequest, "maxSourceRows must be a positive integer")
			return
		}
	}

	queryLog := a.Config.Log.QueryLog
	attribution := queryLog && a.Config.Log.LogClientIP

	limitations := []string{
		"Edges mean DNS queries recorded in the selected window, not visits or connections.",
		"Client addresses are observed source IPs, not authenticated device identities.",
		"Network membership uses the networkId recorded on each query row.",
		"Findings are experimental and alert-only; they do not create queried edges.",
	}

	out := networkMapResponse{
		SchemaVersion:     store.NetworkMapSchemaVersion,
		GeneratedAt:       now,
		RequestedHours:    hours,
		EffectiveFrom:     since,
		EffectiveTo:       until,
		QueryLog:          queryLog,
		ClientAttribution: attribution,
		RetentionDays:     retention,
		Available:         true,
		Limitations:       limitations,
		EdgeMeaning:       "DNS queries recorded during the selected time window — not proof of a connection, visit, download or exfiltration.",
		NetworkMapGraph: store.NetworkMapGraph{
			Networks: []store.NetworkMapNetwork{},
			Clients:  []store.NetworkMapClient{},
			Domains:  []store.NetworkMapDomain{},
			Edges:    []store.NetworkMapEdge{},
			Findings: []store.NetworkMapFinding{},
		},
		ResolverStatus: &networkMapResolverStatus{
			Note: "Current runtime context only — not proof of the transport or validation mode used for every displayed historical query.",
		},
	}
	out.ResolverStatus.Mode = a.Config.DNS.LocalDNSSECValidation

	w.Header().Set("Cache-Control", "no-store")

	if !queryLog {
		out.Available = false
		out.Unavailable = "Query logging is disabled. The map cannot show per-query relationships until logging is enabled; previously retained rows are not erased by this setting alone."
		writeJSON(w, http.StatusOK, out)
		return
	}
	if !attribution {
		out.Available = false
		out.Unavailable = "Client address logging is disabled. Client nodes are not reconstructed from other tables. Network rollups remain available on Overview and Reports."
		out.Limitations = append(out.Limitations, "Privacy controls omitted client addresses; the map does not invent client identity.")
		writeJSON(w, http.StatusOK, out)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	networks, err := a.Store.ListNetworks(ctx)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	// Findings are loaded separately (no join that multiplies query counts).
	findings, _, err := a.Store.ListFindings(ctx, store.FindingFilter{
		Since: since, Until: until, Limit: 200,
	})
	if err != nil {
		// Findings are optional enrichment; map still works without them.
		findings = nil
		out.Limitations = append(out.Limitations, "Findings could not be loaded for this window; query relationships are still shown.")
	} else if networkID != "" {
		filtered := findings[:0]
		for _, f := range findings {
			if f.NetworkID == networkID || (f.NetworkID == "" && (f.ClientIP != "" || f.Domain != "")) {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	filter := store.NetworkMapFilter{
		Since: since, Until: until, NetworkID: networkID, Action: action,
		ClientIP: clientIP, Domain: domain, Search: search,
		MaxClients: maxClients, MaxDomains: maxDomains, MaxEdges: maxEdges, MaxSourceRows: maxSource,
	}
	graph, err := a.Store.BuildNetworkMap(ctx, filter, networks, findings)
	if err != nil {
		if ctx.Err() != nil {
			writeError(w, http.StatusGatewayTimeout, "map aggregation timed out; narrow the window or focus on one network")
			return
		}
		writeStoreError(w, err)
		return
	}
	out.NetworkMapGraph = graph

	if graph.Limits.TruncatedSource || graph.Limits.TruncatedClients || graph.Limits.TruncatedDomains || graph.Limits.TruncatedEdges {
		out.Limitations = append(out.Limitations, "The graph is truncated to bounded limits. Counts describe the displayed subset, not all retained traffic. Narrow filters or focus a client/domain to see more.")
	}
	if graph.Totals.UnattributedQueries > 0 {
		out.Limitations = append(out.Limitations, "Some query rows in the window have no recorded client address and are omitted from client nodes.")
	}

	writeJSON(w, http.StatusOK, out)
}
