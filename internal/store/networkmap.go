package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Network-map aggregation for the DNS Security Map.
//
// Built only from retained query_log rows and separately listed findings.
// Findings never invent query edges. Source rows are capped before GROUP BY
// so a long window cannot pull the whole table into memory. Display limits
// are applied after aggregation and reported as truncation, not silent drop.

const (
	// NetworkMapSchemaVersion is the JSON contract version for map responses.
	NetworkMapSchemaVersion = 1

	// Default caps for a usable first paint. Soft display targets; hard caps
	// refuse to grow further.
	NetworkMapDefaultMaxClients = 80
	NetworkMapDefaultMaxDomains = 70
	NetworkMapDefaultMaxEdges   = 300
	NetworkMapHardMaxClients    = 250
	NetworkMapHardMaxDomains    = 250
	NetworkMapHardMaxEdges      = 1000
	NetworkMapDefaultSourceCap  = 50000
	NetworkMapHardSourceCap     = 100000
)

// NetworkMapFilter bounds a map aggregation.
type NetworkMapFilter struct {
	Since     time.Time
	Until     time.Time // exclusive upper bound when set; zero means open
	NetworkID string    // empty = all networks present in retained rows
	Action    string    // empty | allowed | blocked | error
	ClientIP  string    // optional focus
	Domain    string    // optional exact domain focus
	Search    string    // substring match on client ip/name or domain (display filter)

	MaxClients    int
	MaxDomains    int
	MaxEdges      int
	MaxSourceRows int
}

// NetworkMapGraph is the aggregated graph for one window.
type NetworkMapGraph struct {
	Networks []NetworkMapNetwork `json:"networks"`
	Clients  []NetworkMapClient  `json:"clients"`
	Domains  []NetworkMapDomain  `json:"domains"`
	Edges    []NetworkMapEdge    `json:"edges"`
	Findings []NetworkMapFinding `json:"findings"`

	Totals NetworkMapTotals `json:"totals"`
	Limits NetworkMapLimits `json:"limits"`
}

// NetworkMapNetwork is a configured network container.
type NetworkMapNetwork struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	CIDRs   []string `json:"cidrs,omitempty"`
	// ClientsInWindow counts attributed clients under this network in the
	// processed subset (not a lifetime total).
	ClientsInWindow int   `json:"clientsInWindow"`
	Queries         int64 `json:"queries"`
	Blocked         int64 `json:"blocked"`
	Errors          int64 `json:"errors"`
}

// NetworkMapClient is an observed DNS client context in the window.
type NetworkMapClient struct {
	ID         string     `json:"id"` // stable: "client:"+networkId+"/"+ip
	ClientIP   string     `json:"clientIp"`
	ClientName string     `json:"clientName,omitempty"`
	NameSource string     `json:"nameSource,omitempty"` // operator | recorded | ""
	NetworkID  string     `json:"networkId"`
	Queries    int64      `json:"queries"`
	Allowed    int64      `json:"allowed"`
	Blocked    int64      `json:"blocked"`
	Errors     int64      `json:"errors"`
	Domains    int64      `json:"distinctDomains"`
	FirstSeen  *time.Time `json:"firstSeen,omitempty"`
	LastSeen   *time.Time `json:"lastSeen,omitempty"`
	// AttributionSource states that networkId came from the recorded query
	// row, not from reclassifying with today's CIDRs.
	AttributionSource string `json:"attributionSource"` // recorded_query
}

// NetworkMapDomain is an exact queried name in the window.
type NetworkMapDomain struct {
	ID        string     `json:"id"` // "domain:"+name
	Domain    string     `json:"domain"`
	Queries   int64      `json:"queries"`
	Allowed   int64      `json:"allowed"`
	Blocked   int64      `json:"blocked"`
	Errors    int64      `json:"errors"`
	Clients   int64      `json:"distinctClients"`
	Category  string     `json:"category,omitempty"` // most recent block category if any
	FirstSeen *time.Time `json:"firstSeen,omitempty"`
	LastSeen  *time.Time `json:"lastSeen,omitempty"`
}

// NetworkMapEdge is a client→domain query relationship in the window.
type NetworkMapEdge struct {
	ID        string           `json:"id"`
	Type      string           `json:"type"` // queried
	ClientID  string           `json:"clientId"`
	DomainID  string           `json:"domainId"`
	Queries   int64            `json:"queries"`
	Allowed   int64            `json:"allowed"`
	Blocked   int64            `json:"blocked"`
	Errors    int64            `json:"errors"`
	QTypes    map[string]int64 `json:"qtypes,omitempty"`
	FirstSeen *time.Time       `json:"firstSeen,omitempty"`
	LastSeen  *time.Time       `json:"lastSeen,omitempty"`
	// Meaning restates the edge contract for API consumers.
	Meaning string `json:"meaning"`
}

// NetworkMapFinding links an experimental finding to map subjects without
// creating a queried edge.
type NetworkMapFinding struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	EventType string    `json:"eventType"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	ClientIP  string    `json:"clientIp,omitempty"`
	NetworkID string    `json:"networkId,omitempty"`
	Domain    string    `json:"domain,omitempty"`
	ClientID  string    `json:"clientId,omitempty"`
	DomainID  string    `json:"domainId,omitempty"`
	Maturity  string    `json:"maturity"` // experimental
}

// NetworkMapTotals describe the processed subset, not all retained traffic
// unless SourceRowsProcessed < SourceRowCap and TruncatedSource is false.
type NetworkMapTotals struct {
	SourceRowsProcessed int64 `json:"sourceRowsProcessed"`
	Clients             int   `json:"clients"`
	Domains             int   `json:"domains"`
	Edges               int   `json:"edges"`
	FindingsLinked      int   `json:"findingsLinked"`
	Queries             int64 `json:"queries"`
	Allowed             int64 `json:"allowed"`
	Blocked             int64 `json:"blocked"`
	Errors              int64 `json:"errors"`
	UnattributedQueries int64 `json:"unattributedQueries"`
}

// NetworkMapLimits reports caps and truncation.
type NetworkMapLimits struct {
	MaxClients       int  `json:"maxClients"`
	MaxDomains       int  `json:"maxDomains"`
	MaxEdges         int  `json:"maxEdges"`
	MaxSourceRows    int  `json:"maxSourceRows"`
	TruncatedClients bool `json:"truncatedClients"`
	TruncatedDomains bool `json:"truncatedDomains"`
	TruncatedEdges   bool `json:"truncatedEdges"`
	TruncatedSource  bool `json:"truncatedSource"`
	OmittedClients   int  `json:"omittedClients,omitempty"`
	OmittedDomains   int  `json:"omittedDomains,omitempty"`
	OmittedEdges     int  `json:"omittedEdges,omitempty"`
}

func clampMapLimits(f *NetworkMapFilter) {
	if f.MaxClients <= 0 {
		f.MaxClients = NetworkMapDefaultMaxClients
	}
	if f.MaxClients > NetworkMapHardMaxClients {
		f.MaxClients = NetworkMapHardMaxClients
	}
	if f.MaxDomains <= 0 {
		f.MaxDomains = NetworkMapDefaultMaxDomains
	}
	if f.MaxDomains > NetworkMapHardMaxDomains {
		f.MaxDomains = NetworkMapHardMaxDomains
	}
	if f.MaxEdges <= 0 {
		f.MaxEdges = NetworkMapDefaultMaxEdges
	}
	if f.MaxEdges > NetworkMapHardMaxEdges {
		f.MaxEdges = NetworkMapHardMaxEdges
	}
	if f.MaxSourceRows <= 0 {
		f.MaxSourceRows = NetworkMapDefaultSourceCap
	}
	if f.MaxSourceRows > NetworkMapHardSourceCap {
		f.MaxSourceRows = NetworkMapHardSourceCap
	}
}

func networkMapWhere(f NetworkMapFilter) (string, []any) {
	var parts []string
	var args []any
	if !f.Since.IsZero() {
		parts = append(parts, "ts >= ?")
		args = append(args, f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		parts = append(parts, "ts < ?")
		args = append(args, f.Until.UnixMilli())
	}
	if f.NetworkID != "" {
		parts = append(parts, "network_id = ?")
		args = append(args, f.NetworkID)
	}
	switch f.Action {
	case ActionAllowed, ActionBlocked, ActionError:
		parts = append(parts, "action = ?")
		args = append(args, f.Action)
	}
	if f.ClientIP != "" {
		parts = append(parts, "client_ip = ?")
		args = append(args, f.ClientIP)
	}
	if f.Domain != "" {
		parts = append(parts, "qname = ?")
		args = append(args, f.Domain)
	}
	if len(parts) == 0 {
		return "1=1", args
	}
	return strings.Join(parts, " AND "), args
}

func clientNodeID(networkID, ip string) string {
	if networkID == "" {
		networkID = "unknown"
	}
	return "client:" + networkID + "/" + ip
}

func domainNodeID(domain string) string {
	return "domain:" + domain
}

// BuildNetworkMap aggregates the graph for the DNS Security Map.
//
// networks is the configured network list (containers). Client network IDs
// come from recorded query rows. Findings are attached by exact client/domain
// match and do not create queried edges.
func (s *Store) BuildNetworkMap(ctx context.Context, f NetworkMapFilter, networks []Network, findings []Finding) (NetworkMapGraph, error) {
	clampMapLimits(&f)
	out := NetworkMapGraph{
		Networks: []NetworkMapNetwork{},
		Clients:  []NetworkMapClient{},
		Domains:  []NetworkMapDomain{},
		Edges:    []NetworkMapEdge{},
		Findings: []NetworkMapFinding{},
		Limits: NetworkMapLimits{
			MaxClients: f.MaxClients, MaxDomains: f.MaxDomains,
			MaxEdges: f.MaxEdges, MaxSourceRows: f.MaxSourceRows,
		},
	}

	where, args := networkMapWhere(f)
	// Cap source rows newest-first so recent activity wins under pressure.
	// #nosec G202 -- where is literal fragments; values are bound.
	scopedSQL := `
		SELECT id, ts, client_ip, client_name, network_id, qname, qtype, action, category
		  FROM query_log
		 WHERE ` + where + `
		 ORDER BY ts DESC
		 LIMIT ?`
	scopedArgs := append(append([]any{}, args...), f.MaxSourceRows+1)

	rows, err := s.db.QueryContext(ctx, scopedSQL, scopedArgs...)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	type edgeKey struct{ net, ip, domain string }
	type clientKey struct{ net, ip string }

	type aggOutcomes struct {
		queries, allowed, blocked, errors int64
		first, last                       int64
		category                          string // last seen block category
	}
	type clientAgg struct {
		aggOutcomes
		name    string
		domains map[string]struct{}
	}
	type domainAgg struct {
		aggOutcomes
		clients map[string]struct{}
	}
	type edgeAgg struct {
		aggOutcomes
		qtypes map[string]int64
	}

	clients := map[clientKey]*clientAgg{}
	domains := map[string]*domainAgg{}
	edges := map[edgeKey]*edgeAgg{}
	var processed int64
	var unattributed int64

	// Source rows are scanned newest-first (ORDER BY ts DESC). Keep the first
	// nonempty metadata value so client names and block categories reflect the
	// most recent evidence in the window, not the oldest overwrite.
	addOutcome := func(a *aggOutcomes, action string, ts int64, category string) {
		a.queries++
		switch action {
		case ActionAllowed:
			a.allowed++
		case ActionBlocked:
			a.blocked++
			if category != "" && a.category == "" {
				a.category = category
			}
		case ActionError:
			a.errors++
		}
		if a.first == 0 || ts < a.first {
			a.first = ts
		}
		if ts > a.last {
			a.last = ts
		}
	}

	for rows.Next() {
		var (
			id                                              int64
			ts                                              int64
			cip, cname, nid, qname, qtype, action, category string
		)
		if err := rows.Scan(&id, &ts, &cip, &cname, &nid, &qname, &qtype, &action, &category); err != nil {
			return out, err
		}
		processed++
		if processed > int64(f.MaxSourceRows) {
			out.Limits.TruncatedSource = true
			break
		}
		if cip == "" {
			unattributed++
			continue
		}
		if f.Search != "" {
			needle := strings.ToLower(f.Search)
			hay := strings.ToLower(cip + " " + cname + " " + qname + " " + nid)
			if !strings.Contains(hay, needle) {
				continue
			}
		}

		ck := clientKey{net: nid, ip: cip}
		ca := clients[ck]
		if ca == nil {
			ca = &clientAgg{domains: map[string]struct{}{}}
			clients[ck] = ca
		}
		if cname != "" && ca.name == "" {
			ca.name = cname
		}
		addOutcome(&ca.aggOutcomes, action, ts, category)
		ca.domains[qname] = struct{}{}

		da := domains[qname]
		if da == nil {
			da = &domainAgg{clients: map[string]struct{}{}}
			domains[qname] = da
		}
		addOutcome(&da.aggOutcomes, action, ts, category)
		da.clients[cip+"@"+nid] = struct{}{}

		ek := edgeKey{net: nid, ip: cip, domain: qname}
		ea := edges[ek]
		if ea == nil {
			ea = &edgeAgg{qtypes: map[string]int64{}}
			edges[ek] = ea
		}
		addOutcome(&ea.aggOutcomes, action, ts, category)
		if qtype != "" {
			ea.qtypes[qtype]++
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}

	out.Totals.SourceRowsProcessed = processed
	if out.Limits.TruncatedSource {
		out.Totals.SourceRowsProcessed = int64(f.MaxSourceRows)
	}
	out.Totals.UnattributedQueries = unattributed

	// Sort clients by queries desc for stable truncation.
	type clientRank struct {
		key clientKey
		agg *clientAgg
	}
	clientRanks := make([]clientRank, 0, len(clients))
	for k, a := range clients {
		clientRanks = append(clientRanks, clientRank{k, a})
	}
	sort.Slice(clientRanks, func(i, j int) bool {
		if clientRanks[i].agg.queries != clientRanks[j].agg.queries {
			return clientRanks[i].agg.queries > clientRanks[j].agg.queries
		}
		if clientRanks[i].key.ip != clientRanks[j].key.ip {
			return clientRanks[i].key.ip < clientRanks[j].key.ip
		}
		return clientRanks[i].key.net < clientRanks[j].key.net
	})
	if len(clientRanks) > f.MaxClients {
		out.Limits.TruncatedClients = true
		out.Limits.OmittedClients = len(clientRanks) - f.MaxClients
		clientRanks = clientRanks[:f.MaxClients]
	}
	keptClients := map[clientKey]struct{}{}
	for _, cr := range clientRanks {
		keptClients[cr.key] = struct{}{}
		fs, ls := msPtr(cr.agg.first), msPtr(cr.agg.last)
		nameSource := ""
		if cr.agg.name != "" {
			nameSource = "recorded"
		}
		out.Clients = append(out.Clients, NetworkMapClient{
			ID: clientNodeID(cr.key.net, cr.key.ip), ClientIP: cr.key.ip, ClientName: cr.agg.name,
			NameSource: nameSource, NetworkID: cr.key.net,
			Queries: cr.agg.queries, Allowed: cr.agg.allowed, Blocked: cr.agg.blocked, Errors: cr.agg.errors,
			Domains: int64(len(cr.agg.domains)), FirstSeen: fs, LastSeen: ls,
			AttributionSource: "recorded_query",
		})
		out.Totals.Queries += cr.agg.queries
		out.Totals.Allowed += cr.agg.allowed
		out.Totals.Blocked += cr.agg.blocked
		out.Totals.Errors += cr.agg.errors
	}
	out.Totals.Clients = len(out.Clients)

	type domainRank struct {
		name string
		agg  *domainAgg
	}
	domainRanks := make([]domainRank, 0, len(domains))
	for name, a := range domains {
		domainRanks = append(domainRanks, domainRank{name, a})
	}
	sort.Slice(domainRanks, func(i, j int) bool {
		if domainRanks[i].agg.queries != domainRanks[j].agg.queries {
			return domainRanks[i].agg.queries > domainRanks[j].agg.queries
		}
		return domainRanks[i].name < domainRanks[j].name
	})
	if len(domainRanks) > f.MaxDomains {
		out.Limits.TruncatedDomains = true
		out.Limits.OmittedDomains = len(domainRanks) - f.MaxDomains
		domainRanks = domainRanks[:f.MaxDomains]
	}
	keptDomains := map[string]struct{}{}
	for _, dr := range domainRanks {
		keptDomains[dr.name] = struct{}{}
		fs, ls := msPtr(dr.agg.first), msPtr(dr.agg.last)
		out.Domains = append(out.Domains, NetworkMapDomain{
			ID: domainNodeID(dr.name), Domain: dr.name,
			Queries: dr.agg.queries, Allowed: dr.agg.allowed, Blocked: dr.agg.blocked, Errors: dr.agg.errors,
			Clients: int64(len(dr.agg.clients)), Category: dr.agg.category, FirstSeen: fs, LastSeen: ls,
		})
	}
	out.Totals.Domains = len(out.Domains)

	type edgeRank struct {
		key edgeKey
		agg *edgeAgg
	}
	edgeRanks := make([]edgeRank, 0, len(edges))
	for k, a := range edges {
		if _, ok := keptClients[clientKey{k.net, k.ip}]; !ok {
			continue
		}
		if _, ok := keptDomains[k.domain]; !ok {
			continue
		}
		edgeRanks = append(edgeRanks, edgeRank{k, a})
	}
	sort.Slice(edgeRanks, func(i, j int) bool {
		if edgeRanks[i].agg.queries != edgeRanks[j].agg.queries {
			return edgeRanks[i].agg.queries > edgeRanks[j].agg.queries
		}
		if edgeRanks[i].key.ip != edgeRanks[j].key.ip {
			return edgeRanks[i].key.ip < edgeRanks[j].key.ip
		}
		return edgeRanks[i].key.domain < edgeRanks[j].key.domain
	})
	if len(edgeRanks) > f.MaxEdges {
		out.Limits.TruncatedEdges = true
		out.Limits.OmittedEdges = len(edgeRanks) - f.MaxEdges
		edgeRanks = edgeRanks[:f.MaxEdges]
	}
	for _, er := range edgeRanks {
		cid := clientNodeID(er.key.net, er.key.ip)
		did := domainNodeID(er.key.domain)
		fs, ls := msPtr(er.agg.first), msPtr(er.agg.last)
		out.Edges = append(out.Edges, NetworkMapEdge{
			ID:   fmt.Sprintf("queried:%s->%s", cid, did),
			Type: "queried", ClientID: cid, DomainID: did,
			Queries: er.agg.queries, Allowed: er.agg.allowed, Blocked: er.agg.blocked, Errors: er.agg.errors,
			QTypes: er.agg.qtypes, FirstSeen: fs, LastSeen: ls,
			Meaning: "DNS queries recorded during the selected time window — not proof of a connection, visit, download or exfiltration.",
		})
	}
	out.Totals.Edges = len(out.Edges)

	// Network containers from configuration, with counts from kept clients.
	netByID := map[string]NetworkMapNetwork{}
	for _, n := range networks {
		if f.NetworkID != "" && n.ID != f.NetworkID {
			continue
		}
		netByID[n.ID] = NetworkMapNetwork{ID: n.ID, Name: n.Name, Enabled: n.Enabled, CIDRs: append([]string{}, n.CIDRs...)}
	}
	for _, c := range out.Clients {
		nn, ok := netByID[c.NetworkID]
		if !ok {
			if f.NetworkID != "" {
				continue
			}
			nn = NetworkMapNetwork{ID: c.NetworkID, Name: c.NetworkID + " (recorded)", Enabled: false}
		}
		nn.ClientsInWindow++
		nn.Queries += c.Queries
		nn.Blocked += c.Blocked
		nn.Errors += c.Errors
		netByID[c.NetworkID] = nn
	}
	for _, nn := range netByID {
		// Omit empty configured containers from the graph unless the operator
		// filtered to that networkId explicitly — membership without queries
		// is configuration, not observed DNS activity.
		if nn.ClientsInWindow == 0 && f.NetworkID == "" {
			continue
		}
		out.Networks = append(out.Networks, nn)
	}
	sort.Slice(out.Networks, func(i, j int) bool {
		if out.Networks[i].Queries != out.Networks[j].Queries {
			return out.Networks[i].Queries > out.Networks[j].Queries
		}
		return out.Networks[i].ID < out.Networks[j].ID
	})

	clientByIPNet := map[clientKey]string{}
	for _, c := range out.Clients {
		clientByIPNet[clientKey{c.NetworkID, c.ClientIP}] = c.ID
	}
	domainIDs := map[string]string{}
	for _, d := range out.Domains {
		domainIDs[d.Domain] = d.ID
	}
	for _, fnd := range findings {
		mf := NetworkMapFinding{
			ID: fnd.ID, Time: fnd.Time, EventType: fnd.EventType, Severity: fnd.Severity,
			Title: fnd.Title, ClientIP: fnd.ClientIP, NetworkID: fnd.NetworkID, Domain: fnd.Domain,
			Maturity: "experimental",
		}
		if fnd.ClientIP != "" {
			nid := fnd.NetworkID
			if nid == "" {
				// Link by IP alone only when exactly one displayed client
				// context matches; otherwise leave unset rather than guess.
				var matchID, matchNet string
				matches := 0
				for ck, id := range clientByIPNet {
					if ck.ip != fnd.ClientIP {
						continue
					}
					matches++
					matchID, matchNet = id, ck.net
					if matches > 1 {
						break
					}
				}
				if matches == 1 {
					mf.ClientID = matchID
					mf.NetworkID = matchNet
				}
			} else if id, ok := clientByIPNet[clientKey{nid, fnd.ClientIP}]; ok {
				mf.ClientID = id
			}
		}
		if fnd.Domain != "" {
			if id, ok := domainIDs[fnd.Domain]; ok {
				mf.DomainID = id
			}
		}
		// Keep findings that attach to a displayed node, or that share the
		// filtered network even without a displayed edge.
		if mf.ClientID == "" && mf.DomainID == "" {
			if f.NetworkID != "" && fnd.NetworkID != f.NetworkID {
				continue
			}
			if f.NetworkID == "" && fnd.ClientIP == "" && fnd.Domain == "" {
				continue
			}
		}
		out.Findings = append(out.Findings, mf)
	}
	out.Totals.FindingsLinked = len(out.Findings)
	return out, nil
}

func msPtr(ms int64) *time.Time {
	if ms == 0 {
		return nil
	}
	t := time.UnixMilli(ms).UTC()
	return &t
}
