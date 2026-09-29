package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
	"github.com/jameshoulder/dnsdaddy/internal/evidence"
	"github.com/jameshoulder/dnsdaddy/internal/learning"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// The investigation service: one name or one address, everything already
// recorded about it, in sections that never blur into each other.
//
// Read-only by construction. Every handler here calls store methods that
// only SELECT, and the one evaluation it performs — the policy preview —
// runs on the engine's compiled snapshot through the same code as a live
// query, minus the step that asks an external provider. No query-log row,
// decision record, cache entry or configuration is written by any GET here.
// The enrichment POST is the deliberate exception and says so.
//
// The sections are kept apart because they answer different questions:
//
//	activity    what the query log recorded — outcomes, not verdicts
//	decisions   what was decided at the time, as it was written down then
//	preview     what the current configuration would decide now
//	evidence    what is on file now, and whether any of it ever decided
//	findings    what the experimental detectors inferred, which enforces
//	            nothing
//	observations retained local verdicts with their recorded provenance
//
// A "historical reason" is never re-rendered from today's policy: decisions
// are the stored rows, and the preview is labelled as a preview.

// investigationWindow describes the retained-data window a request covers.
type investigationWindow struct {
	Hours int       `json:"hours"`
	From  time.Time `json:"from"`
	To    time.Time `json:"to"`
	// RetentionDays bounds how far back any per-query row can exist, so a
	// window longer than it covers only what retention kept.
	RetentionDays int `json:"retentionDays"`
	// QueryLog and ClientAttribution restate the two privacy settings that
	// decide whether per-query rows and client addresses exist at all.
	QueryLog          bool `json:"queryLog"`
	ClientAttribution bool `json:"clientAttribution"`
}

// investigationActivity is the recorded-activity section.
type investigationActivity struct {
	Source string `json:"source"`
	// Available is false when the instance-wide query log is off, in which
	// case nothing below was measured and Unavailable says so.
	Available   bool                  `json:"available"`
	Unavailable string                `json:"unavailable,omitempty"`
	Summary     store.ActivitySummary `json:"summary"`
	// Clients are the attributed clients that asked for the name, busiest
	// first. Empty when client addresses are not recorded.
	Clients []store.ClientOfDomain `json:"clients,omitempty"`
	// Domains are the names a client asked for, most asked first.
	Domains []store.DomainOfClient `json:"domains,omitempty"`
	// Recent is the newest recorded rows, with local DNSSEC observations
	// attached where they exist.
	Recent []queryRow `json:"recent"`
	// RecentCursor continues the recent list through /api/v1/queries with
	// the same filters; 0 when Recent holds every matching row.
	RecentCursor int64 `json:"recentCursor"`
	RecentLimit  int   `json:"recentLimit"`
	// Note names the limitation of what was searched.
	Note string `json:"note"`
}

// investigationDecisions is the historical-decisions section.
type investigationDecisions struct {
	// Recording reports whether decision records are switched on at all,
	// so an empty list can be told from a feature that is off.
	Recording  bool             `json:"recording"`
	Items      []store.Decision `json:"items"`
	Truncated  bool             `json:"truncated"`
	NextCursor string           `json:"nextCursor"`
	Note       string           `json:"note"`
}

// investigationPreview is the current-policy-preview section.
type investigationPreview struct {
	ReadOnly bool `json:"readOnly"`
	// Context names what the preview was evaluated for and how the client
	// was attributed, so the reader can see it is one possible context.
	Context previewContext `json:"context"`
	// Decision is what the current configuration would decide.
	Decision previewDecision `json:"decision"`
	// External describes the provider step.
	External previewExternal `json:"external"`
	// ByPolicy evaluates the name under every configured policy, so the
	// reader can see how a different assignment would decide without
	// changing anything.
	ByPolicy []previewByPolicy `json:"byPolicy"`
	Note     string            `json:"note"`
}

type previewContext struct {
	Client      string `json:"client,omitempty"`
	Attribution string `json:"attribution"`
	NetworkID   string `json:"networkId,omitempty"`
	NetworkName string `json:"networkName,omitempty"`
	PolicyID    string `json:"policyId,omitempty"`
	PolicyName  string `json:"policyName,omitempty"`
}

type previewDecision struct {
	// Outcome is "blocked", "allowed" or "not_evaluated". The last is what
	// the preview says when the live outcome would depend on an external
	// lookup this preview did not perform.
	Outcome   string `json:"outcome"`
	Rule      string `json:"rule,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Category  string `json:"category,omitempty"`
	Source    string `json:"source,omitempty"`
	BlockMode string `json:"blockMode,omitempty"`
}

type previewExternal struct {
	Configured bool   `json:"configured"`
	Mode       string `json:"mode,omitempty"`
	Reached    bool   `json:"reached"`
	Evaluated  bool   `json:"evaluated"`
	FromCache  bool   `json:"fromCache"`
	Provider   string `json:"provider,omitempty"`
	Note       string `json:"note"`
}

type previewByPolicy struct {
	PolicyID   string          `json:"policyId"`
	PolicyName string          `json:"policyName"`
	Networks   int             `json:"assignedNetworks"`
	Decision   previewDecision `json:"decision"`
}

// investigationEvidence is the current-evidence section.
type investigationEvidence struct {
	Assessment evidence.Assessment `json:"assessment"`
	Items      []evidenceItem      `json:"items"`
	Note       string              `json:"note"`
}

// evidenceItem is one row on file, with its freshness and its record.
type evidenceItem struct {
	evidence.Evidence
	// Expired reports the claim is past its own expiry and excluded from
	// the assessment. Shown rather than hidden: "listed until Tuesday" is
	// useful to an investigator.
	Expired bool `json:"expired"`
	// ContributedTo is how many recorded decisions cited this row as the
	// one that decided. Zero means on file, never load-bearing.
	ContributedTo int64 `json:"contributedTo"`
}

// investigationFindings is the related-findings section.
type investigationFindings struct {
	Enabled      bool              `json:"enabled"`
	Enforcement  string            `json:"enforcement"`
	Experimental bool              `json:"experimental"`
	Items        []findingResponse `json:"items"`
	Truncated    bool              `json:"truncated"`
	Note         string            `json:"note"`
}

// investigationObservations is the Daddybound section.
type investigationObservations struct {
	Mode         string                    `json:"mode"`
	Available    bool                      `json:"available"`
	Active       bool                      `json:"active"`
	Enforcing    bool                      `json:"enforcing"`
	Experimental bool                      `json:"experimental"`
	Items        []store.DNSSECObservation `json:"items"`
	Truncated    bool                      `json:"truncated"`
	Note         string                    `json:"note"`
}

// domainInvestigation is the response for one name.
type domainInvestigation struct {
	Subject struct {
		Domain string `json:"domain"`
		Input  string `json:"input"`
		Client string `json:"client,omitempty"`
	} `json:"subject"`
	Window       investigationWindow       `json:"window"`
	Activity     investigationActivity     `json:"activity"`
	Decisions    investigationDecisions    `json:"decisions"`
	Preview      investigationPreview      `json:"preview"`
	Evidence     investigationEvidence     `json:"evidence"`
	Findings     investigationFindings     `json:"findings"`
	Observations investigationObservations `json:"observations"`
}

// clientInvestigation is the response for one address.
type clientInvestigation struct {
	Subject struct {
		Client string `json:"client"`
		Name   string `json:"name,omitempty"`
		// Attribution is what the current configuration says about this
		// address: which network and policy it maps to now. Current, not
		// historical; the recorded rows carry their own network id.
		Attribution previewContext `json:"attribution"`
	} `json:"subject"`
	Window       investigationWindow       `json:"window"`
	Activity     investigationActivity     `json:"activity"`
	Decisions    investigationDecisions    `json:"decisions"`
	Findings     investigationFindings     `json:"findings"`
	Learning     investigationLearning     `json:"learning"`
	Observations investigationObservations `json:"observations"`
}

type investigationLearning struct {
	Enabled   bool                 `json:"enabled"`
	Available bool                 `json:"available"`
	Found     *bool                `json:"found"`
	Client    *learning.ClientView `json:"client,omitempty"`
	Note      string               `json:"note"`
}

// Bounds on what one request may pull.
const (
	investigateMaxHours    = 24 * 365
	investigateRecentLimit = 100
	investigateListLimit   = 50
)

// investigationWindowFor reads the hours parameter into a window bounded by
// what retention could hold.
func (a *API) investigationWindowFor(r *http.Request, now time.Time) investigationWindow {
	retention := a.Config.Log.RetentionDays
	if retention <= 0 {
		retention = store.DefaultRetentionDays
	}
	hours := boundedParam(r.URL.Query().Get("hours"), retention*24, 1, investigateMaxHours)
	return investigationWindow{
		Hours:             hours,
		From:              now.Add(-time.Duration(hours) * time.Hour).UTC(),
		To:                now.UTC(),
		RetentionDays:     retention,
		QueryLog:          a.Config.Log.QueryLog,
		ClientAttribution: a.Config.Log.QueryLog && a.Config.Log.LogClientIP,
	}
}

// parseClientParam reads an optional client address, or reports why it is
// not one. Zoned and IPv4-mapped forms are normalised to what the query log
// stores.
func parseClientParam(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", errors.New("client must be an IP address")
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr.WithZone("").String(), nil
}

// handleInvestigateDomain answers everything recorded about one name.
//
// GET /api/v1/investigate/domain/{domain}?client=&hours=
func (a *API) handleInvestigateDomain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()

	input := r.PathValue("domain")
	domain, err := domainutil.NormalizeInput(input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	client, err := parseClientParam(r.URL.Query().Get("client"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var out domainInvestigation
	out.Subject.Domain = domain
	out.Subject.Input = input
	out.Subject.Client = client
	out.Window = a.investigationWindowFor(r, now)
	since := out.Window.From

	// --- recorded activity ----------------------------------------------------
	if out.Activity, err = a.domainActivity(ctx, domain, client, since, out.Window); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// --- historical decisions ------------------------------------------------
	if out.Decisions, err = a.decisionsFor(ctx, store.DecisionFilter{Subject: domain, ClientIP: client, Since: since, Until: out.Window.To}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// --- current policy preview ---------------------------------------------
	if out.Preview, err = a.policyPreview(ctx, domain, client); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// --- current evidence ----------------------------------------------------
	if out.Evidence, err = a.evidenceFor(ctx, domain, now); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// --- related findings ----------------------------------------------------
	if out.Findings, err = a.findingsForDomain(ctx, domain, client, since, out.Window.To); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// --- Daddybound observations ---------------------------------------------
	if out.Observations, err = a.observationsFor(ctx, domain, client, since, out.Window.To); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, out)
}

// handleInvestigateClient answers everything recorded about one address.
//
// GET /api/v1/investigate/client/{ip}?hours=
func (a *API) handleInvestigateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()

	client, err := parseClientParam(r.PathValue("ip"))
	if err != nil || client == "" {
		writeError(w, http.StatusBadRequest, "the path must name an IP address")
		return
	}

	var out clientInvestigation
	out.Subject.Client = client
	out.Subject.Name = a.Engine.ClientName(client)
	out.Window = a.investigationWindowFor(r, now)
	since := out.Window.From
	foundBaseline := false
	out.Learning = investigationLearning{
		Enabled:   a.Learning != nil,
		Available: a.Learning != nil,
		Found:     &foundBaseline,
		Note:      "current bounded local baseline, separate from recorded query history; no baseline or anomaly is proof of a benign or malicious device. Reading this view does not train the model",
	}
	if a.Learning != nil {
		if view, found := a.Learning.Inspect(client); found {
			foundBaseline = true
			out.Learning.Client = &view
		}
	} else if a.LearningError != "" {
		out.Learning.Enabled = true
		out.Learning.Found = nil
		out.Learning.Note = learning.UnavailableStatus().Error
	}

	// Current attribution, from the live engine: the network and policy this
	// address would receive now. Labelled current; the recorded rows carry
	// the network they were attributed to at the time.
	if addr, perr := netip.ParseAddr(client); perr == nil {
		m := a.Engine.MatchClient(addr)
		out.Subject.Attribution = previewContext{
			Client: client, Attribution: attributionKind(m),
			NetworkID: m.NetworkID, NetworkName: m.NetworkName,
			PolicyID: m.PolicyID, PolicyName: m.PolicyName,
		}
	}

	if out.Activity, err = a.clientActivity(ctx, client, since, out.Window); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out.Decisions, err = a.decisionsFor(ctx, store.DecisionFilter{ClientIP: client, Since: since, Until: out.Window.To}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out.Findings, err = a.findingsForClient(ctx, client, since, out.Window.To); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out.Observations, err = a.observationsFor(ctx, "", client, since, out.Window.To); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, out)
}

// handleInvestigateEnrich is the one deliberate write-adjacent action: ask
// the configured external providers about a name, now, within their
// existing budgets and mode.
//
// POST /api/v1/investigate/domain/{domain}/enrich
//
// A POST, so it sits behind the same-origin check like every other
// state-changing request, and so a link cannot trigger a provider call.
// It uses the provider engine exactly as the resolution path would in the
// configured mode: off consults nobody, cache-only queues a lookup for next
// time, blocking waits for at most the configured budget. Nothing about
// the request widens what the operator configured.
func (a *API) handleInvestigateEnrich(w http.ResponseWriter, r *http.Request) {
	domain, err := domainutil.NormalizeInput(r.PathValue("domain"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.Providers == nil {
		writeError(w, http.StatusServiceUnavailable,
			"external provider service is unavailable on this deployment")
		return
	}
	client, err := parseClientParam(r.URL.Query().Get("client"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var body struct {
		Consent bool `json:"consent"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if !body.Consent {
		writeError(w, http.StatusBadRequest, "consent must be true to send this domain to your configured external providers")
		return
	}
	policyID := a.previewPolicyID(client)
	mode := a.Providers.Mode()
	resp := map[string]any{
		"domain":   domain,
		"policyId": policyID,
		"mode":     string(mode),
		"lookup":   "not_performed",
		"verdict":  nil,
	}

	switch mode {
	case apiprovider.ModeOff:
		resp["note"] = "reputation lookup was not performed because its mode is off; independently enabled enrichment is reported separately"
	default:
		verdict, ok := a.Providers.Consult(r.Context(), policyID, domain)
		switch {
		case ok:
			resp["lookup"] = "answered"
			resp["verdict"] = verdict
		case mode == apiprovider.ModeCacheOnly:
			resp["lookup"] = "queued"
			resp["note"] = "cache-only mode never waits: a lookup has been queued and its answer will be on file for the next preview"
		default:
			resp["lookup"] = "no_answer"
			resp["note"] = "no provider answered within the configured budget; the lookup continues in the background"
		}
	}
	// Enrichment has its own explicit enablement, independent of whether
	// reputation can affect policy. Return the actual number queued; a full
	// queue or no eligible providers must not be reported as successful work.
	queued := a.Providers.EnrichForPolicy(domain, policyID)
	resp["enrichmentQueued"] = queued
	resp["enrichmentEnabled"] = a.Providers.EnrichmentEnabled()
	writeJSON(w, http.StatusOK, resp)
}

// domainActivity builds the activity section for a name.
func (a *API) domainActivity(ctx context.Context, domain, client string, since time.Time, win investigationWindow) (investigationActivity, error) {
	act := investigationActivity{
		Source:      "query_log",
		Available:   win.QueryLog,
		RecentLimit: investigateRecentLimit,
		Recent:      []queryRow{},
		Note:        "exact name only, as recorded by this resolver; subdomains and other spellings are separate names",
	}
	if !win.QueryLog {
		act.Unavailable = "the query log is off (log.query_log), so no per-query rows exist; counts on the overview come from rollups"
		act.Summary = store.ActivitySummary{QTypes: map[string]int64{}}
		return act, nil
	}
	summary, err := a.Store.ActivitySummaryWindow(ctx, domain, client, since, win.To)
	if err != nil {
		return act, err
	}
	act.Summary = summary
	if win.ClientAttribution && client == "" {
		clients, err := a.Store.ClientsOfDomainWindow(ctx, domain, since, win.To, investigateListLimit)
		if err != nil {
			return act, err
		}
		act.Clients = clients
	}
	events, next, err := a.Store.ListQueries(ctx, store.QueryFilter{
		ExactDomain: domain, ClientIP: client, Since: since, Until: win.To, Limit: investigateRecentLimit,
	})
	if err != nil {
		return act, err
	}
	act.Recent = a.withDNSSECObservations(ctx, events)
	act.RecentCursor = next
	return act, nil
}

// clientActivity builds the activity section for an address.
func (a *API) clientActivity(ctx context.Context, client string, since time.Time, win investigationWindow) (investigationActivity, error) {
	act := investigationActivity{
		Source:      "query_log",
		Available:   win.ClientAttribution,
		RecentLimit: investigateRecentLimit,
		Recent:      []queryRow{},
		Summary:     store.ActivitySummary{QTypes: map[string]int64{}},
		Note:        "rows recorded with this exact address; nothing is inferred about the device behind it",
	}
	switch {
	case !win.QueryLog:
		act.Unavailable = "the query log is off (log.query_log), so no per-query rows exist"
		return act, nil
	case !win.ClientAttribution:
		// Deliberately not "search the rows anyway": with attribution off
		// the rows carry no address, and any other route to a device's
		// history would be reconstructing what the operator chose not to
		// record.
		act.Unavailable = "client addresses are not recorded (log.log_client_ip), so no activity can be attributed to this address"
		return act, nil
	}
	summary, err := a.Store.ActivitySummaryWindow(ctx, "", client, since, win.To)
	if err != nil {
		return act, err
	}
	act.Summary = summary
	domains, err := a.Store.DomainsOfClientSince(ctx, client, since, investigateRecentLimit)
	if err != nil {
		return act, err
	}
	act.Domains = domains
	events, next, err := a.Store.ListQueries(ctx, store.QueryFilter{
		ClientIP: client, Since: since, Until: win.To, Limit: investigateRecentLimit,
	})
	if err != nil {
		return act, err
	}
	act.Recent = a.withDNSSECObservations(ctx, events)
	act.RecentCursor = next
	return act, nil
}

// decisionsFor lists stored decisions for a filter, as they were written.
func (a *API) decisionsFor(ctx context.Context, f store.DecisionFilter) (investigationDecisions, error) {
	f.Limit = investigateListLimit
	rows, next, err := a.Store.ListDecisionsPage(ctx, f)
	if err != nil {
		return investigationDecisions{}, err
	}
	d := investigationDecisions{
		Recording: a.Decisions != nil,
		Items:     rows,
		Truncated: next != "", NextCursor: next,
		Note: "original recorded decisions within this window; follow nextCursor through /api/v1/decisions with the same domain, client, since and until. " +
			"Evidence detail identifies captured snapshots or legacy current references; decisions are never re-derived from today's policy or feeds",
	}
	if d.Items == nil {
		d.Items = []store.Decision{}
	}
	return d, nil
}

// previewPolicyID decides which policy a preview for the given client (or
// no client) is evaluated under, without side effects.
func (a *API) previewPolicyID(client string) string {
	if client != "" {
		if addr, err := netip.ParseAddr(client); err == nil {
			return a.Engine.MatchClient(addr).PolicyID
		}
	}
	// No client: the catch-all, which is what an unmatched client gets.
	m := a.Engine.MatchClient(netip.Addr{})
	return m.PolicyID
}

// attributionKind words how a match was reached.
func attributionKind(m policy.Match) string {
	switch {
	case m.NetworkID == "":
		return "none"
	case m.NetworkID == "n_default":
		return "catch_all"
	default:
		return "network_prefix"
	}
}

// policyPreview evaluates a name under the current configuration.
func (a *API) policyPreview(ctx context.Context, domain, client string) (investigationPreview, error) {
	pv := investigationPreview{
		ReadOnly: true,
		Note: "what the current configuration would decide now; not what happened. " +
			"Evaluated by the compiled policy engine without DNS resolution or external provider calls. " +
			"Native DNSSEC validation and answer-dependent rebinding checks are not evaluated here; an allowed policy preview does not guarantee that resolution will succeed",
	}

	var match policy.Match
	if client != "" {
		addr, _ := netip.ParseAddr(client)
		match = a.Engine.MatchClient(addr)
		pv.Context = previewContext{Client: client, Attribution: attributionKind(match)}
	} else {
		match = a.Engine.MatchClient(netip.Addr{})
		pv.Context = previewContext{Attribution: "catch_all"}
	}
	pv.Context.NetworkID, pv.Context.NetworkName = match.NetworkID, match.NetworkName
	pv.Context.PolicyID, pv.Context.PolicyName = match.PolicyID, match.PolicyName

	result := a.Engine.Preview(match.PolicyID, domain)
	pv.Context.PolicyID, pv.Context.PolicyName = result.PolicyID, result.PolicyName
	pv.Decision, pv.External = a.previewOutcome(result)

	policies, err := a.Store.ListPolicies(ctx)
	if err != nil {
		return pv, err
	}
	networks, err := a.Store.ListNetworks(ctx)
	if err != nil {
		return pv, err
	}
	assigned := map[string]int{}
	for _, n := range networks {
		if n.Enabled {
			assigned[n.PolicyID]++
		}
	}
	pv.ByPolicy = make([]previewByPolicy, 0, len(policies))
	for _, p := range policies {
		res := a.Engine.Preview(p.ID, domain)
		dec, _ := a.previewOutcome(res)
		pv.ByPolicy = append(pv.ByPolicy, previewByPolicy{
			PolicyID: p.ID, PolicyName: p.Name, Networks: assigned[p.ID], Decision: dec,
		})
	}
	return pv, nil
}

// previewOutcome words an engine preview. The one rule: when the live
// outcome would depend on a lookup the preview did not perform, the outcome
// is "not_evaluated", never "allowed".
func (a *API) previewOutcome(res policy.Preview) (previewDecision, previewExternal) {
	d := res.Decision
	dec := previewDecision{
		Reason: d.Reason, Category: d.Category, Source: d.Source, BlockMode: string(d.BlockMode),
	}
	if d.Basis != nil {
		dec.Rule = string(d.Basis.Rule)
	}
	ext := previewExternal{
		Configured: res.External.Configured,
		Reached:    res.External.Reached,
		Evaluated:  res.External.Evaluated,
		FromCache:  res.External.Evaluated,
		Provider:   res.External.ProviderName,
	}
	if a.Providers != nil {
		ext.Mode = string(a.Providers.Mode())
	}

	switch {
	case d.Blocked:
		dec.Outcome = "blocked"
	case !res.External.Configured:
		dec.Outcome = "allowed"
		ext.Note = "no external provider is configured; local rules decide"
	case !res.External.Reached:
		dec.Outcome = "allowed"
		ext.Note = "decided by a local rule before any provider would be asked"
	case res.External.State == policy.CacheNoProvider:
		dec.Outcome = "allowed"
		ext.Note = "no external provider applies to this policy, or reputation mode is off"
	case res.External.Evaluated:
		dec.Outcome = "allowed"
		ext.Note = "the provider's cached verdict was consulted and did not block"
	default:
		// The live path would ask a provider here. This preview did not.
		dec.Outcome = "not_evaluated"
		dec.Reason = "not evaluated: an external provider would be consulted and no cached verdict exists; provider lookup not performed"
		ext.Note = "provider lookup not performed; use Enrich to request one within the configured budget"
	}
	return dec, ext
}

// evidenceFor assembles what is on file now for a name.
func (a *API) evidenceFor(ctx context.Context, domain string, now time.Time) (investigationEvidence, error) {
	subject := evidence.Domain(domain)
	all, err := a.Store.EvidenceFor(ctx, subject)
	if err != nil {
		return investigationEvidence{}, err
	}
	ids := make([]string, 0, len(all))
	for _, e := range all {
		ids = append(ids, e.ID)
	}
	contributions, err := a.Store.EvidenceContributions(ctx, ids)
	if err != nil {
		return investigationEvidence{}, err
	}
	out := investigationEvidence{
		Assessment: evidence.Assess(subject, all, now),
		Items:      make([]evidenceItem, 0, len(all)),
		Note: "what sources currently assert, with when each claim was observed and whether it ever decided a recorded query; " +
			"expired claims are shown and excluded from the assessment",
	}
	for _, e := range all {
		out.Items = append(out.Items, evidenceItem{
			Evidence:      e,
			Expired:       e.Expired(now),
			ContributedTo: contributions[e.ID],
		})
	}
	return out, nil
}

// findingsForDomain lists findings about a name or any of its parents.
func (a *API) findingsForDomain(ctx context.Context, domain, client string, since, until time.Time) (investigationFindings, error) {
	var names []string
	domainutil.Suffixes(domain, func(s string) bool {
		if strings.Contains(s, ".") {
			names = append(names, s)
		}
		return false
	})
	// The exact name too, even when it has no dot: a finding can name a
	// bare label.
	if len(names) == 0 || names[0] != domain {
		names = append([]string{domain}, names...)
	}
	rows, truncated, err := a.Store.FindingsForDomains(ctx, names, client, since, until, investigateListLimit)
	if err != nil {
		return investigationFindings{}, err
	}
	out := a.findingsSection(rows, truncated)
	out.Items, err = a.withReviews(ctx, out.Items)
	return out, err
}

// findingsForClient lists findings attributed to an address.
func (a *API) findingsForClient(ctx context.Context, client string, since, until time.Time) (investigationFindings, error) {
	rows, next, err := a.Store.ListFindings(ctx, store.FindingFilter{
		ClientIP: client, Since: since, Until: until, Limit: investigateListLimit,
	})
	if err != nil {
		return investigationFindings{}, err
	}
	out := a.findingsSection(rows, next != "")
	out.Items, err = a.withReviews(ctx, out.Items)
	return out, err
}

func (a *API) findingsSection(rows []store.Finding, truncated bool) investigationFindings {
	out := investigationFindings{
		Enabled:      a.Detector != nil || a.Learning != nil,
		Enforcement:  "none",
		Experimental: true,
		Items:        make([]findingResponse, 0, len(rows)),
		Truncated:    truncated,
		Note: "behavioural inferences from experimental detectors; they block nothing, " +
			"and their absence is not evidence that a device is clean",
	}
	for _, f := range rows {
		out.Items = append(out.Items, toFindingResponse(f, true))
	}
	return out
}

// observationsFor lists Daddybound's local verdicts for a name.
func (a *API) observationsFor(ctx context.Context, domain, client string, since, until time.Time) (investigationObservations, error) {
	state := a.dnssecState()
	out := investigationObservations{
		Mode:         state.Effective,
		Available:    state.Observer != nil || state.NativeAvailable,
		Active:       (state.Effective == config.LocalDNSSECObserve && state.ObserverActive) || (state.Effective == config.LocalDNSSECEnforce && state.NativeAvailable),
		Enforcing:    state.Effective == config.LocalDNSSECEnforce && state.NativeAvailable,
		Experimental: true,
		Items:        []store.DNSSECObservation{},
		Note: "retained local DNSSEC verdicts; current mode does not describe historical rows. " +
			"Learn observations changed nothing a client received; native_live rows come from the serving path. " +
			"Use recorded query source and original decisions for the client outcome. Client-scoped rows require retained query-log correlation",
	}
	rows, err := a.Store.ListDNSSECObservations(ctx, store.DNSSECObservationFilter{
		Domain: domain, ClientIP: client, Since: since, Until: until, Limit: investigateListLimit + 1,
	})
	if err != nil {
		return out, err
	}
	if len(rows) > investigateListLimit {
		rows = rows[:investigateListLimit]
		out.Truncated = true
	}
	out.Items = rows
	// A retained result remains inspectable after the runtime is turned off.
	// Available describes whether this section can report data; Active and
	// Mode describe current execution, independently of historical rows.
	out.Available = out.Available || len(rows) > 0
	return out, nil
}
