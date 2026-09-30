package api

import (
	"net/http"
	"path/filepath"
	"sort"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/trustanchors"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// The Daddybound status surface: what the runtime already holds about the
// native resolver, the trust-anchor manager and the observer, reported as a
// bounded snapshot.
//
// Every read here is of a value that already exists — an atomic counter, a
// copy of the trust point under its lock, a handful of rollup rows. Nothing
// in this file resolves a name, refreshes an anchor or touches the trust
// state; polling it changes nothing. The one property that governs the
// wording: it says what was measured and says when the measurement is not
// enough, and it never turns a count into a readiness score.

// DNSSECAnchors is the reporting half of the trust-anchor manager.
//
// An interface so a test can supply a trust point in any state, and nil when
// local validation is off — there is no manager then, and the status says so
// rather than inventing an "ok".
type DNSSECAnchors interface {
	TrustPoint() trustanchors.TrustPoint
	Viable() bool
	Health() trustanchors.Health
}

// dnssecStatus is the response.
type dnssecStatus struct {
	Transport    string                 `json:"transport"`
	Mode         dnssecModeStatus       `json:"mode"`
	Resolution   dnssecResolutionStatus `json:"resolution"`
	Anchors      dnssecAnchorStatus     `json:"anchors"`
	Runtime      dnssecRuntimeStatus    `json:"runtime"`
	Stored       dnssecStoredStatus     `json:"stored"`
	Populations  []dnssecPopulation     `json:"populations"`
	Evidence     dnssecEvidenceStatus   `json:"evidence"`
	Experimental bool                   `json:"experimental"`
	Enforcing    bool                   `json:"enforcing"`
	MeasuredAt   time.Time              `json:"measuredAt"`
	Native       dnssecNativeStatus     `json:"native"`
}

type dnssecNativeStatus struct {
	native.ClientStats
	Available    bool   `json:"available"`
	Enforcing    bool   `json:"enforcing"`
	Peak         int64  `json:"peak"`
	CounterScope string `json:"counterScope"`
	Stored       uint64 `json:"stored"`
	Unrecorded   uint64 `json:"unrecorded"`
	WriteErrors  uint64 `json:"writeErrors"`
}

type dnssecModeStatus struct {
	// Configured is what dns.local_dnssec_validation says, or "unset".
	Configured string `json:"configured"`
	// Effective is what is running: off or observe.
	Effective string `json:"effective"`
	// ChosenBy is "config" when the operator set the mode, or
	// "installation_default" when the installation record decided.
	ChosenBy     string `json:"chosenBy"`
	Experimental bool   `json:"experimental"`
	Enforcing    bool   `json:"enforcing"`
	Locked       bool   `json:"locked"`
	Reason       string `json:"reason,omitempty"`
	Live         struct {
		Available bool   `json:"available"`
		Enforcing bool   `json:"enforcing"`
		Reason    string `json:"reason"`
	} `json:"live"`
}

type dnssecResolutionStatus struct {
	// Source is how Daddybound obtains the records it validates: "native"
	// (from the root to the authoritative servers, itself), "forwarded"
	// (through the operator's upstreams) or "none" when off.
	Source string `json:"source"`
	// Transport describes the auxiliary traffic Learn sends, in plain words.
	Transport string `json:"transport"`
	// ClientPath is how clients' answers are actually produced, which is a
	// separate path and stays so.
	ClientPath string `json:"clientPath"`
	Note       string `json:"note"`
}

type dnssecAnchorStatus struct {
	Available   bool   `json:"available"`
	Unavailable string `json:"unavailable,omitempty"`
	Zone        string `json:"zone,omitempty"`
	// Viable reports the trust point has at least one usable anchor. False
	// means nothing can be authenticated until an operator supplies one.
	Viable            bool   `json:"viable"`
	NeedsIntervention bool   `json:"needsIntervention"`
	InterventionNote  string `json:"interventionNote,omitempty"`
	// TrustedKeys is how many keys currently act as anchors, and Keys lists
	// every managed key with its lifecycle state. Key material is not
	// included: the tag, algorithm and flags identify a key to an operator
	// comparing against IANA's published set, and the file on disk holds
	// the rest.
	TrustedKeys int               `json:"trustedKeys"`
	Keys        []dnssecAnchorKey `json:"keys"`
	// Refresh is the RFC 5011 refresh schedule and its last outcomes.
	Refresh struct {
		LastAttempt *time.Time `json:"lastAttempt"`
		LastSuccess *time.Time `json:"lastSuccess"`
		LastError   string     `json:"lastError,omitempty"`
		Next        *time.Time `json:"next"`
	} `json:"refresh"`
	// Persistence is whether what the resolver has learned survives a
	// restart. Independent of whether the anchors in force work.
	Persistence struct {
		State         string     `json:"state"`
		File          string     `json:"file"`
		Seeded        bool       `json:"seeded"`
		LoadError     string     `json:"loadError,omitempty"`
		LastSaveError string     `json:"lastSaveError,omitempty"`
		Saves         uint64     `json:"saves"`
		SaveErrors    uint64     `json:"saveErrors"`
		LastSaveAt    *time.Time `json:"lastSaveAt"`
	} `json:"persistence"`
}

type dnssecAnchorKey struct {
	KeyTag    uint16     `json:"keyTag"`
	Algorithm uint8      `json:"algorithm"`
	Flags     uint16     `json:"flags"`
	State     string     `json:"state"`
	Trusted   bool       `json:"trusted"`
	Seeded    bool       `json:"seeded"`
	FirstSeen *time.Time `json:"firstSeen"`
	LastSeen  *time.Time `json:"lastSeen"`
	// AddHoldDownUntil, RevokedAt and RemoveHoldDownUntil are the RFC 5011
	// timers, present only when they apply.
	AddHoldDownUntil    *time.Time `json:"addHoldDownUntil,omitempty"`
	RevokedAt           *time.Time `json:"revokedAt,omitempty"`
	RemoveHoldDownUntil *time.Time `json:"removeHoldDownUntil,omitempty"`
}

type dnssecRuntimeStatus struct {
	Available     bool   `json:"available"`
	Active        bool   `json:"active"`
	Scope         string `json:"scope"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	// Observed is completed validations; Dropped is queries never observed
	// because the queue was full or the observer stopped; Unrecorded is observations that completed
	// and were then lost before storage. All three are reported because a
	// dataset smaller than the traffic has one of those two causes.
	Observed    uint64            `json:"observed"`
	Dropped     uint64            `json:"dropped"`
	Stored      uint64            `json:"stored"`
	Unrecorded  uint64            `json:"unrecorded"`
	WriteErrors uint64            `json:"writeErrors"`
	Panics      uint64            `json:"panics"`
	SeamPanics  uint64            `json:"seamPanics"`
	ByStatus    map[string]uint64 `json:"byStatus"`
	// Timeouts and Unreachable are pulled out of ByStatus because they are
	// the operational figures #67 asks for by name.
	Timeouts      uint64            `json:"timeouts"`
	ResourceLimit uint64            `json:"resourceLimit"`
	Unreachable   uint64            `json:"unreachable"`
	Disagreements map[string]uint64 `json:"disagreements"`
	Resolution    string            `json:"resolution,omitempty"`
	Queries       uint64            `json:"queries"`
	Delegations   uint64            `json:"delegations"`
	LastAt        *time.Time        `json:"lastAt"`
	LastStatus    string            `json:"lastStatus,omitempty"`
	// Health is "ok", "inactive", "degraded" or "unavailable", from the counters above
	// and nothing else: dropped or unrecorded observations, write errors
	// or any panic make it degraded.
	Health     string `json:"health"`
	HealthNote string `json:"healthNote,omitempty"`
}

type dnssecStoredStatus struct {
	WindowHours   int              `json:"windowHours"`
	Total         int64            `json:"total"`
	ByStatus      map[string]int64 `json:"byStatus"`
	Disagreements map[string]int64 `json:"disagreements"`
	// ObservingSince and ObservedUntil bound every stored row, whatever the
	// window; RetainedRows is how many there are.
	ObservingSince *time.Time `json:"observingSince"`
	ObservedUntil  *time.Time `json:"observedUntil"`
	RetainedRows   int64      `json:"retainedRows"`
	RetentionDays  int        `json:"retentionDays"`
}

// dnssecPopulation is one comparable-or-not population of stored
// observations in the window.
type dnssecPopulation struct {
	Resolution string `json:"resolution"`
	Cached     bool   `json:"cached"`
	// Comparable reports that both sides made a claim that can agree or
	// disagree: a security-state verdict against an upstream that asserted
	// validated or unvalidated. Operational outcomes and upstream failures
	// are not comparable with anything.
	Comparable    bool             `json:"comparable"`
	Total         int64            `json:"total"`
	Disagreements map[string]int64 `json:"disagreements"`
	Note          string           `json:"note"`
}

type dnssecEvidenceStatus struct {
	// Sufficient is false in this release, and there is no threshold in
	// this code that could make it true: the criteria are the subject of
	// the linked issues and have not been quantified. Reported so that no
	// consumer can mistake the counts above for a readiness verdict.
	Sufficient bool              `json:"sufficient"`
	Note       string            `json:"note"`
	Criteria   []dnssecCriterion `json:"criteria"`
	Issues     []string          `json:"issues"`
}

type dnssecCriterion struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Measured string `json:"measured"`
	// Status is "not_quantified" for every criterion in this release: a
	// measurement is reported, and no threshold is applied to it.
	Status string `json:"status"`
}

const (
	issueCorpus    = "https://github.com/jameshoulder/dnsdaddy/issues/65"
	issueReadiness = "https://github.com/jameshoulder/dnsdaddy/issues/67"
)

// handleDNSSECStatus reports the Daddybound runtime as a bounded snapshot.
//
// GET /api/v1/dnssec/status?hours=
func (a *API) handleDNSSECStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().UTC()
	hours := intParam(r, "hours", 24*7)
	if hours <= 0 || hours > 24*90 {
		hours = 24 * 7
	}
	since := now.Add(-time.Duration(hours) * time.Hour)

	out := dnssecStatus{Experimental: true, Enforcing: false, MeasuredAt: now}
	state := a.dnssecState()
	out.Transport = state.Transport
	if out.Transport == "" {
		out.Transport = config.ResolutionNative
	}
	out.Mode = a.dnssecModeStatus(state)
	out.Enforcing = out.Mode.Enforcing
	out.Resolution = a.dnssecResolutionStatus(state)
	out.Anchors = a.dnssecAnchorStatus(state)
	out.Runtime = a.dnssecRuntimeStatus(now, state)
	out.Native = dnssecNativeStatus{ClientStats: state.Native, Available: state.NativeAvailable,
		Enforcing: out.Enforcing, Peak: state.Native.InflightPeak, CounterScope: "local validation counters since activation; stored/lost/write counters since process start",
		Stored: state.NativeWriter.Written, Unrecorded: state.NativeWriter.Dropped, WriteErrors: state.NativeWriter.Errors}

	summary, err := a.Store.DNSSECObservationSummarySince(ctx, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	first, last, retained, err := a.Store.DNSSECObservationSpan(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cells, err := a.Store.DNSSECPopulationsSince(ctx, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	retention := a.Config.Log.RetentionDays
	if retention <= 0 {
		retention = store.DefaultRetentionDays
	}
	out.Stored = dnssecStoredStatus{
		WindowHours: hours, Total: summary.Total,
		ByStatus: summary.ByStatus, Disagreements: summary.Disagreements,
		RetainedRows: retained, RetentionDays: retention,
	}
	for _, s := range observe.Statuses() {
		if _, ok := out.Stored.ByStatus[string(s)]; !ok {
			out.Stored.ByStatus[string(s)] = 0
		}
	}
	for _, c := range observe.DisagreementClasses() {
		if _, ok := out.Stored.Disagreements[c]; !ok {
			out.Stored.Disagreements[c] = 0
		}
	}
	if retained > 0 {
		out.Stored.ObservingSince, out.Stored.ObservedUntil = &first, &last
	}
	out.Populations = dnssecPopulations(cells)
	out.Evidence = a.dnssecEvidence(out)

	writeJSON(w, http.StatusOK, out)
}

func (a *API) selectedDNSSECState(states []DNSSECRuntimeState) DNSSECRuntimeState {
	if len(states) > 0 {
		return states[0]
	}
	return a.dnssecState()
}

func (a *API) dnssecModeStatus(states ...DNSSECRuntimeState) dnssecModeStatus {
	state := a.selectedDNSSECState(states)
	var m dnssecModeStatus
	m.Configured, m.Effective, m.ChosenBy = state.Configured, state.Effective, state.ChosenBy
	m.Experimental = true
	m.Locked, m.Reason = state.Locked, state.Reason
	m.Enforcing = state.Effective == config.LocalDNSSECEnforce && state.NativeAvailable
	m.Live.Available = a.DNSSECControl != nil
	m.Live.Enforcing = m.Enforcing
	if m.Live.Available {
		m.Live.Reason = "Daddybound resolves and validates the exact answer natively. Live rejects failed validation and never falls back to an upstream. Native UDP/TCP 53 is plaintext; field reliability remains under evaluation."
		if state.Transport == config.ResolutionEncrypted {
			m.Live.Reason = "Daddybound validates the exact answer obtained from approved encrypted resolvers. Live rejects failed validation; DNS traffic uses authenticated TLS 1.3 with no plaintext fallback. Field reliability remains under evaluation."
		}
	} else {
		m.Live.Reason = "Native runtime control is unavailable in this process."
	}
	return m
}

func (a *API) dnssecResolutionStatus(states ...DNSSECRuntimeState) dnssecResolutionStatus {
	state := a.selectedDNSSECState(states)
	res := dnssecResolutionStatus{ClientPath: "clients are answered by the forwarding resolver through the configured upstreams (" + a.Config.DNS.UpstreamMode + ")"}
	if state.Transport == config.ResolutionEncrypted {
		res.Source = "encrypted_forwarded"
		res.Transport = "authenticated TLS 1.3 via approved DoQ, DoH over HTTP/3 or DoH over HTTP/2 endpoints; literal-IP bootstrap; no plaintext fallback"
		res.ClientPath = "approved encrypted resolvers with ordered encrypted-only failover"
		switch state.Effective {
		case config.LocalDNSSECEnforce:
			res.ClientPath = "Daddybound locally validates the exact answer received through approved encrypted resolvers"
			res.Note = "Live accepts locally authenticated secure or proven insecure answers. Bogus, indeterminate and operational failures return SERVFAIL. CD disables DNSSEC checking only; local policy and rebinding protection still apply. The resolver provider can see forwarded names."
		case config.LocalDNSSECObserve:
			res.Note = "Learn observes independently through the same encrypted endpoints after the client answer is decided. Supporting DNSSEC queries and trust-anchor refresh remain encrypted. Observations cannot change the answer."
		default:
			res.Source = "none"
			res.Note = "Forward mode answers through the approved encrypted endpoints. Daddybound validation and trust-anchor refresh are off; local policy, rate limiting and rebinding protection remain active. Background hostname lookups use the same encrypted endpoints."
		}
		return res
	}
	if state.Effective == config.LocalDNSSECOff {
		res.Source = "none"
		res.Transport = "configured forwarding upstreams; no direct queries to root or authoritative servers"
		res.Note = "Forward mode answers through the configured upstreams and keeps caching, local policy, rate limiting and rebinding protection active. Daddybound does not perform local validation or trust-anchor refresh in this mode."
		return res
	}
	res.Source = observe.ResolutionNative
	res.Transport = "plaintext DNS over UDP and TCP port 53 to root and authoritative servers, with QNAME minimisation; this traffic is not protected by configured encrypted upstreams"
	if state.Effective == config.LocalDNSSECEnforce {
		res.ClientPath = "Daddybound native recursion; DNSSEC validation is bound to the returned records; no upstream fallback"
		res.Note = "Live returns authenticated secure or proven insecure answers. Bogus, indeterminate and operational failures return SERVFAIL. A client's CD bit bypasses DNSSEC validation only; policy and rebinding checks still apply."
	} else {
		res.Note = "Learn resolves allowed queries independently after the forwarded answer is decided. Its result cannot change that answer and may describe different records."
		if state.Observer != nil && state.Observer.Stats().Resolution == observe.ResolutionForwarded {
			res.Source = observe.ResolutionForwarded
			res.Transport = "supporting lookups through configured upstreams"
		}
	}
	return res
}

func (a *API) dnssecAnchorStatus(states ...DNSSECRuntimeState) dnssecAnchorStatus {
	runtime := a.selectedDNSSECState(states)
	var st dnssecAnchorStatus
	st.Keys = []dnssecAnchorKey{}
	if runtime.Anchors == nil {
		st.Unavailable = "no trust-anchor manager is running: Daddybound is off"
		if runtime.Effective != config.LocalDNSSECOff {
			st.Unavailable = "the trust-anchor manager is not reporting"
		}
		return st
	}
	tp := runtime.Anchors.TrustPoint()
	health := runtime.Anchors.Health()
	st.Available = true
	st.Zone = tp.Zone
	st.Viable = runtime.Anchors.Viable()
	st.NeedsIntervention = tp.NeedsIntervention
	st.InterventionNote = tp.InterventionNote
	for _, k := range tp.Keys {
		key := dnssecAnchorKey{
			KeyTag: k.KeyTag, Algorithm: k.Algorithm, Flags: k.Flags,
			State: string(k.State), Trusted: k.State.Trusted(), Seeded: k.Seeded,
			FirstSeen: optTime(k.FirstSeen), LastSeen: optTime(k.LastSeen),
			AddHoldDownUntil: optTime(k.AddHoldDownUntil), RevokedAt: optTime(k.RevokedAt),
			RemoveHoldDownUntil: optTime(k.RemoveHoldDownUntil),
		}
		if key.Trusted {
			st.TrustedKeys++
		}
		st.Keys = append(st.Keys, key)
	}
	sort.SliceStable(st.Keys, func(i, j int) bool { return st.Keys[i].KeyTag < st.Keys[j].KeyTag })
	st.Refresh.LastAttempt = optTime(tp.LastRefresh)
	st.Refresh.LastSuccess = optTime(tp.LastSuccess)
	st.Refresh.LastError = tp.LastError
	st.Refresh.Next = optTime(tp.NextRefresh)

	// The file name only. The data directory is the operator's own
	// configuration and is reported on the Settings page; repeating the full
	// path in every status poll adds nothing an operator needs and is one
	// more place a host path would appear in a screenshot.
	st.Persistence.File = filepath.Base(a.Config.TrustAnchorStatePath())
	st.Persistence.Seeded = health.Seeded
	st.Persistence.LoadError = health.LoadError
	st.Persistence.LastSaveError = health.LastSaveError
	st.Persistence.Saves = health.Saves
	st.Persistence.SaveErrors = health.SaveErrors
	st.Persistence.LastSaveAt = optTime(health.LastSaveAt)
	switch {
	case health.LastSaveError != "":
		st.Persistence.State = "failing"
	case health.LoadError != "":
		st.Persistence.State = "load_failed"
	case health.Saves == 0:
		// Nothing has been written yet: on a fresh start that is the
		// ordinary state until the first refresh, and it is reported as
		// exactly that rather than as healthy.
		st.Persistence.State = "not_yet_written"
	default:
		st.Persistence.State = "ok"
	}
	return st
}

func (a *API) dnssecRuntimeStatus(now time.Time, states ...DNSSECRuntimeState) dnssecRuntimeStatus {
	runtime := a.selectedDNSSECState(states)
	rt := dnssecRuntimeStatus{
		Scope:         "since_current_learn_activation",
		Active:        runtime.ObserverActive,
		UptimeSeconds: int64(now.Sub(a.StartedAt).Seconds()),
		ByStatus:      map[string]uint64{},
		Disagreements: map[string]uint64{},
		Health:        "unavailable",
	}
	if a.DNSSECControl == nil {
		rt.Scope = "since_start"
	} else if !rt.Active {
		rt.Scope = "most_recent_learn_activation"
	}
	for _, s := range observe.Statuses() {
		rt.ByStatus[string(s)] = 0
	}
	for _, c := range observe.DisagreementClasses() {
		rt.Disagreements[c] = 0
	}
	if runtime.Observer == nil {
		rt.HealthNote = "no observer is running"
		if runtime.Effective == config.LocalDNSSECObserve {
			rt.HealthNote = "Learn is configured but the observer is not reporting"
		}
		return rt
	}
	s := runtime.Observer.Stats()
	rt.Available = true
	rt.Observed, rt.Dropped, rt.Panics = s.Observed, s.Dropped, s.Panics
	for k, v := range s.ByStatus {
		rt.ByStatus[string(k)] = v
	}
	for k, v := range s.Disagreements {
		rt.Disagreements[k] = v
	}
	rt.Timeouts = s.ByStatus[observe.StatusTimeout]
	rt.ResourceLimit = s.ByStatus[observe.StatusResourceLimit]
	rt.Unreachable = s.ByStatus[observe.StatusUnreachable]
	rt.Resolution = s.Resolution
	rt.Queries, rt.Delegations = s.Queries, s.Delegations
	rt.LastAt = optTime(s.LastAt)
	rt.LastStatus = string(s.LastStatus)
	if runtime.Writer != nil {
		w := runtime.Writer.Stats()
		rt.Stored, rt.Unrecorded, rt.WriteErrors = w.Written, w.Dropped, w.Errors
	}
	if a.DNS != nil {
		rt.SeamPanics = a.DNS.DNSSECObserverPanics()
	}

	switch {
	case rt.Panics > 0 || rt.SeamPanics > 0:
		rt.Health = "degraded"
		rt.HealthNote = "the validator panicked and was contained; that is a defect to report, not a property of the traffic"
	case rt.WriteErrors > 0:
		rt.Health = "degraded"
		rt.HealthNote = "some observation batches failed to write; the stored dataset is smaller than the observed one"
	case rt.Dropped > 0 || rt.Unrecorded > 0:
		rt.Health = "degraded"
		rt.HealthNote = "some queries were not observed or not stored; the sample is smaller than the traffic and biased towards quiet periods"
	default:
		rt.Health = "ok"
	}
	if a.DNSSECControl != nil && !rt.Active {
		if rt.Health == "ok" {
			rt.Health = "inactive"
		}
		rt.HealthNote = "Learn is stopped; these counters describe its most recent activation, including late and shutdown drops. " + rt.HealthNote
	}
	return rt
}

// dnssecPopulations groups the cross-tabulation into populations a reader
// can compare within, and says why each one may or may not be.
func dnssecPopulations(cells []store.DNSSECPopulationCell) []dnssecPopulation {
	type key struct {
		resolution string
		cached     bool
		comparable bool
	}
	groups := map[key]*dnssecPopulation{}
	for _, c := range cells {
		comparable := observe.Status(c.Status).IsSecurityState() &&
			(c.Upstream == store.DNSSECValidated || c.Upstream == store.DNSSECUnvalidated)
		resolution := c.Resolution
		if resolution == "" {
			resolution = "unrecorded"
		}
		k := key{resolution, c.Cached, comparable}
		g, ok := groups[k]
		if !ok {
			g = &dnssecPopulation{
				Resolution: resolution, Cached: c.Cached, Comparable: comparable,
				Disagreements: map[string]int64{},
			}
			for _, class := range observe.DisagreementClasses() {
				g.Disagreements[class] = 0
			}
			groups[k] = g
		}
		g.Total += c.Count
		if c.Disagreement != "" {
			g.Disagreements[c.Disagreement] += c.Count
		}
	}
	out := make([]dnssecPopulation, 0, len(groups))
	for _, g := range groups {
		switch {
		case g.Resolution == "native_live" || g.Resolution == "encrypted_live":
			g.Note = "the local validation result for the exact answer used by the serving path; there is no independent upstream comparison"
		case !g.Comparable:
			g.Note = "not comparable: an operational outcome, or an upstream that asserted nothing; " +
				"these rows cannot disagree with anything and are never counted as one"
		case g.Cached:
			g.Note = "the client's answer came from the cache and may predate this observation; " +
				"a disagreement here is not evidence that the answer the client received was forged"
		case g.Resolution == observe.ResolutionNative:
			g.Note = "resolved natively from the root and validated on the path Live would run; " +
				"each disagreement in local_bogus_upstream_validated is a case to investigate individually"
		default:
			g.Note = "validated on records an upstream handed over; evidence about that upstream's view, " +
				"not about native resolution"
		}
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Comparable != out[j].Comparable {
			return out[i].Comparable
		}
		if out[i].Cached != out[j].Cached {
			return !out[i].Cached
		}
		if out[i].Resolution != out[j].Resolution {
			return out[i].Resolution < out[j].Resolution
		}
		return out[i].Total > out[j].Total
	})
	return out
}

// dnssecEvidence restates the measurements against the criteria in #67,
// without applying a threshold to any of them.
func (a *API) dnssecEvidence(st dnssecStatus) dnssecEvidenceStatus {
	var comparableNative, bogusValidated int64
	for _, p := range st.Populations {
		if p.Comparable && !p.Cached && p.Resolution == observe.ResolutionNative {
			comparableNative += p.Total
			bogusValidated += p.Disagreements[observe.DisagreeLocalBogusUpstreamValidated]
		}
	}
	observingFor := "no stored observations"
	if st.Stored.ObservingSince != nil && st.Stored.ObservedUntil != nil {
		observingFor = st.Stored.ObservedUntil.Sub(*st.Stored.ObservingSince).Round(time.Minute).String() +
			" of retained observations, bounded by retention"
	}
	anchors := "no trust-anchor manager"
	if st.Anchors.Available {
		anchors = itoaInt(st.Anchors.TrustedKeys) + " trusted key(s); viable=" + boolWord(st.Anchors.Viable) +
			"; persistence " + st.Anchors.Persistence.State
		if st.Anchors.Refresh.LastSuccess == nil {
			anchors += "; no successful RFC 5011 refresh yet"
		}
	}
	criteria := []dnssecCriterion{
		{ID: "volume", Title: "Observation volume and duration", Status: "not_quantified",
			Measured: itoa64(st.Stored.Total) + " stored in the window, " + itoa64(st.Stored.RetainedRows) +
				" retained, " + observingFor + "; one instance, one upstream"},
		{ID: "disagreement", Title: "local_bogus_upstream_validated among comparable native observations", Status: "not_quantified",
			Measured: itoa64(bogusValidated) + " of " + itoa64(comparableNative) +
				" comparable native, non-cached observations in the window; no rate or interval is claimed"},
		{ID: "investigation", Title: "Each local-bogus-upstream-validated case investigated individually", Status: "not_quantified",
			Measured: "not tracked by this software; the investigation page shows each observation for a name"},
		{ID: "uptime", Title: "Continuous observation across calendar events", Status: "not_quantified",
			Measured: "process up " + (time.Duration(st.Runtime.UptimeSeconds) * time.Second).String() +
				"; retention keeps " + itoaInt(st.Stored.RetentionDays) + " day(s) of rows"},
		{ID: "timeouts", Title: "Timeout, resource-limit and unreachable outcomes", Status: "not_quantified",
			Measured: itoa64(st.Stored.ByStatus[string(observe.StatusTimeout)]) + " timeout, " +
				itoa64(st.Stored.ByStatus[string(observe.StatusResourceLimit)]) + " resource-limit, " +
				itoa64(st.Stored.ByStatus[string(observe.StatusUnreachable)]) + " unreachable in the window"},
		{ID: "anchors", Title: "Trust-anchor lifecycle", Status: "not_quantified", Measured: anchors},
		{ID: "resolution", Title: "Evidence gathered on the path Live would run", Status: "not_quantified",
			Measured: "resolution source " + st.Resolution.Source},
	}
	return dnssecEvidenceStatus{
		Sufficient: false,
		Note: "These counters provide insufficient field evidence to establish long-term deployment reliability or false-positive rates. " +
			"Live availability is an implemented capability, not proof of field readiness. Learn comparisons and exact native Live results are separate populations. " +
			"The software applies no threshold or readiness score to this sample; the corpus and field criteria remain in the linked issues.",
		Criteria: criteria,
		Issues:   []string{issueReadiness, issueCorpus},
	}
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func boolWord(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoaInt(n int) string { return itoa64(int64(n)) }

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [21]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
