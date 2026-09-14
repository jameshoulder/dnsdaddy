package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/evidence"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Completeness states the "why" endpoint can report.
const (
	// whyComplete: the record exists and cites everything it had.
	whyComplete = "complete"
	// whyTruncated: the record exists and had more evidence than it could cite.
	whyTruncated = "truncated"
	// whyMissing: there is no record. That covers three different situations
	// and the response says which, because "no reason available" would be
	// indistinguishable between a query nothing decided, a record lost under
	// load, and a query answered before this feature existed. An operator
	// investigating an incident needs to tell those apart.
	whyMissing = "missing"
)

// whyEvidence is one piece of evidence as the API renders it.
type whyEvidence struct {
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	SourceName string `json:"sourceName,omitempty"`
	Category   string `json:"category,omitempty"`
	Claim      string `json:"claim"`
	Confidence string `json:"confidence,omitempty"`
	ObservedAt string `json:"observedAt,omitempty"`
	// Role is caused, contributed or observed.
	//
	// An engine that only observes is always "observed" and can never be the
	// reason for anything. Clients must not present an observed item as a
	// cause; the field exists so they do not have to guess from the kind.
	Role string `json:"role"`

	// FirstListed is when the feed behind this evidence first listed the
	// domain, as recorded at the moment of the decision. Omitted when unknown.
	FirstListed string `json:"firstListed,omitempty"`
	// ExpiresAt is when the feed said the listing stops being current.
	// Omitted when the feed gave no expiry, which is every feed shipped today.
	ExpiresAt string `json:"expiresAt,omitempty"`
	// ListingState is "dated" when the dates below are known and "unknown"
	// when they are not.
	//
	// A separate field rather than leaving a client to infer it from empty
	// strings, because the two readings are opposite: a missing date here
	// means nobody recorded one, never that the domain was listed at the epoch
	// or that the listing is brand new.
	ListingState string `json:"listingState"`
}

// Listing states reported on a piece of evidence.
const (
	// listingDated: the record carries the dates the feed's claim had.
	listingDated = "dated"
	// listingUnknown: no dates were recorded. Either the block predates this
	// installation keeping them, or the evidence is not a feed listing at all
	// — an operator block-list entry has no first-seen in this sense.
	listingUnknown = "unknown"
)

// whyResponse explains one answered query.
type whyResponse struct {
	QueryID int64  `json:"queryId"`
	Domain  string `json:"domain"`
	QType   string `json:"qtype,omitempty"`
	Time    string `json:"time"`
	Action  string `json:"action"`

	// Completeness is complete, truncated or missing.
	Completeness string `json:"completeness"`
	// Explanation is the sentence written when the decision was made, not one
	// regenerated now.
	Explanation string `json:"explanation,omitempty"`
	// Reason is the query log's own flattened string. Kept because it is what
	// the activity view already shows, and deliberately not presented as the
	// whole answer: it is one sentence with no sources behind it.
	Reason string `json:"reason,omitempty"`

	Policy   *whyPolicy    `json:"policy,omitempty"`
	Evidence []whyEvidence `json:"evidence"`

	// Note explains a missing or truncated record in words.
	Note string `json:"note,omitempty"`
}

type whyPolicy struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}

// handleQueryWhy explains one query-log row from the record written at the
// time.
//
// It never re-runs the policy engine and never re-reads the feeds. A feed that
// dropped a domain this morning must not change why it was blocked last night,
// and the only way to guarantee that is to answer exclusively from what was
// stored. Everything here comes from the decision row and the evidence it
// cited; where that is absent, the response says so rather than assembling a
// plausible story from the current state of the world.
func (a *API) handleQueryWhy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "a numeric query id is required")
		return
	}

	q, err := a.Store.QueryByID(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	out := whyResponse{
		QueryID:  q.ID,
		Domain:   q.Domain,
		QType:    q.QType,
		Time:     q.Time.UTC().Format(time.RFC3339),
		Action:   q.Action,
		Reason:   q.Reason,
		Evidence: []whyEvidence{},
	}

	if q.DecisionID == "" {
		// No record was ever linked. Which of the two reasons applies is
		// answerable from the row: a query the resolver simply allowed
		// decided nothing, and one that was blocked must have decided
		// something — so a blocked row with no decision id lost its record or
		// predates the feature.
		out.Completeness = whyMissing
		if q.Action == store.ActionBlocked {
			out.Note = "No decision record is linked to this query. Either it was answered " +
				"before decision records were kept, or the record was dropped while the " +
				"resolver was under load. The reason above is the query log's own summary " +
				"and has no stored evidence behind it."
			a.whyMissing.Add(1)
		} else {
			out.Note = "Nothing decided this query: no rule matched and no engine had an " +
				"opinion, so it was answered normally. That is not a missing record — there " +
				"was nothing to record."
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	d, err := a.Store.DecisionWithEvidence(r.Context(), q.DecisionID)
	if errors.Is(err, store.ErrNotFound) {
		// The query log names a decision the decisions table does not hold.
		// The two are written by independent writers, so this is what a drop
		// between them looks like, and it is reported rather than smoothed
		// over.
		out.Completeness = whyMissing
		out.Note = "This query names a decision record that was not written — the record was " +
			"dropped under load after the query log row had already been queued. The reason " +
			"above is the query log's own summary and has no stored evidence behind it."
		a.whyMissing.Add(1)
		writeJSON(w, http.StatusOK, out)
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}

	out.Completeness = whyComplete
	if d.Completeness == store.TruncatedRecord {
		out.Completeness = whyTruncated
		out.Note = "This decision cited more evidence than a record holds. What is listed is " +
			"the evidence that mattered most — what caused the outcome first, then what it " +
			"overrode — and some observations were not kept."
	}
	out.Explanation = d.Explanation
	out.Action = d.Action
	if d.PolicyID != "" || d.PolicyPath != "" {
		out.Policy = &whyPolicy{ID: d.PolicyID, Path: d.PolicyPath}
	}
	for _, c := range d.Cited {
		item := whyEvidence{
			Kind:       string(c.Evidence.Kind),
			Source:     c.Evidence.Source,
			SourceName: c.Evidence.SourceName,
			Category:   c.Evidence.Category,
			Claim:      c.Evidence.Claim,
			Confidence: string(c.Evidence.Confidence),
			ObservedAt: c.Evidence.ObservedAt.UTC().Format(time.RFC3339),
			Role:       string(c.Role),
			// Unknown until something is actually known. An installation that
			// was blocking before it started keeping dates has none of them,
			// and the response has to say that rather than leave a client to
			// read an absent field as a fresh listing.
			ListingState: listingUnknown,
		}
		// Read off the stored record, never from the live index. This is the
		// whole point: the feeds move, and an explanation that re-read them
		// would quietly claim last night's block had a different basis.
		if c.Evidence.Kind == evidence.KindFeed && !c.Evidence.ObservedAt.IsZero() {
			item.FirstListed = c.Evidence.ObservedAt.UTC().Format(time.RFC3339)
			item.ListingState = listingDated
		}
		if c.Evidence.ExpiresAt != nil && !c.Evidence.ExpiresAt.IsZero() {
			item.ExpiresAt = c.Evidence.ExpiresAt.UTC().Format(time.RFC3339)
			item.ListingState = listingDated
		}
		out.Evidence = append(out.Evidence, item)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleListAudit returns recent configuration changes.
func (a *API) handleListAudit(w http.ResponseWriter, r *http.Request) {
	f := store.AuditFilter{
		Action:     r.URL.Query().Get("action"),
		TargetType: r.URL.Query().Get("target_type"),
		TargetID:   r.URL.Query().Get("target_id"),
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		f.Limit = n
	}

	entries, err := a.Store.ListAudit(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the audit log")
		return
	}
	stats := a.Audit.Stats()
	out := map[string]any{
		"entries": entries,
		// Surfaced on every response rather than buried in /metrics: an audit
		// log with holes in it is only trustworthy if the holes are visible,
		// and somebody reading this list is exactly the person who needs to
		// know that some entries never made it.
		"dropped": stats.Dropped,
		"written": stats.Written,
	}
	if total := stats.Dropped["full"] + stats.Dropped["failed"]; total > 0 {
		out["note"] = "Some audit entries were not written. The changes they described still " +
			"took effect; the record of them is incomplete."
	}
	writeJSON(w, http.StatusOK, out)
}
