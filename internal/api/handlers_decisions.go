package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/evidence"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// This file serves the "why was this blocked?" read path.
//
// Everything here reads. There is no route that creates, edits or deletes a
// decision, and that is the point: a decision record is what the resolver did,
// and a management API that could rewrite it would make it worthless as
// evidence. The only write anywhere near this data is the recorder's, on the
// resolver side, and the only removal is retention.

// handleListDecisions returns recent decisions, newest first.
func (a *API) handleListDecisions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))

	rows, err := a.Store.ListDecisions(r.Context(), store.DecisionFilter{
		Subject:  strings.TrimSpace(q.Get("domain")),
		ClientIP: strings.TrimSpace(q.Get("client")),
		Action:   strings.TrimSpace(q.Get("action")),
		Limit:    limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	body := map[string]any{
		"decisions": rows,
		// Whether the feature is on at all, so a dashboard can tell "nothing
		// has been blocked" from "nothing is being recorded". Those look
		// identical in an empty list and mean opposite things.
		"recording": a.Decisions != nil,
	}
	if a.Decisions != nil {
		body["stats"] = a.Decisions.Stats()
	}
	writeJSON(w, http.StatusOK, body)
}

// handleGetDecision returns one decision with the evidence it cited.
//
// The evidence comes back by the IDs the decision recorded, not by re-reading
// what is currently known about the domain. A feed that has since dropped the
// name must not be able to change why it was blocked last week — that is the
// difference between an explanation and a guess.
func (a *API) handleGetDecision(w http.ResponseWriter, r *http.Request) {
	d, err := a.Store.DecisionWithEvidence(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// handleDomainEvidence returns everything on file about a domain, with the
// assessment it currently supports.
//
// Separate from the decision detail on purpose. A decision says what was true
// when it was made; this says what is true now. Showing them as one thing
// would quietly merge two different questions, and the answer to "why was this
// blocked" must not drift because a feed refreshed.
func (a *API) handleDomainEvidence(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.PathValue("domain"))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "a domain is required")
		return
	}
	subject := evidence.Domain(domain)

	all, err := a.Store.EvidenceFor(r.Context(), subject)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	decisionRows, err := a.Store.ListDecisions(r.Context(), store.DecisionFilter{
		Subject: domain, Limit: 20,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"subject":    subject,
		"assessment": evidence.Assess(subject, all, timeNow()),
		// Everything on file, expired rows included, because "this was listed
		// until Tuesday" is a useful thing for an investigator to see and the
		// assessment above has already excluded it from the verdict.
		"evidence":  all,
		"decisions": decisionRows,
	})
}
