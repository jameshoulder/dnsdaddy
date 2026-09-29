package api

import (
	"net/http"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/dnssecobs"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// handleDNSSECObservations reports what local validation has concluded.
//
// Deliberately its own endpoint rather than a widening of an existing one.
// Local DNSSEC observation is experimental and non-enforcing, and a consumer
// that has not opted into reading it should not have to learn about it to keep
// working.
func (a *API) handleDNSSECObservations(w http.ResponseWriter, r *http.Request) {
	hours := intParam(r, "hours", 24)
	if hours <= 0 || hours > 24*90 {
		hours = 24
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	summary, err := a.Store.DNSSECObservationSummarySince(r.Context(), since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// The list covers the same window as the summary, so the two describe
	// one population: a summary of the last day beside a list reaching back
	// a month would invite a reader to reconcile numbers that do not agree.
	// One extra row is fetched so the response can say whether the window
	// holds more than it shows.
	limit := intParam(r, "limit", 50)
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	recent, err := a.Store.ListDNSSECObservations(r.Context(), store.DNSSECObservationFilter{
		Status:            r.URL.Query().Get("status"),
		DisagreementsOnly: r.URL.Query().Get("disagreements") == "1",
		Since:             since,
		Limit:             limit + 1,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	recentTruncated := len(recent) > limit
	if recentTruncated {
		recent = recent[:limit]
	}

	// Every status and every disagreement class is present even at zero, so a
	// dashboard renders a stable set of rows and a reader can tell "none of
	// these happened" from "this build does not know about that outcome".
	for _, s := range observe.Statuses() {
		if _, ok := summary.ByStatus[string(s)]; !ok {
			summary.ByStatus[string(s)] = 0
		}
	}
	for _, c := range observe.DisagreementClasses() {
		if _, ok := summary.Disagreements[c]; !ok {
			summary.Disagreements[c] = 0
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"mode": a.dnssecState().Effective,
		// Stated in the payload rather than left to the reader, because every
		// number below is only meaningful alongside it. A dashboard, a script
		// or a person reading the JSON can distinguish auxiliary Learn
		// observations from exact-answer native_live decisions.
		"enforcing":    a.dnssecModeStatus().Enforcing,
		"experimental": true,
		"summary":      summary,
		"recent":       recent,
		"runtime":      a.dnssecRuntime(),
		"windowHours":  hours,
		// Two scopes, named. `summary` and `recent` are stored rows within
		// the window, and only rows the query-log settings allowed to be
		// stored. `runtime` is the current or most recent Learn activation's
		// counters, including observations that were lost or not retained. They
		// are different populations and neither is derivable from the other.
		"scope": map[string]any{
			"summary": "stored observations within the window",
			"recent":  "stored observations within the window, newest first",
			"runtime": "current or most recent Learn activation; active and scope describe whether it is still running",
			"window": map[string]any{
				"hours": hours,
				"from":  since.UTC(),
				"to":    time.Now().UTC(),
			},
			"recentLimit":     limit,
			"recentTruncated": recentTruncated,
		},
	})
}

// dnssecRuntime reports the health of the observer itself, as distinct from
// the health of DNS resolution.
//
// The two are separate on purpose. A validator dropping observations under
// load is a statement about the sample, not about whether clients are being
// answered — and an operator must be able to tell those apart at a glance.
func (a *API) dnssecRuntime() map[string]any {
	state := a.dnssecState()
	out := map[string]any{
		"available": state.Observer != nil,
		"active":    state.ObserverActive,
	}
	if state.Observer == nil {
		return out
	}
	s := state.Observer.Stats()
	out["scope"] = "since_start"
	if a.DNSSECControl != nil {
		out["scope"] = "most_recent_learn_activation"
		if state.ObserverActive {
			out["scope"] = "since_current_learn_activation"
		}
	}
	out["uptimeSeconds"] = int64(time.Since(a.StartedAt).Seconds())
	out["observed"] = s.Observed
	out["dropped"] = s.Dropped
	out["panics"] = s.Panics
	if !s.LastAt.IsZero() {
		out["lastAt"] = s.LastAt
		out["lastStatus"] = string(s.LastStatus)
	}
	if state.Writer != nil {
		w := state.Writer.Stats()
		out["stored"] = w.Written
		// Completed validations whose result never reached the database.
		// Reported beside "observed" so a smaller dataset than expected has
		// a visible cause rather than looking like quieter traffic.
		out["unrecorded"] = w.Dropped
		out["writeErrors"] = w.Errors
	}
	return out
}

// DNSSECWriterStats reports what became of completed observations.
//
// Separate from DNSSECObserverStats because they answer different questions:
// one is "how many queries did we look at", the other is "how many of those
// verdicts survived to storage". A run where those two numbers differ is a run
// whose dataset is smaller than it appears, and an operator has to be able to
// see that.
type DNSSECWriterStats interface {
	Stats() dnssecobs.Stats
}

// DNSSECObserverStats is the reporting half of the observer.
//
// An interface so internal/api does not have to construct one, and so a test
// can supply fixed numbers. Nil whenever local validation is off, which is the
// default; every reader tolerates that.
type DNSSECObserverStats interface {
	Stats() observe.Stats
}
