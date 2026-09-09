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

	recent, err := a.Store.ListDNSSECObservations(r.Context(), store.DNSSECObservationFilter{
		Status:            r.URL.Query().Get("status"),
		DisagreementsOnly: r.URL.Query().Get("disagreements") == "1",
		Limit:             intParam(r, "limit", 50),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
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
		"mode": a.Config.DNS.LocalDNSSECMode(),
		// Stated in the payload rather than left to the reader, because every
		// number below is only meaningful alongside it. A dashboard, a script
		// or a person reading the JSON has to be able to see that these
		// verdicts changed nothing.
		"enforcing":    false,
		"experimental": true,
		"summary":      summary,
		"recent":       recent,
		"runtime":      a.dnssecRuntime(),
		"windowHours":  hours,
	})
}

// dnssecRuntime reports the health of the observer itself, as distinct from
// the health of DNS resolution.
//
// The two are separate on purpose. A validator dropping observations under
// load is a statement about the sample, not about whether clients are being
// answered — and an operator must be able to tell those apart at a glance.
func (a *API) dnssecRuntime() map[string]any {
	out := map[string]any{
		"available": a.Config.DNS.ObserveDNSSEC(),
	}
	if a.DNSSEC == nil {
		return out
	}
	s := a.DNSSEC.Stats()
	out["observed"] = s.Observed
	out["dropped"] = s.Dropped
	out["panics"] = s.Panics
	if !s.LastAt.IsZero() {
		out["lastAt"] = s.LastAt
		out["lastStatus"] = string(s.LastStatus)
	}
	if a.DNSSECWriter != nil {
		w := a.DNSSECWriter.Stats()
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
