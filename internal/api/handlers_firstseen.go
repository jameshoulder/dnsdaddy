package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/firstseen"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// firstSeenRecord is one domain as the API renders it.
type firstSeenRecord struct {
	Domain     string `json:"domain"`
	FirstSeen  string `json:"firstSeen,omitempty"`
	LastSeen   string `json:"lastSeen,omitempty"`
	QueryCount int64  `json:"queryCount"`
	// Certain reports that firstSeen is the true first sighting on this
	// installation rather than possibly a restart after an eviction. See
	// store.FirstSeen.Certain.
	Certain bool `json:"certain"`
}

// firstSeenLookup is the answer to "has this network seen this domain".
type firstSeenLookup struct {
	// Query is the name that was asked about, and Domain the registered domain
	// it rolls up to. Both, because they are usually different and an operator
	// pasting a full hostname needs to see which registration answered.
	Query  string `json:"query"`
	Domain string `json:"domain,omitempty"`

	// Status is "new", "known" or "unknown".
	//
	// "unknown" is not a synonym for "new" and clients must not render it as
	// one: it means the index is switched off, or the name has no registered
	// domain to index. An interface that showed "never seen before" for every
	// domain on an installation with the index disabled would be the loudest
	// false signal this project could produce.
	Status string `json:"status"`

	Record *firstSeenRecord `json:"record,omitempty"`

	// Explanation is why the status is what it is, in a sentence, so an
	// operator does not have to infer it from a missing field.
	Explanation string `json:"explanation"`
}

func renderFirstSeen(rec store.FirstSeen) *firstSeenRecord {
	return &firstSeenRecord{
		Domain:     rec.Domain,
		FirstSeen:  rec.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:   rec.LastSeen.UTC().Format(time.RFC3339),
		QueryCount: rec.QueryCount,
		Certain:    rec.Certain,
	}
}

// handleFirstSeenLookup answers whether a domain has been seen before.
func (a *API) handleFirstSeenLookup(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("domain")
	if name == "" {
		writeError(w, http.StatusBadRequest, "a domain query parameter is required")
		return
	}

	idx := a.DNS.FirstSeenIndex()
	rec, status := idx.Lookup(r.Context(), name)

	out := firstSeenLookup{Query: name, Status: string(status), Domain: rec.Domain}
	switch status {
	case firstseen.StatusKnown:
		out.Record = renderFirstSeen(rec)
		out.Explanation = "This installation has queried " + rec.Domain + " before."
		if !rec.Certain {
			out.Explanation += " The index has evicted rows since it started, so this first-seen " +
				"time may be when counting restarted rather than the first sighting."
		}
	case firstseen.StatusNew:
		out.Explanation = "This installation has no record of " + rec.Domain + ". " +
			"That is a novelty signal, not a verdict: every domain is new once."
	default:
		if idx == nil {
			out.Explanation = "The first-seen index is switched off, so novelty cannot be " +
				"answered. This is not the same as the domain being new."
		} else {
			out.Explanation = "No registered domain could be derived from this name, so it is " +
				"not something the index tracks."
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleFirstSeenRecent lists the most recently discovered domains.
//
// This is what makes hunt 5 real: "what has this network started talking to
// that it never talked to before" used to be approximated from the query log,
// and was therefore only as good as its retention.
func (a *API) handleFirstSeenRecent(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}

	idx := a.DNS.FirstSeenIndex()
	stats := idx.Stats()

	out := map[string]any{
		"enabled": idx != nil,
		// Stated on every response rather than left for an operator to work
		// out: a list of "newly seen domains" from an index that has been
		// evicting is partly a list of domains whose rows were recycled.
		"evictions": stats.Evictions,
		"rows":      stats.Rows,
		"maxRows":   stats.MaxRows,
		"domains":   []firstSeenRecord{},
	}
	if idx == nil {
		out["explanation"] = "The first-seen index is switched off. Enable dns.first_seen to " +
			"record which registered domains this installation has been asked about."
		writeJSON(w, http.StatusOK, out)
		return
	}

	// The store clamps the limit as well; asking here keeps the error message
	// honest when somebody requests a million.
	recent, err := a.Store.RecentFirstSeen(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the first-seen index")
		return
	}
	rendered := make([]firstSeenRecord, 0, len(recent))
	for _, rec := range recent {
		rendered = append(rendered, *renderFirstSeen(rec))
	}
	out["domains"] = rendered
	if stats.Evictions > 0 {
		out["explanation"] = "This index has evicted rows to stay within max_rows, so a domain " +
			"listed here may be one whose row was recycled rather than one never seen before. " +
			"Records with certain=true predate the first eviction and are unambiguous."
	}
	writeJSON(w, http.StatusOK, out)
}
