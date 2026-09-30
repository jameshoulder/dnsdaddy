package api

import "net/http"

// Live traffic must remain visible when a rollup read fails or query logging
// is disabled. After normal session/token authentication, this endpoint reads
// only DNS handler counters, with no query-history reads or DNS probes.
func (a *API) handleLiveActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.DNS == nil {
		writeError(w, http.StatusServiceUnavailable, "live DNS activity is unavailable in this process")
		return
	}
	writeJSON(w, http.StatusOK, a.DNS.LiveActivity())
}
