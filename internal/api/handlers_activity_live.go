package api

import (
	"net/http"

	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
)

// Live traffic remains available independently of historical rollups. The
// additive clientAccess block contains bounded, privacy-gated source evidence;
// anonymous counters retain their existing fields and meanings. This route
// reads in-memory snapshots only and never probes DNS or grants permission.
func (a *API) handleLiveActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.DNS == nil {
		writeError(w, http.StatusServiceUnavailable, "live DNS activity is unavailable in this process")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		dnsserver.LiveActivity
		ClientAccess ClientAccessActivity `json:"clientAccess"`
	}{a.DNS.LiveActivity(), a.clientAccessActivity()})
}
