package dnsserver

import "time"

// observeClientAccess runs after a response was decided. Source permission and
// token authentication are different: a tokenised DoH answer must not imply
// that ordinary DNS from the same NAT address has become permitted.
func (h *Handler) observeClientAccess(now time.Time, meta requestMeta, outcome activityOutcome) {
	if !h.queryLogEnabled || !h.logClientIP || meta.networkID != "" || h.engine == nil {
		return
	}
	if outcome != activityRefused && !h.access.active.Load() {
		return
	}
	match := h.engine.MatchClient(meta.clientAddr)
	if !h.engine.PolicyLogsQueries(match.PolicyID) {
		return
	}
	h.access.record(now, meta.clientAddr, meta.proto, string(outcome))
}

// AccessActivity reports recent source refusals and subsequent recovery. It
// never enables logging, performs a lookup, persists a query or grants access.
// Per-policy privacy is also checked by the management API before disclosure.
func (h *Handler) AccessActivity() AccessSnapshot {
	if h == nil {
		return AccessSnapshot{Entries: []AccessEntry{}}
	}
	return h.access.snapshot(time.Now(), h.queryLogEnabled && h.logClientIP)
}
