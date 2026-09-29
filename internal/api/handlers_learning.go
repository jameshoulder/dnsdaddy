package api

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/learning"
)

// The learner has no mutation endpoint. Looking at a baseline cannot enqueue
// DNS, contact providers, mark a domain benign or train it from review labels.
func (a *API) handleLearningStatus(w http.ResponseWriter, r *http.Request) {
	if a.Learning == nil {
		if a.LearningError != "" {
			writeJSON(w, http.StatusOK, learning.UnavailableStatus())
			return
		}
		writeJSON(w, http.StatusOK, learning.DisabledStatus())
		return
	}
	writeJSON(w, http.StatusOK, a.Learning.Status())
}

func (a *API) handleLearningClients(w http.ResponseWriter, r *http.Request) {
	client := strings.TrimSpace(r.URL.Query().Get("client"))
	if client != "" {
		if ip, err := netip.ParseAddr(client); err == nil {
			client = ip.Unmap().String()
		} else if client != "unattributed" && (!strings.HasPrefix(client, "network:") || len(client) <= 8 || len(client) > 136 || strings.ContainsAny(client, "\r\n\x00")) {
			writeError(w, http.StatusBadRequest, "client must be an IP address, network:<id>, or unattributed")
			return
		}
		if a.Learning == nil && a.LearningError != "" {
			s := learning.UnavailableStatus()
			writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "available": false, "found": nil, "client": client, "reason": s.Error, "error": s.Error})
			return
		}
		view, found := a.Learning.Inspect(client)
		if !found {
			writeJSON(w, http.StatusOK, map[string]any{"enabled": a.Learning != nil, "found": false, "client": client, "reason": "no retained local baseline for this subject"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "found": true, "client": view})
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "limit must be an integer from 1 to 500")
			return
		}
		limit = n
	}
	if a.Learning == nil && a.LearningError != "" {
		s := learning.UnavailableStatus()
		writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "available": false, "error": s.Error, "clients": []learning.ClientView{}})
		return
	}
	clients := a.Learning.Clients(limit)
	total := 0
	if a.Learning != nil {
		total = a.Learning.Status().Clients.Tracked
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": a.Learning != nil, "clients": clients, "total": total, "returned": len(clients), "truncated": total > len(clients), "scope": "current bounded client models, newest activity first; aggregate parameters, not a complete query history"})
}
