package api

import (
	"errors"
	"net/http"

	"github.com/jameshoulder/dnsdaddy/internal/protection"
)

func (a *API) handleProtection(w http.ResponseWriter, r *http.Request) {
	if a.Protection == nil {
		writeError(w, http.StatusServiceUnavailable, "resolver protection is not available")
		return
	}
	if r.Method == http.MethodPut {
		var cfg protection.Config
		if !decodeBody(w, r, &cfg) {
			return
		}
		if _, err := a.Protection.Update(r.Context(), cfg); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, protection.ErrVersionConflict) {
				status = http.StatusConflict
			}
			if errors.Is(err, protection.ErrPersistence) {
				status = http.StatusInternalServerError
			}
			writeError(w, status, err.Error())
			return
		}
	}
	cfg := a.Protection.Config()
	writeJSON(w, http.StatusOK, struct {
		protection.Config
		Counters protection.Counters `json:"counters"`
	}{cfg, a.Protection.Counters()})
}
