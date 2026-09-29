package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/dnssecobs"
)

const DNSSECModeSetting = "dnssec.mode"

var ErrDNSSECModeLocked = errors.New("daddybound mode is pinned by dns.local_dnssec_validation; remove that setting to manage the mode here")

// DNSSECRuntimeState captures one published mode. The interfaces reference
// concurrency-safe runtime counters; none starts a lookup when read.
type DNSSECRuntimeState struct {
	Configured, Effective, ChosenBy string
	Locked                          bool
	Reason                          string
	NativeAvailable                 bool
	Native                          native.ClientStats
	NativeWriter                    dnssecobs.Stats
	Observer                        DNSSECObserverStats
	ObserverActive                  bool
	Writer                          DNSSECWriterStats
	Anchors                         DNSSECAnchors
}

type DNSSECControl interface {
	State() DNSSECRuntimeState
	SetMode(context.Context, string) error
}

func (a *API) dnssecState() DNSSECRuntimeState {
	if a.DNSSECControl != nil {
		return a.DNSSECControl.State()
	}
	configured := a.Config.DNS.LocalDNSSECValidation
	if configured == "" {
		configured = "unset"
	}
	source := a.LocalDNSSECModeSource
	if source == "" {
		source = "config"
	}
	return DNSSECRuntimeState{Configured: configured, Effective: a.Config.DNS.LocalDNSSECMode(), ChosenBy: source,
		Observer: a.DNSSEC, ObserverActive: a.Config.DNS.LocalDNSSECMode() == config.LocalDNSSECObserve && a.DNSSEC != nil,
		Writer: a.DNSSECWriter, Anchors: a.Anchors}
}

func (a *API) handleDNSSECMode(w http.ResponseWriter, r *http.Request) {
	if a.DNSSECControl == nil {
		writeError(w, http.StatusServiceUnavailable, "runtime mode control is unavailable")
		return
	}
	var body struct {
		Mode                       string `json:"mode"`
		AcknowledgeNativeTransport bool   `json:"acknowledgeNativeTransport"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	switch body.Mode {
	case config.LocalDNSSECOff:
	case config.LocalDNSSECObserve, config.LocalDNSSECEnforce:
		if !body.AcknowledgeNativeTransport {
			writeError(w, http.StatusBadRequest, "acknowledge native UDP/TCP port 53 traffic to root and authoritative servers before enabling Daddybound")
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "mode must be off, observe or enforce")
		return
	}
	if err := a.DNSSECControl.SetMode(r.Context(), body.Mode); err != nil {
		if errors.Is(err, ErrDNSSECModeLocked) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": a.dnssecModeStatus()})
}
