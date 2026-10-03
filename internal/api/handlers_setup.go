package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/setupguide"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

const setupAddressSetting = "setup.advertised_dns.v1"

// Configuration remains authoritative for automated installations. A saved
// dashboard address is display-only and never mutates listeners or the ACL.
func (a *API) setupAddress(ctx context.Context) (string, bool, error) {
	if a.Config.DNS.AdvertisedEndpoint != "" {
		return a.Config.DNS.AdvertisedEndpoint, true, nil
	}
	value, err := a.Store.GetSetting(ctx, setupAddressSetting)
	if errors.Is(err, store.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if value != "" {
		ep, err := netip.ParseAddrPort(value)
		if err != nil {
			return "", false, errors.New("saved client-facing address is invalid")
		}
		if _, err := setupguide.Endpoint(ep.Addr().String(), int(ep.Port())); err != nil {
			return "", false, err
		}
	}
	return value, false, nil
}

func (a *API) handleSetup(w http.ResponseWriter, r *http.Request) {
	endpoint, locked, err := a.setupAddress(r.Context())
	if err != nil {
		writeError(w, 503, "The saved DNS address could not be read. Do not substitute the container IP; check storage and retry.")
		return
	}
	ip, port := "", 53
	if ep, err := netip.ParseAddrPort(endpoint); err == nil {
		ip, port = ep.Addr().String(), int(ep.Port())
	}
	mode := a.dnssecState()
	writeJSON(w, 200, map[string]any{
		"presets": setupguide.Presets(), "endpoint": endpoint,
		"serverIp": ip, "dnsPort": port, "addressLocked": locked,
		"addressSource":       map[bool]string{true: "configuration", false: "dashboard"}[locked],
		"dashboardClientIp":   clientKey(r, a.TrustedProxies),
		"dashboardClientNote": "This is the management connection's source, not proof of a DNS client's source. Proxies, NAT, VPNs and IPv6 can make them differ. It is never granted access automatically.",
		"mode":                mode.Effective, "modeLocked": mode.Locked,
		"listeners": map[string]string{"udp": a.Config.DNS.ListenUDP, "tcp": a.Config.DNS.ListenTCP, "dot": a.Config.DNS.ListenDoT},
	})
}

func (a *API) handleSetupPreview(w http.ResponseWriter, r *http.Request) {
	var body setupguide.Input
	if !decodeBody(w, r, &body) {
		return
	}
	plan, err := setupguide.Build(body)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	// Preview is entirely offline. Applying a grant uses the existing
	// Networks API, including public acknowledgement and aggregate guards.
	writeJSON(w, 200, plan)
}

// Use a request-local configuration value to reuse the established bounded
// interface reporter. Never write to a.Config while another request reads it,
// and never copy API mutexes or infer an endpoint from HTTP Host headers.
func (a *API) handleSetupServerAddresses(w http.ResponseWriter, r *http.Request) {
	endpoint, _, err := a.setupAddress(r.Context())
	if err != nil {
		writeError(w, 503, "The configured client-facing DNS address could not be read; check storage and retry.")
		return
	}
	deps := a.Deps
	deps.Config.DNS.AdvertisedEndpoint = endpoint
	reader := &API{Deps: deps, serverInterfaces: a.serverInterfaces}
	reader.handleServerAddresses(w, r)
}

func (a *API) handleSetupAddress(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ServerIP string  `json:"serverIp"`
		DNSPort  int     `json:"dnsPort"`
		Clear    bool    `json:"clear"`
		Previous *string `json:"previous"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	value := ""
	if !body.Clear {
		var err error
		value, err = setupguide.Endpoint(body.ServerIP, body.DNSPort)
		if err != nil {
			writeError(w, 400, err.Error())
			return
		}
	}
	// This route has its own one-setting intent/outcome journal. It is not
	// in auditedManagementRoute's resource set; adding it there must remove
	// this lock/journal rather than taking configWrites twice.
	a.configWrites.Lock()
	defer a.configWrites.Unlock()
	current, locked, err := a.setupAddress(r.Context())
	if err != nil {
		writeError(w, 503, "The current address could not be read; nothing was changed.")
		return
	}
	if locked {
		writeError(w, 409, "DNSDADDY_ADVERTISED_DNS / dns.advertised_endpoint controls this address. Edit or remove that setting and restart to manage it here.")
		return
	}
	if body.Previous != nil && *body.Previous != current {
		writeError(w, 409, "The DNS address changed in another session. Refresh and review it before saving.")
		return
	}
	p, ok := a.Auth.authenticate(r)
	if !ok {
		writeError(w, 401, "authentication required")
		return
	}
	scope := store.AuditScope{Kind: "settings", ID: setupAddressSetting}
	before, err := a.Store.CaptureConfig(r.Context(), scope)
	if err != nil {
		writeError(w, 503, "The current configuration could not be recorded; nothing was changed.")
		return
	}
	id, err := a.Store.BeginConfigChange(r.Context(), store.CleanAuditLabel(reviewActor(p)), "put", "settings/advertised_dns")
	if err != nil {
		writeError(w, 503, "Configuration history is unavailable; nothing was changed.")
		return
	}
	writeErr := a.Store.SetSetting(r.Context(), setupAddressSetting, value)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	after, captureErr := a.Store.CaptureConfig(ctx, scope)
	status, httpStatus, note := "complete", 200, ""
	if writeErr != nil {
		status, httpStatus, note = "failed", 500, "The address write failed. Review the recorded persisted state before retrying."
	}
	changes := store.DiffConfig(before, after)
	if captureErr != nil {
		status, httpStatus, note = "incomplete", 500, "The address write ran but its resulting state could not be recorded."
		changes = nil
	}
	finishErr := a.Store.CompleteConfigChange(ctx, id, status, httpStatus, changes, note)
	if captureErr != nil || finishErr != nil {
		writeJSON(w, 500, map[string]any{"error": "The address write ran but its history could not be completed. Refresh and inspect it before retrying.", "configurationMayHaveChanged": true, "auditId": id})
		return
	}
	if writeErr != nil {
		writeError(w, 500, note)
		return
	}
	writeJSON(w, 200, map[string]any{"endpoint": value, "verified": false, "auditId": id,
		"note": "Saved for dashboard display. No listener, permission, firewall, NAT mapping or TLS certificate was changed. Test from a permitted client."})
}
