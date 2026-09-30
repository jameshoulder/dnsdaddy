package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/miekg/dns"
)

const DNSTransportSetting = "dns.transport.v1"

func sanitizeForLog(v string) string {
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.ReplaceAll(v, "\r", "")
	return v
}

var ErrDNSTransportLocked = errors.New("DNS transport is pinned by dns.resolution_transport; remove that setting to manage transport here")

// DNSTransportState reports the selected query path. Reading it never tests
// connectivity, refreshes anchors, or sends names to a configured resolver.
type DNSTransportState struct {
	Transport         string                       `json:"transport"`
	Locked            bool                         `json:"locked"`
	ChosenBy          string                       `json:"chosenBy"`
	Reason            string                       `json:"reason,omitempty"`
	Endpoints         []resolver.EncryptedEndpoint `json:"endpoints"`
	TLSMinimum        string                       `json:"tlsMinimum"`
	EncryptedOnly     bool                         `json:"encryptedOnly"`
	PlaintextFallback bool                         `json:"plaintextFallback"`
	Bootstrap         string                       `json:"bootstrap"`
	Scope             string                       `json:"scope"`
	DaddyboundMode    string                       `json:"daddyboundMode"`
	Stats             *resolver.EncryptedStats     `json:"stats"`
}

type DNSTransportControl interface {
	TransportState() DNSTransportState
	SetTransport(context.Context, string, []resolver.EncryptedEndpoint) error
}

func (a *API) transportState() DNSTransportState {
	if c, ok := a.DNSSECControl.(DNSTransportControl); ok {
		return c.TransportState()
	}
	return DNSTransportState{Transport: a.Config.DNS.TransportMode(), Locked: true,
		ChosenBy: "config", Reason: "DNS transport control is unavailable in this process",
		Endpoints: []resolver.EncryptedEndpoint{}, TLSMinimum: "1.3", Bootstrap: "system",
		DaddyboundMode: a.dnssecState().Effective,
		Scope:          "Transport runtime status is unavailable."}
}

func (a *API) handleDNSTransport(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, a.transportState())
		return
	}
	c, ok := a.DNSSECControl.(DNSTransportControl)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "DNS transport control is unavailable")
		return
	}
	var body struct {
		Transport                  string                       `json:"transport"`
		Endpoints                  []resolver.EncryptedEndpoint `json:"endpoints"`
		AcknowledgeForwarding      bool                         `json:"acknowledgeForwarding"`
		AcknowledgeNativeTransport bool                         `json:"acknowledgeNativeTransport"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if c.TransportState().Locked {
		writeError(w, http.StatusConflict, ErrDNSTransportLocked.Error())
		return
	}
	switch body.Transport {
	case config.ResolutionEncrypted:
		if !body.AcknowledgeForwarding {
			writeError(w, http.StatusBadRequest, "acknowledge that the approved resolvers receive DNS names, including supporting and background lookups")
			return
		}
	case config.ResolutionNative:
		if c.TransportState().Transport != config.ResolutionNative && !body.AcknowledgeNativeTransport {
			writeError(w, http.StatusBadRequest, "acknowledge native UDP/TCP port 53 traffic before selecting native transport")
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "transport must be native or encrypted")
		return
	}
	// Construction validates every dial target and TLS identity without
	// opening connections. Invalid settings never reach the controller/store.
	if len(body.Endpoints) != 0 || body.Transport == config.ResolutionEncrypted {
		candidate, err := resolver.NewEncryptedUpstreams(body.Endpoints, 4*time.Second)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = candidate.Close()
	}
	if err := c.SetTransport(r.Context(), body.Transport, body.Endpoints); err != nil {
		if errors.Is(err, ErrDNSTransportLocked) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		a.Log.Error("DNS transport activation failed", "error", sanitizeForLog(err.Error()))
		writeError(w, http.StatusInternalServerError, "could not activate DNS transport; the previous selection remains active")
		return
	}
	writeJSON(w, http.StatusOK, c.TransportState())
}

func (a *API) handleTestDNSTransport(w http.ResponseWriter, r *http.Request) {
	select {
	case a.transportTests <- struct{}{}:
		defer func() { <-a.transportTests }()
	default:
		writeError(w, http.StatusTooManyRequests, "an encrypted DNS test is already running; try again when it finishes")
		return
	}
	var body struct {
		Endpoints             []resolver.EncryptedEndpoint `json:"endpoints"`
		AcknowledgeForwarding bool                         `json:"acknowledgeForwarding"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if !body.AcknowledgeForwarding {
		writeError(w, http.StatusBadRequest, "acknowledge sending a root DNSKEY test query to these endpoints")
		return
	}
	// Each explicit test uses a fixed public root question. It does not
	// disclose browsing history, change configuration, or install trust.
	client, err := resolver.NewEncryptedUpstreams(body.Endpoints, 2*time.Second)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	query := new(dns.Msg)
	query.SetQuestion(".", dns.TypeDNSKEY)
	query.SetEdns0(1232, true)
	query.CheckingDisabled = true
	answer, err := client.Exchange(ctx, query)
	out := map[string]any{"ok": err == nil, "rcode": "", "stats": client.Stats()}
	if err != nil {
		out["error"] = "Encrypted test failed. Check the endpoint, bootstrap IPs, TLS hostname and outbound firewall rules."
	} else if answer != nil {
		out["rcode"] = dns.RcodeToString[answer.Rcode]
		out["ok"] = answer.Rcode == dns.RcodeSuccess
		if answer.Rcode != dns.RcodeSuccess {
			out["error"] = "The encrypted resolver responded but did not answer the root DNSKEY test successfully."
		}
	}
	writeJSON(w, http.StatusOK, out)
}
