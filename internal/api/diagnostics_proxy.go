package api

import (
	"net/http"

	"github.com/jameshoulder/dnsdaddy/internal/diag"
	"github.com/jameshoulder/dnsdaddy/internal/httpx"
)

// proxyRequestCheck is request-scoped evidence, not a discovery or trust rule.
// Header text is not echoed (it may contain identifiers or arbitrary input).
// An untrusted sender can affect only its own authenticated diagnostic response.
func (a *API) proxyRequestCheck(r *http.Request) (diag.Check, bool) {
	forwarded := r.Header.Get("X-Forwarded-For") != "" ||
		r.Header.Get("X-Forwarded-Proto") != "" || r.Header.Get("X-Forwarded-Host") != ""
	if !forwarded {
		return diag.Check{}, false
	}
	peer := httpx.PeerAddr(r)
	c := diag.Check{Section: diag.SectionWeb, Name: "Observed proxy peer", Status: diag.StatusWarn}
	if !peer.IsValid() {
		c.Summary = "Proxy headers arrived, but the actual connecting peer could not be identified."
		c.Action = "Review the reverse proxy connection; no forwarding header is used to discover a trusted peer."
		return c, true
	}
	c.Evidence = []string{"actual connection peer: " + peer.String(), "scope: this authenticated HTTP request only"}
	if a.TrustedProxies != nil && a.TrustedProxies.Trusts(peer) {
		c.Status = diag.StatusPass
		c.Summary = "The actual peer of this request is in the configured trusted-proxy ranges."
	} else {
		c.Summary = "Proxy headers arrived from a peer outside the trusted-proxy ranges; forwarded client and TLS information is ignored."
		c.Action = "For installer-managed Docker HTTPS, run ./deploy/install-docker.sh --upgrade. " +
			"For a custom proxy, verify its real connecting address before setting http.trusted_proxy_cidrs. " +
			"Do not trust all private ranges. This finding does not prove the cause of missing query data."
	}
	return c, true
}
