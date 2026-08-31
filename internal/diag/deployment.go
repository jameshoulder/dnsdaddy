package diag

import (
	"fmt"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

// DeploymentMode reports what kind of deployment this is, and whether the
// dashboard is where that kind of deployment should put it.
//
// It exists because doctor previously had no idea. Every other check reasons
// about the resolver; the management interface was described only by
// ManagementExposure, which counts plaintext requests that have already
// happened. That leaves the most common operator question unanswered — "is my
// dashboard exposed?" — and, worse, gives the same answer whether the
// dashboard is correctly on loopback behind Caddy or is not running at all.
//
// The rule that matters throughout: a dashboard on 127.0.0.1 is the expected,
// correct state for both of the public deployment modes. Reporting it as a
// problem would train operators to "fix" the one thing protecting them.
type DeploymentInput struct {
	// Listen is http.listen as configured — the address the process binds.
	Listen string

	// BaseURL is set when a TLS front end is in play; the installer writes it
	// for HTTPS mode and leaves it empty for the tunnel.
	BaseURL string

	// SecureCookies is the configured mode: auto, always or never.
	SecureCookies string

	// TrustedProxyCIDRs are the peers whose forwarding headers are believed.
	TrustedProxyCIDRs []string

	// PublicPlaintextRequests counts management requests that arrived from a
	// public address over plain HTTP. Non-zero is evidence, not inference.
	PublicPlaintextRequests uint64
}

// Mode names the deployment shape, for the summary line and for tests.
type Mode string

const (
	ModeTunnel  Mode = "SSH tunnel"      // loopback, no TLS front end
	ModeProxied Mode = "HTTPS via proxy" // loopback, TLS front end configured
	ModeLAN     Mode = "LAN"             // a private address, reachable on the local network
	ModePublic  Mode = "publicly bound"  // a wildcard or public address
	ModeUnknown Mode = "unknown"
)

// Classify decides the deployment shape from configuration alone.
func Classify(in DeploymentInput) Mode {
	kind := config.ClassifyManagementBind(in.Listen)
	switch kind {
	case config.BindLoopback:
		if strings.TrimSpace(in.BaseURL) != "" {
			return ModeProxied
		}
		return ModeTunnel
	case config.BindPrivate:
		return ModeLAN
	case config.BindWildcard, config.BindPublic:
		return ModePublic
	}
	return ModeUnknown
}

// Deployment returns the checks describing the management surface.
func Deployment(in DeploymentInput) []Check {
	mode := Classify(in)
	checks := []Check{deploymentBind(in, mode)}
	if mode == ModeProxied {
		checks = append(checks, proxyTrust(in))
	}
	return checks
}

func deploymentBind(in DeploymentInput, mode Mode) Check {
	c := Check{Section: SectionWeb, Name: "Dashboard backend"}
	listen := in.Listen
	if listen == "" {
		listen = "(unset)"
	}

	switch mode {
	case ModeTunnel:
		c.Status = StatusPass
		c.Summary = fmt.Sprintf("Private on %s. Reach it over an SSH tunnel; nothing is published.", listen)
		c.Evidence = []string{"mode: " + string(mode), "listen: " + listen}
	case ModeProxied:
		c.Status = StatusPass
		c.Summary = fmt.Sprintf("Private on %s, with %s terminating TLS in front of it.", listen, in.BaseURL)
		c.Evidence = []string{"mode: " + string(mode), "listen: " + listen, "public URL: " + in.BaseURL}
		if in.SecureCookies != "always" {
			c.Status = StatusWarn
			c.Summary = fmt.Sprintf("Private on %s behind %s, but session cookies are not marked Secure.", listen, in.BaseURL)
			c.Action = `Set http.secure_cookies to "always" (DNSDADDY_SECURE_COOKIES=always). ` +
				"Behind TLS there is no reason for the cookie to be sent over plain HTTP."
		}
	case ModeLAN:
		c.Status = StatusPass
		c.Summary = fmt.Sprintf("Published on %s for the local network.", listen)
		c.Evidence = []string{"mode: " + string(mode), "listen: " + listen}
		c.Action = "Anyone who can reach that address can reach the login page. That is the " +
			"intended trade-off for a LAN deployment; it is the wrong one on a public network."
	case ModePublic:
		c.Status = StatusFail
		c.Summary = fmt.Sprintf("Bound to %s, which publishes the management API beyond this machine.", listen)
		c.Action = "Bind 127.0.0.1:8080 and reach it over an SSH tunnel, or put a TLS reverse " +
			"proxy in front of loopback. The management API should never be published in plaintext."
	default:
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("Could not tell what %q publishes.", listen)
	}

	// Evidence beats classification. A request that actually arrived from the
	// public internet in plaintext outranks anything inferred from config.
	if in.PublicPlaintextRequests > 0 && c.Status != StatusFail {
		c.Status = StatusFail
		c.Summary = fmt.Sprintf(
			"%s — but %d management request(s) have arrived from a public address over plain HTTP.",
			c.Summary, in.PublicPlaintextRequests)
		c.Action = "Something is reaching this dashboard that the configuration does not account for. " +
			"Check for a port-forward or a proxy in front of it, then change the admin password."
	}
	return c
}

// proxyTrust reports whether the trusted-proxy list matches the deployment.
//
// Only meaningful once a TLS front end exists: without one, trusting no
// forwarding header is the correct answer and an empty list is not a problem.
func proxyTrust(in DeploymentInput) Check {
	c := Check{Section: SectionWeb, Name: "Proxy trust"}

	if len(in.TrustedProxyCIDRs) == 0 {
		c.Status = StatusWarn
		c.Summary = "A TLS front end is configured, but no proxy is trusted to report the client address."
		c.Action = "Set http.trusted_proxy_cidrs to the proxy's address range " +
			"(DNSDADDY_TRUSTED_PROXY_CIDRS). Until then every request appears to come from the " +
			"proxy itself, so per-network policy and rate limiting cannot tell clients apart."
		return c
	}

	// A list that trusts everything is the same as trusting no one, except
	// that it believes whatever a client claims — which is worse.
	for _, cidr := range in.TrustedProxyCIDRs {
		switch strings.TrimSpace(cidr) {
		case "0.0.0.0/0", "::/0":
			c.Status = StatusFail
			c.Summary = "Every peer is trusted to report the client address."
			c.Evidence = []string{"trusted_proxy_cidrs: " + strings.Join(in.TrustedProxyCIDRs, ", ")}
			c.Action = "Narrow this to the reverse proxy's address only. As configured, any client " +
				"can set X-Forwarded-For and be treated as any address it likes."
			return c
		}
	}

	c.Status = StatusPass
	c.Summary = fmt.Sprintf("%d proxy range(s) trusted to report the client address.", len(in.TrustedProxyCIDRs))
	c.Evidence = []string{"trusted_proxy_cidrs: " + strings.Join(in.TrustedProxyCIDRs, ", ")}
	return c
}
