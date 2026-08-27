package diag

import (
	"fmt"
	"strings"
	"time"
)

// Sections used by the runtime checks.
const (
	SectionSystem   = "SYSTEM"
	SectionListener = "DNS LISTENER"
	SectionUpstream = "UPSTREAM"
	SectionDatabase = "DATABASE"
	SectionWeb      = "WEB INTERFACE"
	SectionIntel    = "THREAT INTELLIGENCE"
)

// ResolverProbe is the outcome of sending one real query at a listener.
//
// The whole point of the probe is that it exercises the same path a client
// does. Interpreting its result is separated from performing it so the
// interpretation — which is where the useful judgement lives — can be tested
// without a socket.
type ResolverProbe struct {
	// Address is where the query was sent, as the operator would type it.
	Address string
	// Proto is "udp" or "tcp".
	Proto string
	// Rcode is the DNS response code name, empty when Err is set.
	Rcode string
	// Err is a transport failure: nothing answered, or the answer was
	// unreadable.
	Err error
	// Elapsed is how long the exchange took.
	Elapsed time.Duration
	// SourceAddr is the address the probe left from, which is the address the
	// resolver will have judged against its ACL.
	SourceAddr string
}

// ResolverReachability turns a probe result into a finding.
//
// The distinction it draws is the one an operator cannot draw from `dig`
// alone: REFUSED from DNS Daddy is not a fault, it is DNS Daddy working
// correctly and declining to serve this source address. Saying "DNS query
// failed" there would be true and useless.
func ResolverReachability(p ResolverProbe, allowedCIDRs []string) Check {
	c := Check{
		Section: SectionListener,
		Name:    fmt.Sprintf("%s query to %s", strings.ToUpper(p.Proto), p.Address),
	}

	if p.Err != nil {
		c.Status = StatusFail
		c.Summary = fmt.Sprintf("Nothing answered a DNS query sent to %s over %s.", p.Address, p.Proto)
		c.Evidence = []string{"error: " + p.Err.Error()}
		c.Action = "Check that DNS Daddy is running, that it is listening on this address rather " +
			"than loopback only, and that no firewall sits between this command and the port. " +
			"If DNS Daddy runs in Docker, check that the port is published."
		return c
	}

	c.Evidence = []string{
		fmt.Sprintf("rcode: %s", p.Rcode),
		"elapsed: " + formatElapsed(p.Elapsed),
	}
	if p.SourceAddr != "" {
		c.Evidence = append(c.Evidence, "query left from: "+p.SourceAddr)
	}

	switch p.Rcode {
	case "REFUSED":
		c.Status = StatusFail
		c.Summary = "DNS Daddy answered, and REFUSED the query: this source address is not permitted to resolve."
		if len(allowedCIDRs) > 0 {
			c.Evidence = append(c.Evidence, "dns.allowed_client_cidrs: "+strings.Join(allowedCIDRs, ", "))
		}
		c.Action = "The resolver is running and reachable — this is not a network fault. Add the " +
			"address the query left from to dns.allowed_client_cidrs " +
			"(DNSDADDY_ALLOWED_CLIENT_CIDRS) if it is a client you trust, then restart."
	case "NOERROR":
		c.Status = StatusPass
		c.Summary = fmt.Sprintf("DNS Daddy answered a query on %s over %s.", p.Address, p.Proto)
	case "SERVFAIL":
		c.Status = StatusFail
		c.Summary = "DNS Daddy answered SERVFAIL: it is reachable but could not resolve the name."
		c.Action = "This is an upstream problem rather than a client one. See the UPSTREAM section below."
	default:
		// A blocked test name would come back NXDOMAIN, and so would a
		// genuinely missing one. Reachability is established either way, which
		// is what this check is for.
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("DNS Daddy answered %s. It is reachable, but did not resolve the test name.", p.Rcode)
		c.Action = "Reachability is fine. If the test name should resolve, check policy and blocklists."
	}
	return c
}

// PortConflict reports on a DNS port that DNS Daddy is not answering on.
//
// Three states are worth telling apart, and a bare "port 53 is in use" tells
// them apart not at all: nothing is there, DNS Daddy is there, or something
// else is there.
func PortConflict(proto, addr string, bindable bool, owners []string) Check {
	c := Check{Section: SectionListener, Name: fmt.Sprintf("Port %s (%s)", addr, proto)}

	if bindable {
		c.Status = StatusFail
		c.Summary = fmt.Sprintf("Nothing is listening on %s.", addr)
		c.Action = "DNS Daddy is not running, or is bound to a different address. " +
			"Check `systemctl status dnsdaddy` or `docker compose ps`."
		return c
	}

	c.Status = StatusFail
	c.Summary = fmt.Sprintf("%s is held by another process, so DNS Daddy cannot serve on it.", addr)
	if len(owners) > 0 {
		c.Evidence = append(c.Evidence, "listening processes: "+strings.Join(owners, ", "))
		if hasOwner(owners, "systemd-resolved") {
			c.Action = "systemd-resolved owns port 53 on most Ubuntu installs. Disable its stub " +
				"listener (DNSStubListener=no in /etc/systemd/resolved.conf.d/) and restart it; " +
				"deploy/install.sh does this for you. Do not disable systemd-resolved itself " +
				"unless you have given this machine another resolver first."
			return c
		}
		for _, known := range []string{"dnsmasq", "named", "unbound", "pihole-FTL", "coredns"} {
			if hasOwner(owners, known) {
				c.Action = fmt.Sprintf(
					"%s is already serving DNS on this port. Stop it, or move one of the two to a "+
						"different port — see docs/integrations.md for running DNS Daddy alongside "+
						"an existing resolver rather than instead of it.", known)
				return c
			}
		}
	}
	c.Action = fmt.Sprintf(
		"Find the owner with `sudo ss -lnup sport = :%[1]s` and `sudo ss -lntp sport = :%[1]s`, "+
			"then stop it or move DNS Daddy to another port.", portOf(addr))
	return c
}

// portOf extracts the port from a listen address, falling back to the whole
// string so the suggested command is never silently wrong about which port to
// look at.
func portOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 && i+1 < len(addr) {
		return addr[i+1:]
	}
	return addr
}

// formatElapsed renders a probe duration at a useful precision. Rounding
// everything to milliseconds turns a fast local exchange into "0s", which
// reads as a failure rather than as the good news it is.
func formatElapsed(d time.Duration) string {
	if d < time.Millisecond {
		return d.Round(10 * time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}

func hasOwner(owners []string, name string) bool {
	for _, o := range owners {
		if strings.Contains(strings.ToLower(o), strings.ToLower(name)) {
			return true
		}
	}
	return false
}

// UpstreamProbe is the outcome of testing one configured forwarder.
type UpstreamProbe struct {
	Spec    string
	Err     error
	Elapsed time.Duration
}

// Upstreams reports whether the resolver has anywhere to forward to.
//
// One dead forwarder out of two is a warning; all of them dead is a failure,
// because at that point no name resolves regardless of how healthy every other
// part of the system looks.
func Upstreams(probes []UpstreamProbe) []Check {
	if len(probes) == 0 {
		return []Check{{
			Section: SectionUpstream,
			Name:    "Upstream resolvers configured",
			Status:  StatusFail,
			Summary: "No upstream resolver is configured, so nothing can be resolved.",
			Action:  "Set dns.upstreams (DNSDADDY_UPSTREAMS).",
		}}
	}

	var checks []Check
	failed := 0
	for _, p := range probes {
		c := Check{Section: SectionUpstream, Name: "Upstream " + p.Spec}
		if p.Err != nil {
			failed++
			c.Status = StatusWarn
			c.Summary = fmt.Sprintf("Upstream %s did not answer.", p.Spec)
			c.Evidence = []string{"error: " + p.Err.Error()}
			c.Action = "Check outbound access to this address and port. DNS-over-TLS upstreams " +
				"use port 853, which some networks block."
		} else {
			c.Status = StatusPass
			c.Summary = fmt.Sprintf("Upstream %s answered in %s.", p.Spec, formatElapsed(p.Elapsed))
		}
		checks = append(checks, c)
	}

	if failed == len(probes) {
		checks = append(checks, Check{
			Section: SectionUpstream,
			Name:    "At least one upstream usable",
			Status:  StatusFail,
			Summary: "Every configured upstream failed, so no name can be resolved.",
			Action: "Until one answers, DNS Daddy will return SERVFAIL for everything that is not " +
				"already cached. Check this machine's own outbound DNS and network access.",
		})
	}
	return checks
}

// ThreatIndex reports whether the resolver is actually filtering.
//
// A resolver with an empty index answers every question and blocks nothing.
// It is a working resolver and it is not protecting anybody, and the
// difference must not be hidden behind a green tick.
func ThreatIndex(domains int, lastRefresh time.Time, now time.Time, staleAfter time.Duration) Check {
	c := Check{Section: SectionIntel, Name: "Threat index loaded"}

	if domains == 0 {
		c.Status = StatusFail
		c.Summary = "The threat index is empty: DNS Daddy is resolving but blocking nothing."
		c.Action = "On a fresh install the first feed download takes a few minutes. If it stays " +
			"empty, check outbound HTTPS and the Threat feeds page for the download error."
		return c
	}

	c.Evidence = []string{fmt.Sprintf("domains: %d", domains)}

	if lastRefresh.IsZero() {
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("%d domains are indexed, but no successful feed refresh is recorded.", domains)
		c.Action = "The index was loaded from cache. Run a refresh from the Threat feeds page."
		return c
	}

	age := now.Sub(lastRefresh)
	c.Evidence = append(c.Evidence, "last refresh: "+lastRefresh.Format(time.RFC3339))

	if age > staleAfter {
		c.Status = StatusWarn
		c.Summary = fmt.Sprintf("%d domains are indexed, but the intelligence is %s old.", domains, age.Round(time.Hour))
		c.Action = "Last-known-good data is still being enforced, so protection has not stopped — " +
			"but it is not current. Check the Threat feeds page for the download error."
		return c
	}

	c.Status = StatusPass
	c.Summary = fmt.Sprintf("%d domains indexed, refreshed %s ago.", domains, age.Round(time.Minute))
	return c
}
