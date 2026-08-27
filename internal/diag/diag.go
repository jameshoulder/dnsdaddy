// Package diag turns DNS Daddy's configuration and runtime state into
// findings an operator can act on.
//
// It exists because of a specific, reproducible failure: a resolver that
// reports itself healthy on every surface it has — the health endpoint, the
// dashboard, `docker ps` — while answering REFUSED to every client on the
// network. Liveness is not reachability, and nothing in the product used to
// say so.
//
// Everything here is pure: it takes state and returns findings, so the same
// analysis backs the startup log, the management API and `dnsdaddy doctor`,
// and every rule can be tested without a network.
package diag

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Status is a check's verdict.
type Status string

const (
	// StatusPass means the check found nothing wrong.
	StatusPass Status = "pass"
	// StatusWarn means something is probably wrong, or is right but worth
	// knowing about.
	StatusWarn Status = "warn"
	// StatusFail means something is definitely wrong and DNS will not work
	// as the operator intends.
	StatusFail Status = "fail"
)

// Check is one finding.
//
// Summary is a whole sentence, because it is read by somebody who is already
// having a bad time. Evidence carries the values the verdict was reached from,
// so the operator can disagree with us. Action is the next thing to do.
type Check struct {
	Section  string   `json:"section"`
	Name     string   `json:"name"`
	Status   Status   `json:"status"`
	Summary  string   `json:"summary"`
	Evidence []string `json:"evidence,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// Network is a configured network, reduced to what this analysis needs.
type Network struct {
	ID         string
	Name       string
	PolicyName string
	Enabled    bool
	CIDRs      []string
}

// ClientAccessInput is the state the client-access checks read.
type ClientAccessInput struct {
	// AllowedCIDRs is dns.allowed_client_cidrs as the operator wrote it,
	// kept in string form so the evidence quotes them back.
	AllowedCIDRs []string
	// Networks are the networks configured in the dashboard.
	Networks []Network
	// AllowPublicResolver is dns.allow_public_resolver.
	AllowPublicResolver bool
	// RefusedQueries is how many queries the ACL has rejected since start.
	// Nil means not measured — a caller with no running handler, such as a
	// startup check or `dnsdaddy doctor` in its own process. A pointer rather
	// than a sentinel so "none refused" and "never counted" stay distinct,
	// and so the counter needs no signed conversion on the way in.
	RefusedQueries *uint64
}

const sectionClientAccess = "CLIENT ACCESS"

// ClientAccess reports whether the networks configured in the dashboard can
// actually send queries.
//
// These are two independent settings that look like one. A Network says which
// policy an address gets once it is allowed to resolve;
// dns.allowed_client_cidrs says whether it may resolve at all. Adding a
// network does not permit it, and until this check existed nothing in the
// product told anyone that.
func ClientAccess(in ClientAccessInput) []Check {
	allowed, bad := parsePrefixes(in.AllowedCIDRs)

	var checks []Check

	for _, raw := range bad {
		checks = append(checks, Check{
			Section: sectionClientAccess,
			Name:    "Client ACL parses",
			Status:  StatusFail,
			Summary: fmt.Sprintf("%q in dns.allowed_client_cidrs is not a valid address or CIDR, so it permits nothing.", raw),
			Action:  "Correct or remove the entry.",
		})
	}

	switch {
	case len(allowed) == 0 && in.AllowPublicResolver:
		checks = append(checks, Check{
			Section:  sectionClientAccess,
			Name:     "Client ACL configured",
			Status:   StatusWarn,
			Summary:  "Any address on the internet may use this resolver.",
			Evidence: []string{"dns.allowed_client_cidrs is empty", "dns.allow_public_resolver is true"},
			Action: "An open resolver is found and conscripted into amplification attacks within days. " +
				"Set dns.allowed_client_cidrs to the networks you serve unless you genuinely intend this.",
		})
	case len(allowed) == 0:
		// The caveat belongs in the summary, not the action: a renderer that
		// only prints actions for non-passing checks would otherwise drop the
		// one sentence that makes this verdict conditional.
		checks = append(checks, Check{
			Section: sectionClientAccess,
			Name:    "Client ACL configured",
			Status:  StatusPass,
			Summary: "No client ACL is configured, so no query is refused on its source address. " +
				"That is safe only because the DNS listeners are loopback-only — config validation " +
				"refuses any other combination without dns.allow_public_resolver.",
		})
	default:
		checks = append(checks, Check{
			Section:  sectionClientAccess,
			Name:     "Client ACL configured",
			Status:   StatusPass,
			Summary:  fmt.Sprintf("%d address range(s) may send queries; everything else is REFUSED.", len(allowed)),
			Evidence: in.AllowedCIDRs,
		})
	}

	checks = append(checks, networkReachability(in, allowed)...)

	if in.RefusedQueries != nil && *in.RefusedQueries > 0 {
		n := *in.RefusedQueries
		checks = append(checks, Check{
			Section: sectionClientAccess,
			Name:    "Queries refused by the client ACL",
			Status:  StatusWarn,
			Summary: fmt.Sprintf("%d quer%s been REFUSED because the source address is not in dns.allowed_client_cidrs.", n, plural(n, "y has", "ies have")),
			Action: "If clients report that DNS is not working, this is why. The refused addresses are " +
				"not recorded — an unauthorised source could otherwise fill the log — so compare the " +
				"address your client actually has against the ranges above.",
		})
	}

	return checks
}

// networkReachability compares each configured network against the ACL.
func networkReachability(in ClientAccessInput, allowed []netip.Prefix) []Check {
	if len(in.Networks) == 0 {
		return nil
	}

	var checks []Check
	for _, n := range in.Networks {
		if !n.Enabled || len(n.CIDRs) == 0 {
			// A network with no CIDRs is the catch-all for clients matching
			// nothing; it has no address range to compare.
			continue
		}

		var refused, partial []string
		for _, raw := range n.CIDRs {
			p, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				continue
			}
			switch coverage(p, allowed) {
			case coverNone:
				refused = append(refused, raw)
			case coverPartial:
				partial = append(partial, raw)
			}
		}

		name := fmt.Sprintf("Network %q can resolve", n.Name)
		switch {
		case len(refused) > 0:
			checks = append(checks, Check{
				Section: sectionClientAccess,
				Name:    name,
				Status:  StatusFail,
				Summary: fmt.Sprintf("Network %q exists in the dashboard, but DNS queries from it are REFUSED.", n.Name),
				Evidence: []string{
					"network: " + strings.Join(refused, ", "),
					"policy: " + orNone(n.PolicyName),
					"dns.allowed_client_cidrs: " + strings.Join(in.AllowedCIDRs, ", "),
				},
				Action: fmt.Sprintf(
					"Adding a network assigns it a policy; it does not permit it to resolve. "+
						"Add %s to dns.allowed_client_cidrs (DNSDADDY_ALLOWED_CLIENT_CIDRS) if this is a "+
						"network you trust, then restart.", strings.Join(refused, " and ")),
			})
		case len(partial) > 0:
			checks = append(checks, Check{
				Section: sectionClientAccess,
				Name:    name,
				Status:  StatusWarn,
				Summary: fmt.Sprintf("Only part of network %q may resolve; the rest is REFUSED.", n.Name),
				Evidence: []string{
					"partly permitted: " + strings.Join(partial, ", "),
					"dns.allowed_client_cidrs: " + strings.Join(in.AllowedCIDRs, ", "),
				},
				Action: "Widen dns.allowed_client_cidrs to cover the whole range, or narrow the network " +
					"to the part that is permitted, so the two agree.",
			})
		default:
			checks = append(checks, Check{
				Section:  sectionClientAccess,
				Name:     name,
				Status:   StatusPass,
				Summary:  fmt.Sprintf("Network %q is permitted to send queries.", n.Name),
				Evidence: []string{strings.Join(n.CIDRs, ", ") + " → policy " + orNone(n.PolicyName)},
			})
		}
	}
	return checks
}

type cover int

const (
	coverNone cover = iota
	coverPartial
	coverFull
)

// coverage reports how much of p the allowed set permits.
//
// Full coverage is decided by single-prefix containment: some allowed prefix
// is no more specific than p and contains its base address. That is sound but
// not complete — two allowed prefixes could between them cover p without
// either containing it (10.0.0.0/9 and 10.128.0.0/9 covering 10.0.0.0/8).
// Such a configuration is reported as partial rather than full, which
// over-warns in a rare case instead of under-warning in a common one. A
// diagnostic that misses a real outage is worse than one that asks a question.
func coverage(p netip.Prefix, allowed []netip.Prefix) cover {
	overlaps := false
	for _, a := range allowed {
		if a.Addr().Is4() != p.Addr().Is4() {
			continue
		}
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return coverFull
		}
		// More specific than p: it can only cover part of it.
		if p.Contains(a.Addr()) {
			overlaps = true
		}
	}
	if overlaps {
		return coverPartial
	}
	return coverNone
}

// parsePrefixes splits a CIDR list into what parsed and what did not, so a
// typo is reported rather than silently permitting less than intended.
func parsePrefixes(cidrs []string) (ok []netip.Prefix, bad []string) {
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				bad = append(bad, raw)
				continue
			}
			ok = append(ok, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			bad = append(bad, raw)
			continue
		}
		ok = append(ok, p.Masked())
	}
	return ok, bad
}

// Worst returns the most severe status across checks, or StatusPass when there
// are none.
func Worst(checks []Check) Status {
	worst := StatusPass
	for _, c := range checks {
		switch c.Status {
		case StatusFail:
			return StatusFail
		case StatusWarn:
			worst = StatusWarn
		}
	}
	return worst
}

// Failures returns just the checks that failed, in section order.
func Failures(checks []Check) []Check {
	var out []Check
	for _, c := range checks {
		if c.Status == StatusFail {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Section < out[j].Section })
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func plural(n uint64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
