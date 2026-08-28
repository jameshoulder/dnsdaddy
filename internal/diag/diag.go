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
	"sort"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
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
	// AllowResolver is the network's own "allow this network to use DNS
	// Daddy" permission, as set in the dashboard.
	AllowResolver bool
	CIDRs         []string
}

// ClientAccessInput is the state the client-access checks read.
type ClientAccessInput struct {
	// ACL is the effective client ACL: the bootstrap list from configuration
	// unioned with the dashboard-managed permissions. Reporting one source
	// alone was the previous behaviour and was actively misleading once the
	// dashboard could grant access — an operator would be told their network
	// was refused by a resolver that was serving it.
	ACL *clientacl.Set
	// Networks are the networks configured in the dashboard.
	Networks []Network
	// Stale reports that the live ACL could not be reloaded after a change, so
	// what is being enforced may be older than what is stored. Nothing else
	// can detect this: once a network is deleted there is no row left for the
	// reachability checks to compare a stale grant against.
	//
	// Nil means not measured, which is a third answer and not the same as
	// false. It lives in the running daemon's memory, so `dnsdaddy doctor`
	// learns it from the health endpoint and cannot learn it at all when that
	// endpoint is unreachable. Reporting "not stale" there would be a
	// diagnostic quietly passing a check it never ran.
	Stale *bool
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
// Two settings decide this, and until they were brought together in the
// dashboard they looked like one. A Network says which policy an address gets
// once it is allowed to resolve; the client ACL says whether it may resolve at
// all. Both are now set from the same screen, and this check is what says so
// when they disagree.
func ClientAccess(in ClientAccessInput) []Check {
	acl := in.ACL
	if acl == nil {
		acl = clientacl.Compute(nil, false, nil)
	}

	var checks []Check

	for _, raw := range acl.Invalid() {
		checks = append(checks, Check{
			Section: sectionClientAccess,
			Name:    "Client ACL parses",
			Status:  StatusFail,
			Summary: fmt.Sprintf("%q is not a valid address or CIDR, so it permits nothing.", raw),
			Action:  "Correct or remove the entry.",
		})
	}

	shadowed := make(map[string]bool, len(acl.Shadowed()))
	for _, sh := range acl.Shadowed() {
		shadowed[sh.NetworkID] = true
	}

	switch {
	case in.Stale == nil:
		checks = append(checks, Check{
			Section: sectionClientAccess,
			Name:    "Client ACL is in force",
			Status:  StatusWarn,
			Summary: "Whether the rules below are the ones actually being enforced could not be " +
				"determined.",
			Action: "That state lives in the running resolver, and its API did not answer — see " +
				"the WEB INTERFACE section. Everything else in this section is read from your " +
				"configuration and database, which is what SHOULD be enforced rather than what is.",
		})
	case *in.Stale:
		checks = append(checks, Check{
			Section: sectionClientAccess,
			Name:    "Client ACL is in force",
			Status:  StatusFail,
			Summary: "A change to which networks may use this resolver could not be applied, " +
				"so the rules below may be older than what is stored.",
			Action: "A permission you granted may not be working, and — the reason this is a " +
				"failure rather than a warning — one you revoked may still be honoured. Make " +
				"any change under Networks to force a reload, or restart DNS Daddy. The log " +
				"records why the reload failed.",
		})
	}

	checks = append(checks, aclSummary(acl))
	checks = append(checks, publicAccessWarnings(acl)...)
	checks = append(checks, networkReachability(in, acl, shadowed)...)
	checks = append(checks, shadowNotes(acl)...)

	if in.RefusedQueries != nil && *in.RefusedQueries > 0 {
		n := *in.RefusedQueries
		checks = append(checks, Check{
			Section: sectionClientAccess,
			Name:    "Queries refused by the client ACL",
			Status:  StatusWarn,
			Summary: fmt.Sprintf("%d quer%s been REFUSED because the source address is not permitted to use this resolver.", n, plural(n, "y has", "ies have")),
			Action: "If clients report that DNS is not working, this is why. The refused addresses " +
				"are not recorded — an unauthorised source could otherwise fill the log — so " +
				"compare the address your client actually has against the ranges above, and add " +
				"it under Networks with \"Allow this network to use DNS Daddy\" ticked.",
		})
	}

	return checks
}

// aclSummary states who may resolve, and from which of the two sources.
func aclSummary(acl *clientacl.Set) Check {
	c := Check{Section: sectionClientAccess, Name: "Client ACL configured"}

	if acl.Unrestricted() {
		if acl.AllowPublicResolver() {
			c.Status = StatusWarn
			c.Summary = "Any address on the internet may use this resolver."
			c.Evidence = []string{
				"dns.allowed_client_cidrs is empty",
				"dns.allow_public_resolver is true",
			}
			c.Action = "An open resolver is found and conscripted into amplification attacks " +
				"within days. Set dns.allowed_client_cidrs to the networks you serve unless you " +
				"genuinely intend this."
			return c
		}
		// The caveat belongs in the summary, not the action: a renderer that
		// only prints actions for non-passing checks would otherwise drop the
		// one sentence that makes this verdict conditional.
		c.Status = StatusPass
		c.Summary = "No client ACL is configured, so no query is refused on its source address. " +
			"That is safe only because the DNS listeners are loopback-only — config validation " +
			"refuses any other combination without dns.allow_public_resolver."
		if n := len(acl.Grants()); n > 0 {
			c.Evidence = []string{fmt.Sprintf(
				"%d network range(s) are permitted in the dashboard; they add nothing while "+
					"everything is already accepted, and take effect if an ACL is configured", n)}
		}
		return c
	}

	c.Status = StatusPass
	c.Summary = fmt.Sprintf("%d address range(s) may send queries; everything else is REFUSED.",
		len(acl.Effective()))
	c.Evidence = []string{
		"from configuration (" + clientacl.SourceBootstrap + "): " + orNone(strings.Join(acl.Bootstrap(), ", ")),
		"from the dashboard: " + orNone(strings.Join(grantCIDRs(acl.Grants()), ", ")),
	}
	return c
}

// publicAccessWarnings names each permitted range that is reachable from the
// internet.
//
// Deliberately a warning that never resolves itself: DNS Daddy cannot see a
// cloud provider's security group or a host firewall, so it can report what it
// has been told to accept and nothing more. Claiming the port was open, or
// closed, would be inventing a measurement.
func publicAccessWarnings(acl *clientacl.Set) []Check {
	public := acl.PublicGrants()
	if len(public) == 0 {
		return nil
	}
	var ranges []string
	for _, g := range public {
		ranges = append(ranges, fmt.Sprintf("%s (%s)", g.CIDR, g.Source))
	}
	// The count is of distinct ranges; the evidence names every source. One
	// range listed in configuration and ticked on a network is two things to
	// go and change and one exposure, and counting it twice would make adding
	// a redundant permission look like the resolver had been opened wider.
	return []Check{{
		Section:  sectionClientAccess,
		Name:     "Publicly routable ranges are permitted",
		Status:   StatusWarn,
		Summary:  fmt.Sprintf("%d publicly routable range(s) are permitted to query DNS Daddy.", len(acl.PublicPrefixes())),
		Evidence: ranges,
		Action: "That is a supported deployment, and it is the right one for a VPS serving your " +
			"own sites. Confirm your provider's firewall or security group restricts TCP and UDP " +
			"port 53 to those addresses — DNS Daddy cannot see that firewall and has not checked " +
			"it, and it does not change it for you.",
	}}
}

// shadowNotes reports networks that can resolve without their own permission.
func shadowNotes(acl *clientacl.Set) []Check {
	var checks []Check
	for _, sh := range acl.Shadowed() {
		checks = append(checks, Check{
			Section: sectionClientAccess,
			Name:    fmt.Sprintf("Network %q resolves via a wider range", sh.NetworkName),
			Status:  StatusWarn,
			Summary: fmt.Sprintf(
				"Network %q is not itself permitted to use DNS Daddy, but its clients can resolve anyway.",
				sh.NetworkName),
			Evidence: []string{
				sh.CIDR + " is inside " + sh.CoveredBy,
				"permitted by: " + sh.Source,
			},
			Action: "Client access has no deny rules: a permission grants, and a narrower network " +
				"without one does not carve a hole in it. If these clients should not resolve, " +
				"narrow or remove the wider range rather than leaving this network unticked.",
		})
	}
	return checks
}

func grantCIDRs(grants []clientacl.Grant) []string {
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		out = append(out, g.CIDR)
	}
	return out
}

// networkReachability compares each configured network against the effective ACL.
//
// An unrestricted ACL is not a narrow one, and the difference matters:
// admission returns true the moment nothing is configured, whatever the source
// address. Comparing networks against an empty prefix list would report every
// one of them as REFUSED when every one of them is in fact permitted — a false
// failure on two supported configurations, a deliberate public resolver and
// loopback-only listeners, and one that made `dnsdaddy doctor` exit non-zero on
// a working deployment.
//
// Whether an unrestricted ACL is *wise* is a separate question, and aclSummary
// answers it.
func networkReachability(in ClientAccessInput, acl *clientacl.Set, shadowed map[string]bool) []Check {
	if len(in.Networks) == 0 || acl.Unrestricted() {
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
			p, err := clientacl.ParsePrefix(raw)
			if err != nil {
				continue
			}
			switch acl.Cover(p) {
			case clientacl.CoverNone:
				refused = append(refused, raw)
			case clientacl.CoverPartial:
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
					"permitted: " + strings.Join(acl.Effective(), ", "),
				},
				Action: refusedAction(n),
			})
		case len(partial) > 0:
			checks = append(checks, Check{
				Section: sectionClientAccess,
				Name:    name,
				Status:  StatusWarn,
				Summary: fmt.Sprintf("Only part of network %q may resolve; the rest is REFUSED.", n.Name),
				Evidence: []string{
					"partly permitted: " + strings.Join(partial, ", "),
					"permitted: " + strings.Join(acl.Effective(), ", "),
				},
				Action: "Tick \"Allow this network to use DNS Daddy\" on this network so its whole " +
					"range is permitted, or narrow the network to the part that already is, so the " +
					"two agree.",
			})
		case shadowed[n.ID]:
			// Reachable, but not by its own permission. shadowNotes says so
			// precisely; a bare "is permitted to send queries" beside that
			// would contradict it in the reader's eye.

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

// refusedAction says how to fix a refused network, and the answer now depends
// on whether the operator has already asked for it.
//
// The old advice — edit DNSDADDY_ALLOWED_CLIENT_CIDRS and restart — is still
// correct for a headless deployment, and is still wrong as the first thing to
// tell somebody sitting in front of the dashboard with a tick-box that does
// the same job without a restart.
func refusedAction(n Network) string {
	if !n.AllowResolver {
		return "Adding a network assigns it a policy; it does not by itself permit it to resolve. " +
			"Open Networks, edit this network and tick \"Allow this network to use DNS Daddy\". " +
			"It takes effect immediately — no restart."
	}
	return "This network is marked as permitted, so the effective ACL above should already " +
		"include it. If it does not, the permission has not been reloaded: check the DNS Daddy " +
		"log for a client-access reload error, and report this."
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
