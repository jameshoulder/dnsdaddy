package reclab

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// Signed runs a built, signed hierarchy as one authoritative server per zone.
//
// This is the arrangement that makes native recursion testable end to end.
// internal/daddybound/lab constructs and signs whole hierarchies and can serve
// one from a single address, which is what a validator reading records needs. A
// resolver needs the other shape: separate servers that refer it downwards, so
// that resolution is resolution rather than a lookup. Both read the same signed
// zones, so a disagreement between the two paths is a disagreement about
// resolution and not about the data.
//
// Two things are the harness's rather than the zones'.
//
// Nameserver names are rewritten, one per zone, to a name inside the zone being
// delegated. The built hierarchy names a single nameserver for every child
// because it never needed addresses; a resolver does need them, and an
// out-of-bailiwick nameserver name with no address anywhere in the hierarchy is
// unresolvable. Substituting the name is safe precisely because a delegation's
// NS RRset lives on the parent side of the cut and is never signed — no
// signature covers what is being changed, and a validator that expected one
// would reject every real delegation on the Internet.
//
// Addresses come from the running servers, filled in as in-bailiwick glue.
// A zone was written before any server existed and cannot know where one
// listens.
//
// Everything a validator actually checks — DNSKEY, DS, RRSIG, the NSEC and
// NSEC3 chains, the signed denial that proves an insecure delegation — is
// served exactly as lab built it.
func Signed(t testing.TB, h *lab.Hierarchy) *Hierarchy {
	t.Helper()

	zones := make([]Zone, 0, len(h.Zones))
	for _, z := range h.Zones {
		name := dns.CanonicalName(z.Name)
		children := h.Delegations(name)

		delegations := make(map[string][]string, len(children))
		for child := range children {
			// One nameserver per child, inside the child. See the comment
			// above on why rewriting this is not tampering.
			delegations[child] = []string{nameserverFor(child)}
		}

		zones = append(zones, Zone{
			Name:        name,
			Delegations: delegations,
			Answer:      signedAnswer(h, name, delegations),
		})
	}
	return Start(t, zones...)
}

// nameserverFor is the in-bailiwick nameserver name this harness gives a zone.
func nameserverFor(zone string) string {
	if zone == "." {
		return "ns."
	}
	return "ns." + dns.CanonicalName(zone)
}

// signedAnswer builds the reply callback for one zone.
func signedAnswer(h *lab.Hierarchy, zone string, delegations map[string][]string) func(string, uint16, bool) Reply {
	return func(qname string, qtype uint16, do bool) Reply {
		resp, ok := h.RespondFrom(zone, qname, qtype, do)
		if !ok {
			// This zone does not serve the name. A real server says REFUSED,
			// which the resolver reads as a lame delegation rather than as
			// an answer — the distinction the resolver's failover depends on.
			return Reply{Rcode: dns.RcodeRefused}
		}

		child, referral := referralTarget(delegations, qname, qtype)
		out := Reply{
			Rcode:     resp.Rcode,
			Answer:    resp.Answer,
			Authority: rewriteNS(resp.Authority, child, referral),
			// A referral is the one reply an authoritative server sends with
			// AA clear: the data belongs to the zone below the cut.
			Authoritative: !referral,
		}
		return out
	}
}

// referralTarget reports whether this question falls below a delegation, and
// which one.
//
// A DS query at a delegation point is the exception: that record lives on the
// parent side of the cut, so the parent answers it rather than referring. Get
// this wrong and a resolver can never learn any zone's DS, which reads as every
// zone being insecure.
func referralTarget(delegations map[string][]string, qname string, qtype uint16) (string, bool) {
	name := dns.CanonicalName(qname)
	best := ""
	for child := range delegations {
		if !dns.IsSubDomain(child, name) {
			continue
		}
		if child == name && qtype == dns.TypeDS {
			continue
		}
		if len(child) > len(best) {
			best = child
		}
	}
	return best, best != ""
}

// rewriteNS replaces the nameserver names in a referral with the one this
// harness runs a server for, leaving every other record untouched.
func rewriteNS(authority []dns.RR, child string, referral bool) []dns.RR {
	if !referral || len(authority) == 0 {
		return authority
	}
	out := make([]dns.RR, 0, len(authority))
	replaced := false
	for _, rr := range authority {
		ns, isNS := rr.(*dns.NS)
		if !isNS || dns.CanonicalName(ns.Hdr.Name) != child {
			out = append(out, rr)
			continue
		}
		if replaced {
			// One nameserver per zone. Collapsing several NS records into
			// one keeps the referral honest rather than naming the same
			// server twice.
			continue
		}
		replaced = true
		copied := *ns
		copied.Ns = nameserverFor(child)
		out = append(out, &copied)
	}
	return out
}
