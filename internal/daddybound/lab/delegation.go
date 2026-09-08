package lab

import "github.com/miekg/dns"

// Delegation records: what a parent zone says about a child, and how the two
// kinds of delegation differ.
//
// A secure delegation publishes NS and a signed DS. An insecure one
// publishes NS and, crucially, a signed *denial* that any DS exists. The
// second is the only honest route to RFC 4033's Insecure, so the lab has to
// be able to build it.

// delegationCovering returns the delegated child zone at or above qname
// within zone, or "" when qname is not below a cut.
func (h *Hierarchy) delegationCovering(zone *Zone, qname string) string {
	best := ""
	for child := range zone.delegations {
		if !dns.IsSubDomain(child, qname) {
			continue
		}
		if best == "" || dns.CountLabel(child) > dns.CountLabel(best) {
			best = child
		}
	}
	return best
}

// referral builds the authority section of a delegation response.
//
// The NS RRset is deliberately unsigned: a delegation's NS records live on
// the parent side of the cut and are not authoritative data there, so no
// signer signs them. A validator that expected a signature here would reject
// every real delegation on the Internet.
//
// What *is* signed is either the DS RRset or the denial that one exists, and
// that is the whole difference between a secure and an insecure delegation.
func (h *Hierarchy) referral(zone *Zone, child string, wantDNSSEC bool) []dns.RR {
	var out []dns.RR
	if ns := zone.sets[setKey{name: child, rrtype: dns.TypeNS}]; len(ns) > 0 {
		out = append(out, filterSignatures(ns, false)...)
	}

	if ds := zone.sets[setKey{name: child, rrtype: dns.TypeDS}]; len(ds) > 0 {
		out = append(out, filterSignatures(ds, wantDNSSEC)...)
		return out
	}

	// No DS: an insecure delegation. The parent must prove the absence
	// rather than merely omit it, which is what the denial records do.
	if wantDNSSEC {
		out = append(out, h.denialFor(zone, child, dns.TypeDS, dns.RcodeSuccess)...)
	}
	return out
}
