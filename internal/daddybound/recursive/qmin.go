package recursive

import (
	"strings"

	"github.com/miekg/dns"
)

// QNAME minimisation: tell each level only what it needs to answer.
//
// Without it, resolving www.private-project.example.com sends that entire name
// to the root and to com, neither of which needs it — the root's only job is
// to say where com is. That is a privacy leak to every server on the path, and
// it is a property of resolver architecture rather than something a policy can
// add afterwards.
//
// The approach here is the conservative one: ask for the next label down as
// an NS query, and descend on the referral. A server that answers an empty
// NOERROR for an intermediate name has told us the name exists with no NS
// records, which is not an answer to the client's question — resolve.go
// re-asks unminimised at that level rather than treating it as NODATA.

// minimisedQuestion returns the question to send to zone's servers when
// resolving qname/qtype.
//
// At or one label below the target it returns the real question: there is
// nothing left to hide, and sending an NS probe for the final name would cost
// a round trip for no privacy gain.
func minimisedQuestion(zone, qname string, qtype uint16) (string, uint16) {
	zone = dns.CanonicalName(zone)
	qname = dns.CanonicalName(qname)

	if zone == qname {
		return qname, qtype
	}
	if !inBailiwick(zone, qname) {
		return qname, qtype
	}

	next := nextLabel(zone, qname)
	if next == "" || next == qname {
		return qname, qtype
	}
	return next, dns.TypeNS
}

// nextLabel returns qname truncated to one label more than zone.
//
//	zone  com.
//	qname www.example.com.
//	   -> example.com.
func nextLabel(zone, qname string) string {
	if zone == qname {
		return qname
	}
	rest := strings.TrimSuffix(qname, zone)
	rest = strings.TrimSuffix(rest, ".")
	if rest == "" {
		return qname
	}
	labels := dns.SplitDomainName(rest)
	if len(labels) == 0 {
		return qname
	}
	last := labels[len(labels)-1]
	if zone == "." {
		return last + "."
	}
	return last + "." + zone
}
