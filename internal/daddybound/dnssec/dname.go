package dnssec

import (
	"strings"

	"github.com/miekg/dns"
)

// DNAME redirection, and the one place in this engine where the answer is
// computed rather than read.
//
// A DNAME at some ancestor of the queried name redirects everything beneath
// it (RFC 6672 §2.2). A server answering such a query sends the DNAME
// together with a CNAME it synthesised for the queried name — and RFC 6672
// §5.3.1 is explicit about what that CNAME is worth:
//
//	In any response, a signed DNAME RR indicates a non-terminal redirection
//	of the query. There might or might not be a server-synthesized CNAME in
//	the answer section; if there is, the CNAME will never be signed. For a
//	DNSSEC validator, verification of the DNAME RR and then that the CNAME
//	was properly synthesized is sufficient proof.
//
// "will never be signed" is the whole difficulty. A validator that treats the
// synthesised CNAME as an ordinary alias finds an unsigned RRset and reports
// Bogus for every DNAME-using name in the DNS — which is what this engine did
// before this file existed. A validator that treats it as *trustworthy*
// because a signed DNAME was nearby has done worse: the CNAME's target is
// then whatever the sender wrote, authenticated by a signature over a
// different record.
//
// So the synthesised CNAME is not read at all. The DNAME RRset is
// authenticated, the substitution is performed here from the authenticated
// owner and target, and the result is where the chain goes next. Whatever the
// sender put in the CNAME is ignored, which makes tampering with it a no-op
// rather than something to detect.

// validateDname authenticates a DNAME that covers qname and returns the name
// the query is redirected to.
//
// Returns ok=false when the answer section holds no DNAME that could apply,
// which is the ordinary case and costs one pass over the answer.
func (w *walk) validateDname(zone *zoneState, qname string, resp Response) (aliasOutcome, bool) {
	owner, ok := closestDnameOwner(resp.Answer, qname, zone.name)
	if !ok {
		return aliasOutcome{}, false
	}

	step := ValidationStep{Kind: StepRRset, Zone: zone.name, Name: owner, RRType: dns.TypeDNAME}
	data, sigs := SplitSignaturesAt(resp.Answer, owner, dns.TypeDNAME)

	// RFC 6672 §2.4: "DNAME is a singleton type, meaning only one DNAME is
	// allowed per name." Two would leave a validator choosing which
	// redirection to follow out of a response an attacker ordered, which is
	// the same defect the CNAME path refuses for the same reason.
	if len(data) != 1 {
		return aliasOutcome{result: w.rec.verdict(w.rec.fail(step, ReasonAliasAmbiguous))}, true
	}
	dname, isDname := data[0].(*dns.DNAME)
	if !isDname {
		return aliasOutcome{result: w.rec.verdict(w.rec.fail(step, ReasonMalformedRecord))}, true
	}

	set, reason := NewRRset(data)
	if reason != ReasonNone {
		return aliasOutcome{result: w.rec.verdict(w.rec.fail(step, reason))}, true
	}
	accepted, reason := w.authenticateSigned(set, sigs, zone.name, zone.keys)
	if reason != ReasonNone {
		return aliasOutcome{result: w.rec.verdict(reason)}, true
	}

	// A DNAME can be wildcard-expanded like anything else, and an expanded
	// one redirects every name under the encloser rather than one name — so
	// if anything, the proof matters more here than for an address.
	if res, done := w.wildcardProof(zone, owner, dns.TypeDNAME, accepted, resp); done {
		return aliasOutcome{result: res}, true
	}

	target, reason := dnameSubstitute(qname, owner, dns.CanonicalName(dname.Target))
	if reason != ReasonNone {
		return aliasOutcome{result: w.rec.verdict(w.rec.fail(step, reason))}, true
	}

	step.Note = "DNAME redirection to " + target
	w.rec.ok(step)
	return aliasOutcome{result: w.rec.secure(), followTo: target}, true
}

// closestDnameOwner finds the DNAME in an answer section that applies to
// qname, if any.
//
// Two conditions, and both are load-bearing.
//
// The owner must be a *proper* ancestor of qname. RFC 6672 §2.3: "the owner
// name of a DNAME is not redirected itself" — a query for the DNAME's own
// name is answered from that name, not substituted. Allowing the equal case
// would turn a query for the owner into an infinite redirection to itself.
//
// The owner must also be at or below the zone whose keys will authenticate
// it. Without that check a response could carry a DNAME owned by some
// ancestor zone, have it verified against the wrong zone's keys — or, worse,
// have an out-of-zone name accepted as an ancestor and redirect a query out
// of the zone that was supposed to answer it. The signer check inside
// authenticateSigned catches the signature, but the owner check is what stops
// the question being asked in the first place.
//
// The deepest qualifying owner wins, per RFC 1034 §4.3.2's "start matching
// down, label by label": a shallower DNAME does not get to pre-empt a
// closer one, which is what an attacker adding a DNAME high in the zone
// would be trying to do. Depth is measured in labels, so the result is a
// function of the names rather than of the order the records arrived in.
func closestDnameOwner(answer []dns.RR, qname, zone string) (string, bool) {
	qname = dns.CanonicalName(qname)
	zone = dns.CanonicalName(zone)

	best, bestLabels := "", -1
	for _, rr := range answer {
		if rr.Header().Rrtype != dns.TypeDNAME {
			continue
		}
		owner := dns.CanonicalName(rr.Header().Name)
		if !isProperSubDomain(owner, qname) || !isSubDomainOf(zone, owner) {
			continue
		}
		if n := dns.CountLabel(owner); n > bestLabels {
			best, bestLabels = owner, n
		}
	}
	return best, bestLabels >= 0
}

// dnameSubstitute performs RFC 6672 §2.2's substitution: the labels of qname
// that match owner are replaced by target.
//
// Only whole labels are replaced, which is why this works on the label
// boundary rather than on the string. "ab.example.com." does not match a
// DNAME owned by "b.example.com." even though one string is a suffix of the
// other, and a suffix-of-string implementation would redirect it — RFC 6672's
// own substitution table lists that case as "<no match>" precisely because it
// is the mistake to make.
//
// The caller has already established that owner is a proper ancestor, so the
// remaining failure is length: §2.2 notes the result can exceed the legal 255
// octets, in which case a server returns YXDOMAIN. There is nothing to
// authenticate about a name that cannot exist, so it is refused here.
func dnameSubstitute(qname, owner, target string) (string, Reason) {
	qname = dns.CanonicalName(qname)
	owner = dns.CanonicalName(owner)
	target = dns.CanonicalName(target)

	if !isProperSubDomain(owner, qname) {
		return "", ReasonDnameNoMatch
	}
	prefix := qname[:len(qname)-len(owner)]
	if !strings.HasSuffix(prefix, ".") {
		// Unreachable while isProperSubDomain is label-aware, and asserted
		// rather than assumed: the whole correctness of the substitution
		// rests on prefix ending at a label boundary.
		return "", ReasonDnameNoMatch
	}

	result := prefix + target
	if target == "." {
		// The root as a target leaves the prefix as the whole name.
		// RFC 6672 §2.2's table: "shortloop.x.x." under owner "x." and
		// target "." gives "shortloop.x." — the prefix, already dotted.
		result = prefix
	}
	if _, ok := dns.IsDomainName(result); !ok {
		return "", ReasonDnameTooLong
	}
	return result, ReasonNone
}
