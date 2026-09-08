package dnssec

import "github.com/miekg/dns"

// Where the chain walk consults a denial proof.
//
// Three places need one, and they are here together because what they have in
// common — a response claiming an absence, and an obligation to disbelieve it
// until it is proved — is easier to see in one file than spread across the
// walk.

// noDSAtDelegation decides what a missing DS RRset means.
//
// Two situations produce a response with no DS, and until this milestone
// Daddybound could not tell them apart:
//
//   - child is not a zone cut at all, which is true of nearly every name a
//     chain walk passes through;
//   - child is a zone cut with no DS — an insecure delegation — and
//     everything below it is legitimately unsigned.
//
// The difference is now decided by evidence rather than by assumption, and
// the evidence is the parent's signed NSEC at that name. RFC 4035 §5.2 says
// what the response owed:
//
//	If the referral from the parent zone did not contain a DS RRset, the
//	response should have included a signed NSEC RRset proving that no DS
//	RRset exists for the delegated name.
//
// Where that proof is absent, the walk keeps v0.1's deliberately one-sided
// assumption rather than inventing a verdict — see the default branch.
func (w *walk) noDSAtDelegation(zone *zoneState, child string, resp Response) (*zoneState, ValidationResult, bool) {
	proof := w.collectDenial(zone, resp.Authority)
	step := ValidationStep{Kind: StepDenial, Zone: zone.name, Name: child, RRType: dns.TypeDS}

	switch w.dsDenialFrom(&proof, child) {
	case dsDenialInsecure:
		// NS present, DS absent, SOA absent: an authenticated insecure
		// delegation. This is the one and only route to RFC 4033 §5's
		// Insecure, and it is reached by having proved something rather
		// than by having failed to prove something else.
		step.Note = "NS present and DS absent in an authenticated parent NSEC: an insecure delegation"
		w.rec.ok(step)
		return nil, w.rec.insecure(), true

	case dsDenialNotADelegation:
		step.Note = "the name exists with neither NS nor DS, so it is not a zone cut"
		w.rec.ok(step)
		return nil, ValidationResult{}, false

	case dsDenialNameAbsent:
		// The name does not exist, so it cannot be a delegation. Whatever
		// was asked for below it does not exist either, and the answer step
		// will demand that proof in its own right.
		step.Note = "the name does not exist, so it is not a zone cut"
		w.rec.ok(step)
		return nil, ValidationResult{}, false

	case dsDenialContradicted:
		// The zone's own signed records say a DS is published here, and the
		// response omitted it. Somebody removed it in transit.
		return nil, w.rec.verdict(w.rec.fail(step, ReasonDenialContradicted)), true

	default:
		// No usable proof either way. The walk assumes "not a zone cut" and
		// continues in the same zone, which is v0.1's behaviour and is kept
		// deliberately.
		//
		// The bias is one-sided, and that is the whole argument for it. If
		// the assumption is wrong — this really was an insecure delegation
		// — the data below is unsigned, no signature from a trusted zone
		// covers it, and the answer is reported Bogus where a complete
		// proof would have given Insecure. That is a false Bogus: it
		// refuses data that was fine.
		//
		// The converse cannot happen. Concluding Secure requires a
		// signature made by a key in an apex DNSKEY RRset this walk has
		// already authenticated, and an attacker below an insecure
		// delegation does not hold one. So the cost is paid in refusals and
		// never in false Secures.
		//
		// Returning Indeterminate here instead would be worse, not better:
		// almost no name a walk passes through is a zone cut, so it would
		// turn ordinary validation into "cannot tell", and an enforcing
		// resolver reading Indeterminate as "allow" would then accept
		// forged data.
		step.Note = "no authenticated proof either way; assuming this is not a zone cut, which can only cost a false Bogus"
		w.rec.skip(step, proof.unreadOverReported(proof.denialUnavailable()))
		return nil, ValidationResult{}, false
	}
}

// validateDenial authenticates a response that answers with an absence.
//
// The rcode says what the server claims and the authority section is where it
// has to prove it, so the two are checked against each other: an NXDOMAIN
// needs a name-error proof, a NOERROR with an empty answer needs a NODATA
// proof, and a proof of the wrong one does not substitute for the other.
//
// A proved absence is Secure. That is not a technicality — RFC 4035 §5.4's
// whole subject is authenticating denial, and a validator that could only
// ever say Secure about records that exist would have nothing to say about
// the majority of hostile answers, which claim that something does not.
func (w *walk) validateDenial(zone *zoneState, qname string, rrtype uint16, resp Response) ValidationResult {
	proof := w.collectDenial(zone, resp.Authority)
	step := ValidationStep{Kind: StepDenial, Zone: zone.name, Name: qname, RRType: rrtype}

	var reason Reason
	switch resp.Rcode {
	case dns.RcodeNameError:
		step.Note = "NXDOMAIN: the name must be covered, and so must the wildcard that could have answered"
		if proof.hasNSEC3() {
			reason = proof.nsec3.proveNameError(qname)
		} else {
			reason = proof.proveNameError(qname, rrtype)
		}
	case dns.RcodeSuccess:
		step.Note = "NODATA: the matching denial record must omit both the queried type and CNAME"
		if proof.hasNSEC3() {
			reason = proof.nsec3.proveNoData(qname, rrtype)
		} else {
			reason = proof.proveNoData(qname, rrtype)
		}
	default:
		// SERVFAIL, REFUSED and the rest are not claims about the zone's
		// contents, so there is nothing here to authenticate and nothing to
		// accuse the zone of. The rcode is deliberately not turned into a
		// reason: an rcode is a transport-level outcome and this taxonomy
		// describes evidence.
		step.Note = "the response carries neither an answer nor a denial this validator can authenticate"
		return w.rec.indeterminate(w.rec.skip(step, ReasonUnknown))
	}

	if reason != ReasonNone {
		// A proof that was cut short cannot support an accusation. See
		// denialProof.unreadOverReported.
		return w.rec.verdict(w.rec.fail(step, proof.unreadOverReported(reason)))
	}
	w.rec.ok(step)
	return w.rec.secure()
}

// wildcardProof demands the extra proof a wildcard-expanded answer owes.
//
// R-DEN-11, RFC 4035 §5.3.4: an owner name with more labels than the
// verifying RRSIG's Labels field was produced by wildcard expansion, and the
// signature alone does not establish that the expansion was legitimate. The
// same signed wildcard answers for every name under its encloser, so without
// the extra proof an attacker replays one over a name that has its own
// records and every signature still verifies.
//
// Returns done=true only when it has a terminal result. A non-expanded answer
// — the overwhelming majority — returns immediately and costs one comparison.
func (w *walk) wildcardProof(zone *zoneState, qname string, rrtype uint16, sig *dns.RRSIG, resp Response) (ValidationResult, bool) {
	if sig == nil {
		return ValidationResult{}, false
	}
	labels := dns.CountLabel(dns.CanonicalName(qname))
	if labels <= int(sig.Labels) {
		return ValidationResult{}, false
	}

	step := ValidationStep{
		Kind: StepDenial, Zone: zone.name, Name: qname, RRType: rrtype,
		Note: "wildcard-expanded answer: the name it expanded over must be shown not to exist",
	}
	proof := w.collectDenial(zone, resp.Authority)
	reason := proof.proveWildcardAnswer(qname, int(sig.Labels), rrtype)
	if proof.hasNSEC3() {
		reason = proof.nsec3.proveWildcardAnswer(qname, int(sig.Labels))
	}
	if reason != ReasonNone {
		return w.rec.verdict(w.rec.fail(step, proof.unreadOverReported(reason))), true
	}
	w.rec.ok(step)
	return ValidationResult{}, false
}

// dsDenialFrom reads a delegation proof through whichever denial mechanism
// the zone publishes.
//
// A zone signs with NSEC or with NSEC3, never both, so this is a choice and
// not a fallback: trying the other after one fails would let a response that
// supplied a broken NSEC3 proof be rescued by an unrelated NSEC record, and
// vice versa. NSEC3 is preferred when present because its records are the
// ones the zone's signer produced.
func (w *walk) dsDenialFrom(proof *denialProof, child string) dsDenial {
	if proof.hasNSEC3() {
		return proof.nsec3.proveNoDS(child)
	}
	return proof.proveNoDS(child)
}
