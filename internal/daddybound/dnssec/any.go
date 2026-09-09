package dnssec

import (
	"sort"

	"github.com/miekg/dns"
)

// QTYPE=* is not a type, and that difference is a false Secure waiting to
// happen.
//
// Type 255 is a query type. It never appears in a record header and it can
// never appear in an NSEC or NSEC3 type bitmap, because a bitmap lists the
// types that exist at a name and no record has type 255. Every part of this
// engine that reasons about "the RRset of type T" therefore degenerates when
// T is 255: the answer filter matches nothing, and the NODATA rule — "the
// matching denial record must omit the queried type" — is satisfied by every
// bitmap ever published.
//
// Composing those two gives a validator that answers "Secure, and there is
// no data here" for a name whose NSEC record, in the same response, lists its
// types. This package did exactly that until the review that added this file:
// an attacker had only to strip the answer section from an ANY response and
// leave the zone's own genuine denial records in place, and Daddybound
// authenticated an absence the zone had never asserted. That is a false
// Secure produced with no forgery at all.
//
// RFC 6840 §4.2 says what to do instead:
//
//	When validating a response to QTYPE=*, all received RRsets that match
//	QNAME and QCLASS MUST be validated. If any of those RRsets fail
//	validation, the answer is considered Bogus. If there are no RRsets
//	matching QNAME and QCLASS, that fact MUST be validated according to
//	the rules in Section 5.4 of [RFC4035] ... To be clear, a validator
//	must not expect to receive all records at the QNAME in response to
//	QTYPE=*.
//
// The last sentence is why a QTYPE=* answer cannot be checked for
// completeness: RFC 1034 §6.2.2 lets a server return a subset, so "these are
// all the records" is not a claim this response makes and not one a validator
// can test. What Secure means for an ANY query is therefore narrower than for
// any other, and validateAny is written so the narrower claim is the only one
// it can produce: every RRset that arrived is authentic, and nothing is said
// about the ones that did not.

// validateAny implements RFC 6840 §4.2.
func (w *walk) validateAny(zone *zoneState, qname string, resp Response) aliasOutcome {
	types := answerTypesAt(resp.Answer, qname)

	if len(types) == 0 {
		return aliasOutcome{result: w.emptyAnyAnswer(zone, qname, resp)}
	}

	// A budget, because the number of types in the answer section is chosen
	// by whoever sent it and each one costs a canonicalisation and a
	// public-key operation. A name with more distinct types than this is not
	// something the DNS produces; sending one is.
	if len(types) > w.v.cfg.Limits.MaxAnyRRsets {
		return aliasOutcome{result: w.rec.indeterminate(w.rec.fail(
			ValidationStep{Kind: StepLimit, Zone: zone.name, Name: qname, RRType: dns.TypeANY,
				Note: "more RRsets in one ANY answer than the configured limit"},
			ReasonResourceLimit,
		))}
	}

	// Every one of them, and the *worst* result rather than the first
	// failure, so that the verdict is a function of the set of RRsets rather
	// than of the order the server sent them in. §4.2's "if any of those
	// RRsets fail validation, the answer is considered Bogus" is an
	// all-must-pass rule, and an all-must-pass rule implemented with an
	// early return still gives an order-dependent *reason* — which decides
	// Bogus versus Indeterminate once aboutValidator() is consulted, and so
	// hands an attacker who reorders the answer section a say in the verdict.
	status := StatusSecure
	reason := ReasonVerified
	for _, rrtype := range types {
		res := w.validateAnyRRset(zone, qname, rrtype, resp)
		if next := weakest(status, res.Status); next != status {
			status, reason = next, res.Reason
		}
	}
	return aliasOutcome{result: w.rec.result(status, reason)}
}

// validateAnyRRset authenticates one type's RRset from an ANY answer.
//
// Deliberately the same three steps the ordinary answer path takes — group,
// authenticate, demand the wildcard proof — rather than a shortened version
// of them. A wildcard-expanded RRset inside an ANY answer is exactly as
// replayable over sibling names as one returned on its own, and it would be
// easy to reach for a cheaper check here on the grounds that ANY is a corner.
func (w *walk) validateAnyRRset(zone *zoneState, qname string, rrtype uint16, resp Response) ValidationResult {
	step := ValidationStep{Kind: StepRRset, Zone: zone.name, Name: qname, RRType: rrtype}

	data, sigs := SplitSignaturesAt(resp.Answer, qname, rrtype)
	set, reason := NewRRset(data)
	if reason != ReasonNone {
		return w.rec.verdict(w.rec.fail(step, reason))
	}

	accepted, reason := w.authenticateSigned(set, sigs, zone.name, zone.keys)
	if reason != ReasonNone {
		return w.rec.verdict(reason)
	}
	w.rec.ok(step)

	if res, done := w.wildcardProof(zone, qname, rrtype, accepted, resp); done {
		return res
	}
	return w.rec.secure()
}

// emptyAnyAnswer handles a QTYPE=* response whose answer section holds
// nothing at the queried name.
//
// RFC 6840 §4.2 sends this case to RFC 4035 §5.4, and §5.4 has two rules. The
// name-error one transfers intact: proving the name does not exist proves it
// has no records of any type, which is a complete answer to QTYPE=*. The
// NODATA one does not transfer at all, and that is the whole point of this
// function — a NODATA proof works by showing the queried type is absent from
// a bitmap, and type 255 is absent from every bitmap because no record has
// it. Accepting one would authenticate nothing.
//
// So a NOERROR with an empty answer is refused, and refused as Indeterminate
// rather than Bogus. The zone has not been caught doing anything: a server is
// entitled under RFC 1034 §6.2.2 to return a subset of the records at a name,
// and the empty set is a subset. What has happened is that this validator
// cannot authenticate the response, which is a fact about the validator.
func (w *walk) emptyAnyAnswer(zone *zoneState, qname string, resp Response) ValidationResult {
	if resp.Rcode == dns.RcodeNameError {
		return w.validateDenial(zone, qname, dns.TypeANY, resp)
	}
	return w.rec.indeterminate(w.rec.skip(
		ValidationStep{Kind: StepDenial, Zone: zone.name, Name: qname, RRType: dns.TypeANY,
			Note: "no NSEC or NSEC3 type bitmap can deny QTYPE=*, so an empty ANY answer cannot be authenticated"},
		ReasonAnyNotProvable,
	))
}

// answerTypesAt lists the distinct record types present at one owner name,
// ignoring RRSIGs, in ascending order.
//
// Sorted so that the traversal — and therefore the trace, and therefore any
// reason that survives to the verdict — is a function of which types arrived
// rather than of the order they were written into the message.
func answerTypesAt(records []dns.RR, owner string) []uint16 {
	want := dns.CanonicalName(owner)
	seen := map[uint16]bool{}
	for _, rr := range records {
		h := rr.Header()
		if h.Rrtype == dns.TypeRRSIG || dns.CanonicalName(h.Name) != want {
			continue
		}
		seen[h.Rrtype] = true
	}
	out := make([]uint16, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
