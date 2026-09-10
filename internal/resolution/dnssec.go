package resolution

import (
	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// The DNSSEC state of an answer, and exactly what each state does to the
// response a client receives.
//
// RFC 4033 §5 defines four security states and this deployment adds a fifth for
// the case the RFC does not describe: a resolver that could not obtain the
// records at all. Keeping that separate is the whole reason this is not simply
// dnssec.ValidationStatus. An attacker who can drop packets can cause a
// timeout; if a timeout were recorded as Insecure they could downgrade any
// signed zone by dropping its DNSKEY query, and if it were recorded as Bogus
// they could condemn any zone by dropping anything.
//
// The mapping to the wire is deliberately dull, and it is documented here
// rather than being spread across the code that implements it:
//
//	Secure         NOERROR, the answer, AD set when the client asked for it
//	Insecure       NOERROR, the answer, AD clear
//	Bogus          SERVFAIL, no answer, EDE 6 (DNSSEC Bogus)
//	Indeterminate  the answer, AD clear, EDE 5 (DNSSEC Indeterminate)
//	Unchecked      the answer as received, AD only if the upstream set it
//
// Two of those are worth the argument.
//
// Bogus is SERVFAIL with nothing attached. RFC 4035 §5.5 says a response that
// fails to validate "SHOULD be considered BAD", and RFC 4033 §5 is explicit
// that a validator must not return data it believes forged. Returning the
// records with a warning would be worse than useless: nothing on the client
// side reads the warning, and the records would be used. There is deliberately
// no configuration to soften this, because a switch labelled "let bogus
// answers through" is a switch that gets turned on the first time a
// misconfigured bank breaks.
//
// Indeterminate returns the answer. It means this validator could not decide —
// no trust anchor covers the name, an algorithm this build cannot read, a
// resource limit reached — and every one of those is a statement about this
// resolver rather than about the data. Refusing to answer would take a
// deployment offline for the entire unsigned Internet the moment a trust anchor
// went missing, and would let an attacker cause a denial of service by
// publishing something exotic. So the answer goes out with AD clear and an
// extended error saying why, which is the honest shape: here is what the
// servers said, and no, we could not authenticate it.
type Status string

const (
	// StatusSecure: the records authenticate to a configured trust anchor.
	StatusSecure Status = "secure"
	// StatusInsecure: an authenticated proof shows the data lies in an
	// unsigned part of the namespace. A proof, not a shrug — see
	// internal/daddybound/dnssec on why the difference matters.
	StatusInsecure Status = "insecure"
	// StatusBogus: a secure delegation was established and the data failed to
	// validate under it. The answer is refused.
	StatusBogus Status = "bogus"
	// StatusIndeterminate: this validator could not decide, for a reason
	// about itself rather than about the data.
	StatusIndeterminate Status = "indeterminate"
	// StatusUnchecked: nothing local validated this answer.
	//
	// The forwarding backend's normal state. It is not "insecure" and it is
	// not "indeterminate": those are conclusions a validator reached, and
	// this is the absence of a validator. Recording it as either would put a
	// claim in the query log that nothing in this deployment ever made.
	StatusUnchecked Status = "unchecked"
)

// Statuses lists every state, in report order, so a metric counter exists at
// zero rather than appearing the first time something goes wrong.
func Statuses() []Status {
	return []Status{
		StatusSecure, StatusInsecure, StatusBogus,
		StatusIndeterminate, StatusUnchecked,
	}
}

// Refuses reports whether this state means the answer must not be served.
//
// One function, called wherever the decision is made, because "which states are
// fatal" is the kind of question that gets answered slightly differently in two
// places and then only one of them is updated.
func (s Status) Refuses() bool { return s == StatusBogus }

// FromValidation maps a Daddybound verdict onto a resolution state.
//
// By typed reason rather than by inspecting text, and the reasons that are
// statements about the validator rather than about the zone are separated out —
// the same distinction internal/daddybound/observe makes, for the same reason.
// An answer this build cannot read must not be reported as provably unsigned,
// because that would let an attacker downgrade a zone by publishing a
// delegation signed with something exotic.
func FromValidation(res dnssec.ValidationResult) (Status, string) {
	reason := string(res.Reason)
	switch res.Reason {
	case dnssec.ReasonCancelled, dnssec.ReasonResourceLimit,
		dnssec.ReasonUnsupportedAlgorithm, dnssec.ReasonUnsupportedDigest,
		dnssec.ReasonDenialNotImplemented, dnssec.ReasonNoTrustAnchor:
		return StatusIndeterminate, reason
	}
	switch res.Status {
	case dnssec.StatusSecure:
		return StatusSecure, reason
	case dnssec.StatusInsecure:
		return StatusInsecure, reason
	case dnssec.StatusBogus:
		return StatusBogus, reason
	case dnssec.StatusIndeterminate:
		return StatusIndeterminate, reason
	default:
		// A status this package does not know about is not guessed at.
		// Folding it into Indeterminate would hide a version skew between the
		// engine and the code reading its verdicts, and Indeterminate serves
		// the answer.
		return StatusBogus, reason
	}
}

// extendedError returns the RFC 8914 code for a state, and whether there is
// one worth sending.
//
// Only codes that describe what actually happened. RFC 8914 §2 makes these
// diagnostic rather than authoritative — a client must not change its
// behaviour on the strength of one — so an invented or approximate code is
// pure noise on the wire and a lie in a packet capture.
func extendedError(s Status) (uint16, bool) {
	switch s {
	case StatusBogus:
		return dns.ExtendedErrorCodeDNSBogus, true
	case StatusIndeterminate:
		return dns.ExtendedErrorCodeDNSSECIndeterminate, true
	default:
		return 0, false
	}
}

// applyDNSSEC prepares a response for the client according to its security
// state, and reports whether the answer may be served at all.
//
// The single place the table in this file's comment is implemented.
func applyDNSSEC(msg *dns.Msg, req *dns.Msg, status Status, authority Authority) (*dns.Msg, bool) {
	if status.Refuses() {
		// SERVFAIL with nothing attached. Not the records with a warning:
		// nothing on the client side reads warnings, and the records would be
		// used.
		fail := new(dns.Msg)
		fail.SetRcode(req, dns.RcodeServerFailure)
		fail.RecursionAvailable = true
		attachEDE(fail, req, status)
		return fail, false
	}

	// RFC 4035 §3.2.3: AD is set only when the client asked for it, by setting
	// DO or AD in its own query — and only when this resolver actually
	// authenticated the answer.
	//
	// The second condition is the one worth being careful about. An upstream's
	// AD bit is that upstream's claim, and passing it through unchanged tells a
	// client "this was authenticated" on the strength of a machine somebody
	// else runs. It is left alone for the forwarding backend, which is what a
	// forwarder is, and it is *ours* to set only where we validated.
	if authority == AuthorityLocal {
		msg.AuthenticatedData = status == StatusSecure && clientWantsAD(req)
	}
	attachEDE(msg, req, status)
	return msg, true
}

// attachEDE adds an extended error, but only to a response that already carries
// an OPT record.
//
// A client that did not send EDNS0 cannot be sent an OPT record in reply: RFC
// 6891 §6.1.1 makes the option a property of an EDNS conversation, and
// inventing one for a plain DNS client produces a response some stubs refuse to
// parse. So the diagnostic is attached where it can be read and omitted where
// it cannot, which costs nothing — EDE is diagnostic in both directions.
func attachEDE(msg *dns.Msg, req *dns.Msg, status Status) {
	code, ok := extendedError(status)
	if !ok || req.IsEdns0() == nil {
		return
	}
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(ednsBufferSize(req), clientWantsDO(req))
		opt = msg.IsEdns0()
		if opt == nil {
			return
		}
	}
	for _, o := range opt.Option {
		if _, already := o.(*dns.EDNS0_EDE); already {
			return
		}
	}
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: code})
}

// ednsBufferSize echoes a size that will not make things worse.
//
// The client's advertised size, capped at the DNS flag-day 1232 octets: large
// enough for the responses this resolver sends and small enough to stay under
// the common path MTU, so a truncation is answered by a TCP retry rather than
// by fragments a middlebox drops.
func ednsBufferSize(req *dns.Msg) uint16 {
	const flagDay = 1232
	opt := req.IsEdns0()
	if opt == nil {
		return flagDay
	}
	if size := opt.UDPSize(); size > 0 && size < flagDay {
		return size
	}
	return flagDay
}

func clientWantsDO(req *dns.Msg) bool {
	opt := req.IsEdns0()
	return opt != nil && opt.Do()
}

// clientWantsAD reports whether the client signalled interest in the AD bit,
// by setting DO in EDNS0 or AD in the query header.
func clientWantsAD(req *dns.Msg) bool {
	if req == nil {
		return false
	}
	if req.AuthenticatedData {
		return true
	}
	opt := req.IsEdns0()
	return opt != nil && opt.Do()
}
