package dnssec_test

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// TestAnOptOutSpanCannotProveANameError is RFC 5155 §12.2 applied to the one
// conclusion §8.4 would otherwise license.
//
// §8.4's procedure is short and says nothing about opt-out:
//
//	A validator MUST verify that there is a closest encloser proof for
//	QNAME present in the response and that there is an NSEC3 RR that
//	covers the wildcard at the closest encloser.
//
// Over an Opt-Out span that procedure completes. Every record verifies, the
// closest encloser is found, the wildcard is covered. And §12.2 says what the
// result is nonetheless worth:
//
//	the primary difference in security when using Opt-Out is the loss of
//	the ability to prove the existence or nonexistence of an insecure
//	delegation within the span of an Opt-Out NSEC3 RR
//
// So a validator that reports Secure here is claiming a proof the standard
// says is unavailable. §1.3 makes the same point structurally: inside an
// opt-out zone the closest *provable* encloser is not the closest encloser,
// and the proof establishes only the former.
//
// Insecure rather than Bogus or Indeterminate, and that choice is decided by
// the standard rather than by taste. §7.1 permits a signer to omit only "owner
// names of unsigned delegations" from the chain, so a name covered by an
// opt-out span either does not exist or is unsigned; §12.2 opens by settling
// what that means: "All unsigned names are, by definition, insecure."
//
// The two reference validators disagree about this, on the lab fixture and on
// the live Internet alike: libunbound reports insecure, delv reports a fully
// validated name error. Daddybound follows neither by preference — it follows
// §12.2, and the resulting agreement with libunbound is a consequence rather
// than a reason.
//
// How this was found is worth recording, because the first attempt at it went
// the wrong way. The live corpus showed Daddybound reporting Insecure for
// darkegy.cam while delv returned a validated NXDOMAIN, and the engine's
// reason for that Insecure was plainly wrong — it claimed "NS present and DS
// absent", an insecure delegation, for a name that does not exist. Correcting
// that reasoning (R-N3-12, tested below) moved the verdict to Secure and
// looked like a fix. It was a regression: the old verdict had been right by
// accident, reached through a check that happened to stop the walk before it
// could claim a proof it did not have.
func TestAnOptOutSpanCannotProveANameError(t *testing.T) {
	h, err := lab.Build(lab.NSEC3Spec())
	if err != nil {
		t.Fatalf("lab: %v", err)
	}

	// The precondition, asserted rather than assumed. This test is only
	// about opt-out if the record covering the missing name is an Opt-Out
	// record; if the fixture ever changes so that it is not, the name error
	// would be proved through the ordinary path and the verdict below would
	// flip for a reason that has nothing to do with the rule. An earlier
	// version of this test assumed it and passed with the rule removed.
	if !coveredByOptOut(t, h, lab.MissingUnderOptOut) {
		t.Fatalf("no Opt-Out NSEC3 covers %s: this test would be vacuous", lab.MissingUnderOptOut)
	}

	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	res := v.Validate(context.Background(), lab.MissingUnderOptOut, dns.TypeA)
	if res.Status != dnssec.StatusInsecure {
		t.Fatalf("a name error over an Opt-Out span came back %s (%s), want insecure\n%s",
			res.Status, res.Reason, res.Trace())
	}
	// The reason carries the whole argument, and a right verdict reached
	// through the wrong rule is what this test exists to catch: reporting
	// Insecure because the walk decided the name was a delegation is the
	// defect, not the fix.
	if res.Reason != dnssec.ReasonDenialOptOutSpan {
		t.Fatalf("reason = %s, want %s: the verdict is right for the wrong reason\n%s",
			res.Reason, dnssec.ReasonDenialOptOutSpan, res.Trace())
	}

	// The control, in the same test, because the rule must not have been
	// bought by refusing to read opt-out at all. §8.9 is the one place
	// opt-out is permitted to establish something, and it still must.
	res = v.Validate(context.Background(), lab.UnsignedName, dns.TypeA)
	if res.Status != dnssec.StatusInsecure || res.Reason != dnssec.ReasonVerified {
		t.Fatalf("a genuine insecure delegation came back %s (%s), want insecure (verified)\n%s",
			res.Status, res.Reason, res.Trace())
	}
}

// TestADSProbeUnderNXDOMAINIsNotADelegation is R-N3-12, the rule that keeps
// the verdict above from being reached by accident.
//
// RFC 5155 §8.9 describes how to establish that a *delegation* has no DS, and
// its second branch lets an Opt-Out span do it. Every sentence presumes the
// name is a delegation. The chain walk cannot know that when it asks: it
// probes for a DS at each candidate zone cut, and most candidates are not
// delegations. So an opt-out span was read as "insecure delegation" for names
// that are not delegations at all, including names that do not exist.
//
// A delegation is a name that exists, and RFC 2308 §2.2 separates the two
// cases in the response itself: a name that exists with no data of the queried
// type is answered NODATA under NOERROR, and only a name that does not exist
// gets NXDOMAIN. Reading the rcode is what lets §8.9's precondition be checked
// instead of assumed.
//
// The verdict is the same either way — Insecure — which is exactly why this
// needs its own test. The difference is what the engine claims to have proved,
// and a trace that says "NS present and DS absent" about a name the response
// says does not exist is a false statement in the evidence a reviewer reads.
func TestADSProbeUnderNXDOMAINIsNotADelegation(t *testing.T) {
	h, err := lab.Build(lab.NSEC3Spec())
	if err != nil {
		t.Fatalf("lab: %v", err)
	}
	if !coveredByOptOut(t, h, lab.MissingUnderOptOut) {
		t.Fatalf("no Opt-Out NSEC3 covers %s: this test would be vacuous", lab.MissingUnderOptOut)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	res := v.Validate(context.Background(), lab.MissingUnderOptOut, dns.TypeA)
	for _, step := range res.Steps {
		if step.RRType == dns.TypeDS && strings.Contains(step.Note, "insecure delegation") {
			t.Fatalf("the walk claimed an insecure delegation at a name the response says does not exist:\n%s",
				res.Trace())
		}
	}
}

// coveredByOptOut reports whether some NSEC3 record with the Opt-Out bit set
// covers name's hash, computed independently of the validator's own hashing.
func coveredByOptOut(t *testing.T, h *lab.Hierarchy, name string) bool {
	t.Helper()
	hash := strings.ToUpper(dns.HashName(dns.CanonicalName(name), dns.SHA1, 0, ""))
	for _, rr := range h.Records() {
		n3, ok := rr.(*dns.NSEC3)
		if !ok || n3.Flags&1 == 0 {
			continue
		}
		owner := strings.ToUpper(strings.SplitN(n3.Hdr.Name, ".", 2)[0])
		next := strings.ToUpper(n3.NextDomain)
		if owner < next {
			if hash > owner && hash < next {
				return true
			}
			continue
		}
		// The last record in the chain wraps past the end of the zone.
		if hash > owner || hash < next {
			return true
		}
	}
	return false
}

// TestAnNSECDelegationCannotArriveWithANameError is R-DEN-13, the NSEC half of
// the same rule.
//
// Under NSEC there is no opt-out and so no ambiguous span: an insecure
// delegation is proved by an NSEC *matching* the delegation name with NS set
// and DS clear. That record is a signed statement that the name exists. An
// NXDOMAIN header on the same message is a statement that it does not.
//
// One message, two incompatible claims, and only one of them is signed. The
// engine used to read the signed half and ignore the header, reporting
// Insecure — which is the more useful half for an attacker, because Insecure
// invites a consumer to accept unsigned data at a name whose real status the
// message has just obscured. Refusing the message outright is the only
// answer that does not pick a half.
//
// This is the same shape as the rule that a positive answer may not arrive
// under NXDOMAIN, and it was found by generalising that one rather than by
// another live name.
func TestAnNSECDelegationCannotArriveWithANameError(t *testing.T) {
	// The control first, on an untouched hierarchy: this is the scenario
	// that must reach Insecure, or the test below proves nothing.
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("lab: %v", err)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	if res := v.Validate(context.Background(), lab.UnsignedName, dns.TypeA); res.Status != dnssec.StatusInsecure {
		t.Fatalf("the control came back %s (%s), want insecure\n%s", res.Status, res.Reason, res.Trace())
	}

	// Now the same records, with one unsigned header field changed.
	h, err = lab.Standard()
	if err != nil {
		t.Fatalf("lab: %v", err)
	}
	h.ForceRcode(lab.UnsignedZone, dns.TypeDS, dns.RcodeNameError)
	v, err = h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	res := v.Validate(context.Background(), lab.UnsignedName, dns.TypeA)
	if res.Status == dnssec.StatusInsecure {
		t.Fatalf("a delegation the header says does not exist still established Insecure\n%s", res.Trace())
	}
	if res.Status == dnssec.StatusSecure {
		t.Fatalf("a self-contradictory message validated\n%s", res.Trace())
	}
	if res.Reason != dnssec.ReasonDenialContradicted {
		t.Errorf("reason = %s, want %s: the verdict is right but for the wrong reason, which is how a rule stops meaning what it says",
			res.Reason, dnssec.ReasonDenialContradicted)
	}
}
