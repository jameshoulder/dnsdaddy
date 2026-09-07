package dnssec

import "github.com/miekg/dns"

// authenticate decides whether an RRset is authenticated by any of a zone's
// keys, recording a step for every signature it considers.
//
// RFC 6840 §5.4 (R-SIG-10) fixes the shape of this function:
//
//	a resolver SHOULD accept any valid RRSIG as sufficient, and only
//	determine that an RRset is Bogus if all RRSIGs fail validation.
//
// So the loop returns success on the first signature that verifies and only
// fails once every signature has been tried. Both of the obvious wrong
// implementations are easy to write and hard to spot afterwards:
//
//   - failing on the first RRSIG that does not verify rejects zones in the
//     middle of a key rollover, which publish signatures from the outgoing
//     key alongside the incoming one. Wrong, but wrong towards refusing
//     valid data;
//   - accepting because a signature was *present* rather than because one
//     verified. That is the P0 direction — a false Secure — and it is why
//     the only `return ReasonNone` here sits directly after a verifier call
//     that returned ReasonNone.
func (w *walk) authenticate(set RRset, sigs []*dns.RRSIG, zone string, keys []*dns.DNSKEY) Reason {
	base := ValidationStep{Kind: StepRRSIG, Zone: zone, Name: set.Name, RRType: set.RRType}

	if len(sigs) == 0 {
		return w.rec.fail(base, ReasonMissingRRSIG)
	}
	if len(sigs) > w.v.cfg.Limits.MaxSignatures {
		return w.rec.fail(base, ReasonResourceLimit)
	}

	worst := ReasonMissingRRSIG
	note := func(reason Reason) {
		if diagnosticRank(reason) > diagnosticRank(worst) {
			worst = reason
		}
	}

	for _, sig := range sigs {
		if err := w.ctx.Err(); err != nil {
			return w.rec.fail(base, ReasonCancelled)
		}

		step := base
		step.Algorithm = sig.Algorithm
		step.KeyTag = sig.KeyTag

		// The strong form of R-SIG-02. rrsigAdmissible can only check that
		// the signer's name is at or above the owner name, because on its
		// own it does not know where the zone cuts are. Here the chain walk
		// does know: this RRset was reached inside a zone whose apex DNSKEY
		// RRset has been authenticated, so the signer must be that zone
		// exactly. An ancestor zone signing a delegated child's data is
		// refused here and nowhere else.
		if dns.CanonicalName(sig.SignerName) != zone {
			note(w.rec.skip(step, ReasonSignerNotZone))
			continue
		}

		// Policy before cryptography. An algorithm nobody is willing to rely
		// on should not consume a public-key operation, and the reason an
		// operator sees should say "policy" rather than "did not verify".
		if reason := w.v.cfg.Policy.CheckAlgorithm(Algorithm(sig.Algorithm)); reason != ReasonNone {
			policyStep := step
			policyStep.Kind = StepPolicy
			note(w.rec.skip(policyStep, reason))
			continue
		}

		if reason := rrsigAdmissible(set, sig, w.now); reason != ReasonNone {
			note(w.rec.skip(step, reason))
			continue
		}

		candidates := candidateKeys(zone, sig, keys)
		if len(candidates) == 0 {
			note(w.rec.skip(step, ReasonNoMatchingKey))
			continue
		}

		// Every candidate is tried, not just the first. Key tags are 16-bit
		// checksums (RFC 4034 Appendix B) and two keys in one apex RRset may
		// share one; stopping at the first collision rejects a correctly
		// signed zone intermittently, which is close to undiagnosable in
		// production.
		verified := false
		for _, k := range candidates {
			if reason := keyUsable(k); reason != ReasonNone {
				note(w.rec.fail(keyStep(StepDNSKEY, zone, k), reason))
				continue
			}
			reason := verifyRRset(w.v.cfg.Verifier, set, sig, k)
			if reason == ReasonNone {
				w.rec.ok(step)
				verified = true
				break
			}
			note(w.rec.fail(step, reason))
		}
		if verified {
			return ReasonNone
		}
	}

	return worst
}

// diagnosticRank orders failure reasons by how much they narrow down the
// problem, so that when several signatures fail for different reasons the one
// reported is the most useful rather than the last one seen.
//
// It affects only which reason is reported. It never affects the verdict:
// every path that consults it has already established that nothing verified.
// The ordering is fixed here rather than derived from iteration order so that
// two runs over the same input report the same reason, which is what makes a
// trace comparable against a reference validator's.
func diagnosticRank(r Reason) int {
	switch r {
	case ReasonSignatureCryptoFailed:
		// The signature was fully admissible and the arithmetic said no.
		// Nothing else localises the problem as precisely.
		return 6
	case ReasonSignatureExpired, ReasonSignatureNotYetValid:
		// An operational fault with an obvious remedy, and the most common
		// real-world cause of a chain failing.
		return 5
	case ReasonKeyMalformed, ReasonKeyBadProtocol, ReasonKeyNotZoneKey:
		return 4
	case ReasonNoMatchingKey:
		return 3
	case ReasonDisallowedAlgorithm, ReasonUnsupportedAlgorithm:
		// A statement about this validator rather than about the zone, so it
		// ranks below anything that points at the data.
		return 2
	case ReasonMissingRRSIG:
		return 0
	default:
		// Structural mismatches: the signature was about something else.
		return 1
	}
}
