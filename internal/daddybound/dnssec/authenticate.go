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
	_, reason := w.authenticateSigned(set, sigs, zone, keys)
	return reason
}

// authenticateSigned is authenticate, additionally reporting which RRSIG did
// the authenticating.
//
// Callers need that for exactly one rule, and it is not optional. R-DEN-11
// (RFC 4035 §5.3.4) decides whether an answer was wildcard-expanded by
// comparing the owner name's label count against "the Labels field of the
// covering RRSIG RR" — the one that verified, not any of the others that may
// be sitting alongside it in the response. Picking the wrong one lets an
// attacker attach a second RRSIG whose Labels field hides the expansion, and
// the wildcard proof would then never be demanded.
func (w *walk) authenticateSigned(set RRset, sigs []*dns.RRSIG, zone string, keys []*dns.DNSKEY) (*dns.RRSIG, Reason) {
	base := ValidationStep{Kind: StepRRSIG, Zone: zone, Name: set.Name, RRType: set.RRType}

	if len(sigs) == 0 {
		return nil, w.rec.fail(base, ReasonMissingRRSIG)
	}
	if len(sigs) > w.v.cfg.Limits.MaxSignatures {
		return nil, w.rec.fail(base, ReasonResourceLimit)
	}

	worst := ReasonMissingRRSIG
	note := func(reason Reason) { worst = worseReason(worst, reason) }

	for _, sig := range sigs {
		if err := w.ctx.Err(); err != nil {
			return nil, w.rec.fail(base, ReasonCancelled)
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

		// R-SIG-11, RFC 6840 §5.12: "a validating resolver MUST disregard
		// RRSIGs with algorithm types that don't exist in the DNSKEY RRset."
		//
		// Disregard means exactly that: the signature is not evidence of
		// anything, including of this validator's limitations. That
		// distinction is the whole point of doing this check before the
		// policy check rather than after.
		//
		// Without it there is a downgrade attack. Once a zone has been
		// authenticated through a supported algorithm it is known to sign
		// with one, so an answer carrying no valid signature is forged. An
		// attacker who strips the real signature and leaves one naming an
		// algorithm this build cannot verify — or that policy refuses —
		// would otherwise have the failure reported as the validator's own
		// inability, and `verdict` would turn a Bogus into an allow-prone
		// Indeterminate. The attacker chooses the algorithm field, so they
		// would be choosing the verdict.
		//
		// After disregarding, RFC 4035 §5.5 applies unchanged: "If for
		// whatever reason none of the RRSIGs can be validated, the response
		// SHOULD be considered BAD."
		//
		// The reason recorded is ReasonNoMatchingKey, which is a statement
		// about the data — no key in this zone corresponds to this signature
		// — rather than about Daddybound, so it cannot reach Indeterminate.
		if !algorithmInKeySet(Algorithm(sig.Algorithm), keys) {
			disregarded := step
			disregarded.Note = "algorithm absent from the zone's DNSKEY RRset; disregarded per RFC 6840 §5.12"
			note(w.rec.skip(disregarded, ReasonNoMatchingKey))
			continue
		}

		// Policy before cryptography, for an algorithm the zone genuinely
		// uses. An algorithm nobody is willing to rely on should not consume
		// a public-key operation, and the reason an operator sees should say
		// "policy" rather than "did not verify".
		//
		// Reaching this line means the algorithm *is* in the zone's DNSKEY
		// RRset, so refusing it is a statement about a zone this validator
		// cannot check rather than about a signature an attacker invented —
		// which is the RFC 6840 §5.3 case, and correctly Indeterminate.
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
			return sig, ReasonNone
		}
	}

	return nil, worst
}

// worseReason combines two candidate reasons into the one worth reporting.
//
// It is a function of the *set* of reasons seen, never of the order they were
// seen in. That matters more than it sounds: an RRset and a DS RRset are
// unordered, an attacker on the path can reorder their members freely, and a
// "last one wins" accumulator hands the attacker a say in which reason — and
// therefore, once aboutValidator() is consulted, which verdict — comes out.
// That was a real defect here, found in review for DS records.
//
// Rank decides; equal ranks are broken lexicographically so the result is
// fully determined by the set with no residual dependence on traversal.
func worseReason(a, b Reason) Reason {
	ra, rb := diagnosticRank(a), diagnosticRank(b)
	switch {
	case ra > rb:
		return a
	case rb > ra:
		return b
	case a <= b:
		return a
	default:
		return b
	}
}

// diagnosticRank orders failure reasons by how much they narrow down the
// problem, so that when several checks fail for different reasons the one
// reported is the most useful rather than whichever came last.
//
// This is not only presentation. Because aboutValidator() decides Bogus
// versus Indeterminate from the reported reason, a reason that describes the
// data must outrank one that describes this validator — otherwise an
// attacker who adds an unusable alternative alongside a definitive failure
// downgrades a Bogus into an allow-prone Indeterminate. Every
// validator-local reason therefore sits at rank 2 or below, beneath every
// reason that points at the data.
func diagnosticRank(r Reason) int {
	switch r {
	case ReasonSignatureCryptoFailed, ReasonDSDigestMismatch:
		// Definitive. The record was fully admissible and the arithmetic
		// said no; nothing localises a problem more precisely. A DS digest
		// mismatch belongs here because the parent named this exact key and
		// disagreed about its contents, which is the shape of a substituted
		// key.
		return 6
	case ReasonSignatureExpired, ReasonSignatureNotYetValid:
		// An operational fault with an obvious remedy, and the most common
		// real-world cause of a chain failing.
		return 5
	case ReasonKeyMalformed, ReasonKeyBadProtocol, ReasonKeyNotZoneKey:
		return 4
	case ReasonNoMatchingKey, ReasonNoDSMatchedKey:
		return 3
	case ReasonDisallowedAlgorithm, ReasonUnsupportedAlgorithm,
		ReasonDisallowedDigest, ReasonUnsupportedDigest:
		// Statements about this validator rather than about the zone, so
		// they rank below anything that points at the data. See the note
		// above: this ordering is what stops an unusable alternative
		// softening a definitive failure.
		return 2
	case ReasonMissingRRSIG:
		return 0
	default:
		// Structural mismatches: the record was about something else.
		return 1
	}
}

// algorithmInKeySet reports whether any key in the set uses alg.
//
// The set passed in is the zone's authenticated DNSKEY RRset — or, while the
// apex DNSKEY RRset is itself being authenticated, the subset of it a DS or
// trust anchor vouches for. Using the narrower set there is stricter than
// RFC 6840 §5.12 requires and is what RFC 4035 §5.2 asks for separately: the
// apex DNSKEY RRset must be signed by a key the parent named.
func algorithmInKeySet(alg Algorithm, keys []*dns.DNSKEY) bool {
	for _, k := range keys {
		if Algorithm(k.Algorithm) == alg {
			return true
		}
	}
	return false
}
