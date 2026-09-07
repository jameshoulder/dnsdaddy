package lab

import (
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// Scenario is one named situation the lab can construct, together with the
// verdict Daddybound must reach on it.
//
// The expected verdict is part of the scenario rather than part of a test, so
// that the same list drives Daddybound's own tests and the differential
// comparison against a reference validator. One list, one set of
// expectations, and any disagreement is between the two validators rather
// than between two copies of the expectations.
type Scenario struct {
	// Name is stable and appears in test output, traces and comparison
	// reports.
	Name string
	// Why says what would be broken if this scenario passed when it should
	// fail. A scenario nobody can justify is a scenario nobody will maintain.
	Why string

	Query  string
	QType  uint16
	At     time.Time
	Expect dnssec.ValidationStatus
	// Reason is the expected failure reason. Empty means "any reason", used
	// only where more than one is legitimately correct.
	Reason dnssec.Reason

	// KnownGap explains a disagreement with a reference validator that this
	// milestone predicts, from a capability v0.1 does not claim.
	//
	// It never excuses a false Secure. The differential comparator checks
	// for that class before it looks at this field, so an annotation here
	// cannot quiet the one failure that matters.
	KnownGap string

	// Build produces the hierarchy for this scenario.
	Build func() (*Hierarchy, error)
}

// Scenarios returns the full set.
//
// Every one of them is a negative except the first, which is deliberate: a
// validator that returns Secure for everything passes exactly one of these,
// and a validator that returns Bogus for everything passes none. The pair
// makes the suite meaningful in both directions.
func Scenarios() []Scenario {
	return []Scenario{
		{
			Name:   "valid",
			Why:    "the positive case. Without it, every other scenario could be passed by a validator that never returns Secure.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  Standard,
		},
		{
			Name:   "tampered-answer",
			Why:    "an on-path attacker rewriting an address. This is the attack DNSSEC exists to stop, so a false Secure here is the worst possible outcome.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonSignatureCryptoFailed,
			Build: mutated(func(h *Hierarchy) error {
				return h.TamperData(LeafZone, AnswerName, dns.TypeA, func(rr dns.RR) {
					rr.(*dns.A).A = net.IPv4(198, 51, 100, 66)
				})
			}),
		},
		{
			Name:   "corrupt-signature",
			Why:    "one flipped bit in an otherwise admissible signature. Reaching the arithmetic is the point: a validator that rejected it on a length or format check would pass this while being unable to verify anything.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonSignatureCryptoFailed,
			Build: mutated(func(h *Hierarchy) error {
				return h.CorruptSignature(LeafZone, AnswerName, dns.TypeA)
			}),
		},
		{
			Name:   "expired-signature",
			Why:    "R-SIG-05. An expired signature is a replay of data that was once genuine, which is why expiry is enforced rather than advisory.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonSignatureExpired,
			Build: mutated(func(h *Hierarchy) error {
				// Moved a year into the past, so the whole window closed
				// before the validator's clock.
				return h.ShiftValidity(LeafZone, AnswerName, dns.TypeA, -365*24*3600)
			}),
		},
		{
			Name:   "not-yet-valid-signature",
			Why:    "R-SIG-06, the boundary in the other direction. Easy to omit, because a validator that only checks expiry looks correct against every well-run zone.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonSignatureNotYetValid,
			Build: mutated(func(h *Hierarchy) error {
				return h.ShiftValidity(LeafZone, AnswerName, dns.TypeA, 365*24*3600)
			}),
		},
		{
			Name:   "missing-signature",
			Why:    "signed data arriving with its signature stripped. Distinct from a signature that fails, and a validator must not treat an absent signature as an absent objection.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonMissingRRSIG,
			Build: mutated(func(h *Hierarchy) error {
				return h.RemoveSignatures(LeafZone, AnswerName, dns.TypeA)
			}),
		},
		{
			Name:   "malformed-signature",
			Why:    "the parsing path rather than the cryptographic one. Hostile input reaches this code before any check does.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonMalformedRecord,
			Build: mutated(func(h *Hierarchy) error {
				return h.MalformSignature(LeafZone, AnswerName, dns.TypeA)
			}),
		},
		{
			Name:   "ds-digest-mismatch",
			Why:    "the parent's delegation names this exact key and disagrees about its contents, which is the shape of a substituted zone key.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonDSDigestMismatch,
			Build: mutated(func(h *Hierarchy) error {
				return h.CorruptDS(LeafZone)
			}),
		},
		{
			Name:   "missing-dnskey",
			Why:    "a secure delegation to a zone with no keys. The DS is the parent's signed promise that the zone is signed, so this is a broken chain and not an unsigned zone.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonMissingDNSKEY,
			Build: mutated(func(h *Hierarchy) error {
				return h.RemoveDNSKEYs(LeafZone)
			}),
		},
		{
			Name:   "rogue-key-appended",
			Why:    "a key added to an authenticated apex DNSKEY RRset without re-signing it, then used to sign the answer. A validator that trusts every key in a set because one matched a DS returns Secure here. That is the P0 failure class.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Build: mutated(func(h *Hierarchy) error {
				return h.AppendRogueKey(LeafZone, AnswerName, dns.TypeA)
			}),
		},
		{
			Name:     "foreign-zone-signature",
			Why:      "R-SIG-02. The signature is cryptographically perfect and made by the wrong authority: an ancestor zone signing a delegated child's data.",
			Query:    AnswerName,
			QType:    dns.TypeA,
			At:       Now(),
			Expect:   dnssec.StatusBogus,
			Reason:   dnssec.ReasonSignerNotZone,
			KnownGap: "libunbound in forwarding mode accepts this and Daddybound does not. RFC 4035 section 5.3.1 is unambiguous -- the signer's name MUST be the zone that contains the RRset -- and example.dnsdaddylab. is a zone here, delegated with a DS. A forwarder cannot establish that cut for itself: it takes the zone from the answer's own signer name, which is the field under attack. Daddybound's chain walk crosses the delegation and so knows better. This is a limitation of the oracle's configuration, not a defect in either validator.",
			Build: mutated(func(h *Hierarchy) error {
				return h.SignWithForeignZone(LeafZone, AnswerName, dns.TypeA, MiddleZone)
			}),
		},
		{
			Name:     "unsupported-algorithm",
			Why:      "a zone signed with an algorithm this build cannot verify. RFC 6840 section 5.3 says such a zone is treated as unsigned, so this must not be Bogus: the data may be perfect and the validator simply cannot check it.",
			Query:    AnswerName,
			QType:    dns.TypeA,
			At:       Now(),
			Expect:   dnssec.StatusIndeterminate,
			Reason:   dnssec.ReasonUnsupportedAlgorithm,
			KnownGap: "RFC 6840 §5.3 says such a zone is treated as unsigned. A complete validator reports Insecure; v0.1 has no denial proofs and so reports Indeterminate.",
			Build: mutated(func(h *Hierarchy) error {
				// Ed448: in the IANA registry, with no verifier in Go's
				// standard library and therefore none here.
				return h.RelabelAlgorithm(LeafZone, dnssec.AlgED448)
			}),
		},
		{
			Name:     "disallowed-algorithm",
			Why:      "RFC 9905. This build can verify RSASHA1 and the default policy refuses to rely on it, which is both obligations at once. Reporting it as Bogus would blame the zone for the operator's policy.",
			Query:    AnswerName,
			QType:    dns.TypeA,
			At:       Now(),
			Expect:   dnssec.StatusIndeterminate,
			Reason:   dnssec.ReasonDisallowedAlgorithm,
			KnownGap: "the reference has its own algorithm policy and need not share this one. Where it still validates RSASHA1, it reports Secure and Daddybound reports Indeterminate.",
			Build: mutated(func(h *Hierarchy) error {
				return h.RelabelAlgorithm(LeafZone, dnssec.AlgRSASHA1)
			}),
		},
		{
			Name:     "unsupported-ds-digest",
			Why:      "RFC 6840 section 5.2: a DS with an unusable digest type is treated like a DS to an unsupported algorithm, and where none is left the zone is treated as unsigned. Not Bogus.",
			Query:    AnswerName,
			QType:    dns.TypeA,
			At:       Now(),
			Expect:   dnssec.StatusIndeterminate,
			Reason:   dnssec.ReasonUnsupportedDigest,
			KnownGap: "RFC 6840 §5.2 says the zone is treated as unsigned. A complete validator reports Insecure; v0.1 reports Indeterminate.",
			Build: mutated(func(h *Hierarchy) error {
				// GOST R 34.11-94, deprecated by RFC 9906 and not
				// implemented here.
				return h.SetDSDigestType(LeafZone, dnssec.DigestGOST94)
			}),
		},
		{
			Name:     "no-trust-anchor",
			Why:      "RFC 4033 section 5 calls having no anchor the default operation mode. A validator that returns anything but Indeterminate here has invented trust.",
			Query:    "www.somewhere-else.invalid.",
			QType:    dns.TypeA,
			At:       Now(),
			Expect:   dnssec.StatusIndeterminate,
			Reason:   dnssec.ReasonNoTrustAnchor,
			KnownGap: "the anchor set is narrowed for Daddybound only; a reference validator configured with the lab anchor still has one for this name.",
			Build: func() (*Hierarchy, error) {
				h, err := Standard()
				if err != nil {
					return nil, err
				}
				// The anchor covers the root, which covers everything, so
				// the scenario narrows it to the middle zone. The query then
				// falls outside any anchor.
				h.Anchor.Name = MiddleZone
				return h, nil
			},
		},
	}
}

// mutated adapts a mutation into a Scenario's Build function.
func mutated(apply func(*Hierarchy) error) func() (*Hierarchy, error) {
	return func() (*Hierarchy, error) {
		h, err := Standard()
		if err != nil {
			return nil, err
		}
		if err := apply(h); err != nil {
			return nil, err
		}
		return h, nil
	}
}
