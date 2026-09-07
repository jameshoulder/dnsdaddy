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

	// NoOracle, when non-empty, says why this scenario cannot be posed to an
	// external validator at all, and is not the same thing as a KnownGap.
	//
	// A known gap is a disagreement with a reason. This is the absence of a
	// question: some scenarios test a property of Daddybound's own
	// configuration rather than of any data — what it does when no trust
	// anchor covers a name, for instance — and there is nothing for another
	// validator to agree or disagree with. Comparing anyway produces a
	// reference error, which would then have to be excused, and excusing
	// reference errors is how a comparison suite stops meaning anything.
	NoOracle string

	// Build produces the hierarchy for this scenario from a base
	// specification, so the same logical scenario can be built against fixed
	// instants or around a wall-clock moment. Pass StandardSpec() for the
	// former.
	Build func(Spec) (*Hierarchy, error)
}

// Shifted returns the same scenario moved by d: every signature window and
// the instant it is validated at.
//
// A reference validator that cannot be told what time it is has to be given
// fixtures that are current when it runs. Shifting rather than regenerating
// keeps the scenario identical in every other respect, so a disagreement
// remains a disagreement about validation and not about the fixtures.
func (s Scenario) Shifted(d time.Duration) Scenario {
	out := s
	out.At = s.At.Add(d)
	inner := s.Build
	out.Build = func(spec Spec) (*Hierarchy, error) { return inner(spec.Shifted(d)) }
	return out
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
			Build:  Build,
		},
		{
			Name:   "multi-record-rrset",
			Why:    "RFC 4034 section 6.3 orders an RRset by RDATA, not by record length. The signer sorted one way; a validator sorting packed records sorts the other and declares this correctly signed RRset bogus. The MX preferences are chosen so the two orders genuinely differ.",
			Query:  MailName,
			QType:  dns.TypeMX,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
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
			Name: "stripped-signature-unsupported-algorithm",
			Why: "the downgrade attack. The zone is authenticated through a supported algorithm, so it is known to be signed with one; " +
				"an attacker strips the valid signature and leaves one naming an algorithm this build cannot verify. " +
				"Reporting the validator's own inability here would turn forged data into an allow-prone Indeterminate. " +
				"RFC 6840 section 5.12 requires such a signature to be disregarded entirely, after which RFC 4035 section 5.5 applies: none validated, so BAD.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Build: mutated(func(h *Hierarchy) error {
				// Ed448: in the IANA registry, absent from this zone's
				// DNSKEY RRset, and unverifiable by this build.
				return h.SetSignatureAlgorithm(LeafZone, AnswerName, dns.TypeA, dnssec.AlgED448)
			}),
		},
		{
			Name: "stripped-signature-disallowed-algorithm",
			Why: "the same attack using an algorithm this build CAN verify but policy refuses. " +
				"The two must not be distinguishable to an attacker: neither the validator's capability nor the operator's policy " +
				"may be used to soften the absence of a valid signature from an algorithm the zone actually signs with.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Build: mutated(func(h *Hierarchy) error {
				return h.SetSignatureAlgorithm(LeafZone, AnswerName, dns.TypeA, dnssec.AlgRSASHA1)
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
			KnownGap: "UNRESOLVED, and deliberately recorded as such rather than as a Daddybound win. Two independent validators accept this answer and Daddybound refuses it: libunbound 1.19.2 and BIND delv 9.18.39. The first was initially dismissed as a forwarder that cannot see zone cuts. That explanation does not survive the second: delv performs its own chain walk and does fetch example.dnsdaddylab/DS in the valid scenario, yet still accepts an ancestor-signed answer here, because both take the containing zone from the RRSIG signer name rather than re-deriving the cut for every RRset. RFC 4035 section 5.3.1 says the signer's name MUST be the zone that contains the RRset, which is the letter Daddybound follows. Against that reading: the ancestor already publishes the child's DS and can take the child over by replacing the delegation, so accepting its signature grants no authority it lacks -- a plausible reason two mature implementations do not spend a query checking. Daddybound keeps the strict behaviour because it errs towards refusal and cannot produce a false Secure, and the question stays open.", Build: mutated(func(h *Hierarchy) error {
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
			NoOracle: "this narrows Daddybound's own anchor set and asks about a name the hierarchy does not serve. An external validator is configured from the same hierarchy, so it still holds an anchor, and it has no records to reason about either way. The property under test belongs to Daddybound's configuration rather than to any data, so there is no question to put to a second validator.",
			Build: func(spec Spec) (*Hierarchy, error) {
				h, err := Build(spec)
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
func mutated(apply func(*Hierarchy) error) func(Spec) (*Hierarchy, error) {
	return func(spec Spec) (*Hierarchy, error) {
		h, err := Build(spec)
		if err != nil {
			return nil, err
		}
		if err := apply(h); err != nil {
			return nil, err
		}
		return h, nil
	}
}
