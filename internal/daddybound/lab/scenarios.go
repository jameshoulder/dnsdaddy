package lab

import (
	"fmt"
	"net"
	"sort"
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

	// Family groups scenarios by the part of the engine they exercise, so
	// that a coverage claim can be checked rather than assumed. A suite can
	// grow to fifty entries and still have a blind spot; counting by family
	// is what makes the spot visible.
	Family Family

	// KnownGap explains a disagreement with a reference validator that this
	// milestone predicts and can justify.
	//
	// Two kinds qualify, and both have to be argued rather than asserted: a
	// capability Daddybound does not claim, and a place where Daddybound is
	// deliberately stricter because it reports a verdict where a full
	// resolver would repair the answer. Nothing else does. In particular
	// "the reference validator says otherwise" is not a gap; it is the
	// beginning of an investigation against the RFC.
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

// Family names the part of the engine a scenario exercises.
type Family string

const (
	// FamilyPositive: correctly signed data that must validate. Without
	// these, every negative scenario could be passed by a validator that
	// never returns Secure.
	FamilyPositive Family = "positive"

	// FamilyChainFailure: the chain of trust is broken or the data is
	// forged. Signatures, keys, delegation records and algorithm policy.
	FamilyChainFailure Family = "chain-failure"

	// FamilyNSEC: authenticated denial of existence using NSEC.
	FamilyNSEC Family = "nsec"

	// FamilyNSEC3: the same questions asked of an NSEC3-signed hierarchy.
	FamilyNSEC3 Family = "nsec3"

	// FamilyAlias: CNAME chains, including the ones that cross a zone cut or
	// a change in security status.
	FamilyAlias Family = "alias"

	// FamilyConfiguration: a property of Daddybound's own configuration
	// rather than of any data — what it does with no trust anchor, for
	// instance. These are the scenarios with nothing to ask an oracle.
	FamilyConfiguration Family = "configuration"
)

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
			Family: FamilyPositive,
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
			Family: FamilyPositive,
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
			Family: FamilyChainFailure,
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
			Family: FamilyChainFailure,
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
			Family: FamilyChainFailure,
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
			Family: FamilyChainFailure,
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
			Family: FamilyChainFailure,
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
			Family: FamilyChainFailure,
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
			Name:   "stripped-signature-unsupported-algorithm",
			Family: FamilyChainFailure,
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
			Name:   "stripped-signature-disallowed-algorithm",
			Family: FamilyChainFailure,
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
			Family: FamilyChainFailure,
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
			Family: FamilyChainFailure,
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
			Family: FamilyChainFailure,
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
			Family:   FamilyChainFailure,
			Why:      "R-SIG-02. The signature is cryptographically perfect and made by the wrong authority: an ancestor zone signing a delegated child's data.",
			Query:    AnswerName,
			QType:    dns.TypeA,
			At:       Now(),
			Expect:   dnssec.StatusBogus,
			Reason:   dnssec.ReasonSignerNotZone,
			KnownGap: "Settled by measurement, and not the way the earlier note guessed. Two independent validators accept this answer and Daddybound refuses it: libunbound 1.19.2 and BIND delv 9.18.39. The explanation on file was that all three know where the zone cut is and read RFC 4035 section 5.3.1 differently. The lab's query log says otherwise: against this scenario delv asks for the answer, then dnsdaddylab DNSKEY, dnsdaddylab DS and the root DNSKEY, and never asks about example.dnsdaddylab at all. Taking the containing zone from the signer name is what determines where it looks, so the cut is never discovered and the rule cannot be applied. Daddybound fetches that zone's DS and DNSKEY because it descends the delegations rather than following the signature, so its refusal rests on evidence delv did not gather. Still not a vulnerability in delv: section 5.3.1 also requires the signer to be at or above the owner name, which delv does check, and an ancestor can seize any name beneath it by replacing the delegation anyway. Daddybound keeps the strict behaviour because it errs towards refusal and has the information as a by-product of the walk. See docs/daddybound/standards.md section 5.8 and the pinned measurement in internal/daddybound/differential/zonecut_test.go.", Build: mutated(func(h *Hierarchy) error {
				return h.SignWithForeignZone(LeafZone, AnswerName, dns.TypeA, MiddleZone)
			}),
		},
		{
			Name:     "unsupported-algorithm",
			Family:   FamilyChainFailure,
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
			Family:   FamilyChainFailure,
			Why:      "RFC 9905. This build can verify RSASHA1 and the default policy refuses to rely on it, which is both obligations at once. Reporting it as Bogus would blame the zone for the operator's policy.",
			Query:    AnswerName,
			QType:    dns.TypeA,
			At:       Now(),
			Expect:   dnssec.StatusIndeterminate,
			Reason:   dnssec.ReasonDisallowedAlgorithm,
			KnownGap: "policy, not protocol, and the standards put the two implementations on opposite sides of it deliberately. RFC 9905 section 2 tells validator implementations they MUST continue to support validation using RSASHA1, and in the same paragraph tells validator operators they MUST treat it as unsupported. A reference validator built to the first sentence reports Secure; Daddybound's default policy is built to the second and reports Indeterminate with disallowed_algorithm. Neither is wrong about the data, and the disagreement would vanish if the oracle were configured with the same policy. What must not happen is Bogus, because the zone is not broken.",
			Build: mutated(func(h *Hierarchy) error {
				return h.RelabelAlgorithm(LeafZone, dnssec.AlgRSASHA1)
			}),
		},
		{
			Name:     "unsupported-ds-digest",
			Family:   FamilyChainFailure,
			Why:      "RFC 6840 section 5.2: a DS with an unusable digest type is treated like a DS to an unsupported algorithm, and where none is left the zone is treated as unsigned. Not Bogus.",
			Query:    AnswerName,
			QType:    dns.TypeA,
			At:       Now(),
			Expect:   dnssec.StatusIndeterminate,
			Reason:   dnssec.ReasonUnsupportedDigest,
			KnownGap: "RFC 6840 section 5.2 says that where no usable DS digest is left, the zone is treated as if it were unsigned, and a complete validator therefore reports Insecure. Daddybound reports Indeterminate with unsupported_digest. The difference is that Insecure is a claim — RFC 4033 section 5 defines it as signed proof that no DS exists — and here no such proof was offered: the DS records are present and this build simply cannot compute their digest type. Reporting Insecure would say the parent proved something it never asserted. The honest statement is that this validator could not evaluate the delegation, which is what Indeterminate means and what the reason says.",
			Build: mutated(func(h *Hierarchy) error {
				// GOST R 34.11-94, deprecated by RFC 9906 and not
				// implemented here.
				return h.SetDSDigestType(LeafZone, dnssec.DigestGOST94)
			}),
		},
		// Authenticated denial of existence. Four positives and six
		// negatives, because the denial rules are where a validator most
		// easily arrives at the right answer for the wrong reason: an
		// implementation that accepts any NSEC it can verify passes every
		// positive here and fails every negative.
		{
			Name:   "nxdomain",
			Family: FamilyNSEC,
			Why:    "RFC 4035 section 5.4. A proved non-existence is a Secure answer. Without this, a validator could pass every other denial scenario by refusing to conclude anything about absences.",
			Query:  MissingName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
		},
		{
			Name:   "nodata",
			Family: FamilyNSEC,
			Why:    "RFC 4035 section 5.4 first bullet: the name exists and the type does not, proved by the queried type being absent from the matching NSEC's bitmap.",
			Query:  AnswerName,
			QType:  dns.TypeTXT,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
		},
		{
			Name:   "empty-non-terminal-nodata",
			Family: FamilyNSEC,
			Why:    "RFC 4035 section 2.3 requires an NSEC only at names with authoritative data or a delegation NS RRset, so an empty non-terminal has none. A validator that demands a matching NSEC for every NODATA rejects a correctly signed zone here; one that reads the spanning NSEC as a name error turns NODATA into NXDOMAIN.",
			Query:  EmptyNonTerminal,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
		},
		{
			Name:   "wildcard-expanded-answer",
			Family: FamilyNSEC,
			Why:    "RFC 4035 section 5.3.4. The signature over a wildcard answer is genuine and is valid for every name under the encloser, so it does not on its own establish that this expansion was legitimate. The wildcard here sits two labels below the apex, so a validator assuming the source of synthesis is always the apex wildcard looks for the wrong name.",
			Query:  WildcardMatch,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
		},
		{
			Name:   "insecure-delegation",
			Family: FamilyNSEC,
			Why:    "RFC 4033 section 5's Insecure, and the only honest route to it: the parent's signed NSEC has NS set and DS clear (RFC 6840 section 4.4), so the absence of a DS is proved rather than merely observed. A validator that reports Secure here has verified data against keys nothing authenticates; one that reports Bogus refuses a legitimately unsigned zone.",
			Query:  UnsignedName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusInsecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
		},
		{
			Name:   "nxdomain-without-wildcard-denial",
			Family: FamilyNSEC,
			Why:    "RFC 4035 section 5.4: proving the queried name is missing is only half the proof, because a wildcard could have answered. Everything left in the response verifies; what was removed is the half a validator that stops at the first covering NSEC never asks for. This is the forged NXDOMAIN that works against every wildcard-bearing zone.",
			Query:  MissingName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonDenialIncomplete,
			Build: mutated(func(h *Hierarchy) error {
				// The NSEC covering "*.example.dnsdaddylab." is the leaf
				// apex record, which is also what covers the wildcard for a
				// name whose closest encloser is the apex.
				return h.RemoveNSEC(LeafZone, LeafZone)
			}),
		},
		{
			Name:   "nxdomain-with-no-denial-at-all",
			Family: FamilyNSEC,
			Why:    "the server asserts NXDOMAIN and proves nothing. A validator that trusts the rcode accepts every forged name error ever sent.",
			Query:  MissingName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonNoDenialProof,
			Build: func(spec Spec) (*Hierarchy, error) {
				return Build(withoutDenial(spec, LeafZone))
			},
		},
		{
			Name:   "nodata-contradicted-by-its-own-nsec",
			Family: FamilyNSEC,
			Why:    "the response claims no A exists at a name whose signed NSEC lists A. The zone's own records refute the answer it was sent with, which is what an attacker stripping an RRset produces.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonDenialContradicted,
			Build: mutated(func(h *Hierarchy) error {
				// Remove the answer but leave the NSEC saying it is there.
				return h.Replace(LeafZone, AnswerName, dns.TypeA, nil)
			}),
		},
		{
			Name:   "nodata-hiding-a-cname",
			Family: FamilyNSEC,
			Why:    "RFC 6840 section 4.3. An attacker turns a positive CNAME response into NOERROR/NODATA by deleting the CNAME RRset. The matching NSEC does not list the queried type, so a validator checking only that bit accepts it; the CNAME bit is what gives the removal away.",
			Query:  AnswerName,
			QType:  dns.TypeTXT,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonDenialContradicted,
			Build: mutated(func(h *Hierarchy) error {
				// The zone says a CNAME lives here. It does not say TXT
				// does — so only the RFC 6840 check catches this.
				return h.SetNSECBitmap(LeafZone, AnswerName,
					[]uint16{dns.TypeCNAME, dns.TypeRRSIG, dns.TypeNSEC})
			}),
		},
		{
			Name:   "insecure-delegation-claimed-without-the-ns-bit",
			Family: FamilyNSEC,
			Why:    "RFC 6840 section 4.4. An attacker strips the DS from a referral and supplies an NSEC that does not list NS, reusing a record from an ordinary name to claim an unsigned delegation. Concluding Insecure here would put a signed zone outside DNSSEC's protection entirely — which is the point of the attack. The NS-bit check is the whole defence.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			// Refusing to read this as a delegation leaves the walk in the
			// parent zone, where the leaf's own signature is correctly
			// rejected as coming from a zone this one has no authority over.
			Reason: dnssec.ReasonSignerNotZone,
			Build: mutated(func(h *Hierarchy) error {
				if err := h.Replace(MiddleZone, LeafZone, dns.TypeDS, nil); err != nil {
					return err
				}
				return h.SetNSECBitmap(MiddleZone, LeafZone,
					[]uint16{dns.TypeRRSIG, dns.TypeNSEC})
			}),
		},
		{
			Name:   "ds-stripped-while-its-nsec-still-lists-it",
			Family: FamilyNSEC,
			Why:    "the parent's own signed NSEC says a DS is published at this delegation and the referral does not carry one. That is removal in transit, not an insecure delegation, and a validator that reads the absence rather than the zone's statement about it downgrades a secure delegation on request.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonDenialContradicted,
			Build: mutated(func(h *Hierarchy) error {
				// The NSEC at the delegation is left exactly as the zone
				// signed it; only the DS RRset is removed.
				return h.Replace(MiddleZone, LeafZone, dns.TypeDS, nil)
			}),
		},
		{
			Name:   "wildcard-answer-without-its-denial",
			Family: FamilyNSEC,
			Why:    "RFC 4035 section 5.3.4. The wildcard answer and its signature are genuine and verify; what is missing is the proof that the queried name did not exist in its own right. Without demanding it, a validator accepts one replayed wildcard answer for every name under the encloser, including names that have their own records.",
			Query:  WildcardMatch,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			// The zone publishes no denial records at all, so the accurate
			// complaint is that nothing was supplied rather than that what
			// was supplied fell short.
			Reason: dnssec.ReasonNoDenialProof,
			Build: func(spec Spec) (*Hierarchy, error) {
				return Build(withoutDenial(spec, LeafZone))
			},
		},
		{
			Name:   "nxdomain-with-an-unsigned-denial",
			Family: FamilyNSEC,
			Why:    "RFC 4035 section 5.4: the NSEC RRsets comprising a non-existence proof MUST themselves be authenticated. Anyone can put an NSEC record in a response, and an attacker forging a denial will supply one covering exactly the name they want denied. Receiving the record is not the proof; verifying it is.",
			Query:  MissingName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonNoDenialProof,
			Build: mutated(func(h *Hierarchy) error {
				// Both records an NXDOMAIN proof needs here: the one
				// covering the name and the one covering the wildcard.
				for _, owner := range []string{LeafZone, MailName} {
					if err := h.CorruptSignature(LeafZone, owner, dns.TypeNSEC); err != nil {
						return err
					}
				}
				return nil
			}),
		},
		{
			Name:   "ancestor-nsec-denying-the-childs-own-data",
			Family: FamilyNSEC,
			Why:    "RFC 6840 section 4.1, and the reason that section exists. Every zone cut has two NSEC records at the same name; the parent's is genuinely signed by a zone inside the chain of trust, and says only what the parent is entitled to say. Reused as a NODATA proof for the child's data it hides an entire signed zone, and every signature still verifies. Without the ancestor-delegation restriction this is a false Secure.",
			Query:  LeafZone,
			QType:  dns.TypeTXT,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonDenialWrongZone,
			Build: func(spec Spec) (*Hierarchy, error) {
				h, err := Build(spec)
				if err != nil {
					return nil, err
				}
				// The attacker keeps the parent's delegation NSEC — a real,
				// correctly signed record — and moves it.
				planted := h.Set(MiddleZone, LeafZone, dns.TypeNSEC)
				if len(planted) == 0 {
					return nil, fmt.Errorf("lab: the middle zone published no NSEC at %s to replay", LeafZone)
				}
				// Strip the DS so the walk cannot cross into the child, and
				// strip the referral's proof so it cannot tell that a cut is
				// there at all. It therefore stays in the parent zone, where
				// the planted record's signer matches.
				if err := h.Replace(MiddleZone, LeafZone, dns.TypeDS, nil); err != nil {
					return nil, err
				}
				h.SubstituteAuthority(LeafZone, dns.TypeDS, nil)
				h.SubstituteAuthority(LeafZone, dns.TypeTXT, planted)
				return h, nil
			},
		},
		{
			Name:   "insecure-delegation-claimed-by-a-child-side-nsec",
			Family: FamilyNSEC,
			Why:    "RFC 4035 section 5.2: the parent's NSEC and the child's are distinguished by the SOA bit, and a resolver MUST use the parent's when proving no DS exists. An NSEC carrying SOA describes a zone apex, which is a statement about the child's contents and not about the delegation. Reading it as a no-DS proof turns a secure delegation into an insecure one, which is the downgrade the whole chain exists to prevent.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonSignerNotZone,
			Build: mutated(func(h *Hierarchy) error {
				if err := h.Replace(MiddleZone, LeafZone, dns.TypeDS, nil); err != nil {
					return err
				}
				// NS and SOA together: this now reads as a zone apex rather
				// than as a delegation, so it cannot prove the absence of a
				// DS however tempting its bitmap looks.
				return h.SetNSECBitmap(MiddleZone, LeafZone,
					[]uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC})
			}),
		},
		{
			Name:     "nxdomain-for-a-name-that-exists",
			Family:   FamilyNSEC,
			Why:      "an empty non-terminal answered NXDOMAIN instead of NODATA. Nothing is forged: the covering NSEC is genuine and verifies, and only the response code changed. But its next name lies below the queried name, so that name provably exists, and accepting the stronger claim lets one header field delete a whole branch of a zone.",
			Query:    EmptyNonTerminal,
			QType:    dns.TypeA,
			At:       Now(),
			Expect:   dnssec.StatusBogus,
			Reason:   dnssec.ReasonDenialContradicted,
			KnownGap: "libunbound 1.19.2 reports Secure here and hands its client NODATA, having rewritten the response code it did not believe. delv 9.18 refuses the response, as Daddybound does (\"resolution failed: insecurity proof failed\"). Daddybound returns a verdict rather than an answer, so it has no way to correct a response — refusing is the only outcome available to it that does not endorse the claim. RFC 8020 §2 is why endorsing would matter: a resolver MAY apply the NXDOMAIN cut, treating every name below as unreachable, and MAY choose to do so only for responses validated with DNSSEC. Calling this Secure would hand that licence to an attacker who changed one header field, and take out the name that does exist.",
			Build: func(spec Spec) (*Hierarchy, error) {
				h, err := Build(spec)
				if err != nil {
					return nil, err
				}
				h.ForceRcode(EmptyNonTerminal, dns.TypeA, dns.RcodeNameError)
				return h, nil
			},
		},
		// NSEC3. The same questions as the NSEC block above, asked of a
		// hierarchy that differs in exactly one respect, so a failure here
		// and a pass there isolates the difference to the denial mechanism.
		{
			Name:   "nsec3-positive-answer",
			Family: FamilyNSEC3,
			Why:    "the positive case for the NSEC3 hierarchy. Without it, every NSEC3 scenario below could be passed by a validator that fails to read NSEC3 zones at all.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  nsec3(func(*Hierarchy) error { return nil }),
		},
		{
			Name:   "nsec3-nxdomain",
			Family: FamilyNSEC3,
			Why:    "RFC 5155 section 8.4: a closest encloser proof for the name, plus a record covering the wildcard at that encloser. Because a hash discards a name's ancestry, the encloser cannot be read off one record the way it can from an NSEC's next name; it has to be walked.",
			Query:  MissingName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  nsec3(func(*Hierarchy) error { return nil }),
		},
		{
			Name:   "nsec3-nodata",
			Family: FamilyNSEC3,
			Why:    "RFC 5155 section 8.5: the record matching the name must have neither the queried type nor CNAME set.",
			Query:  AnswerName,
			QType:  dns.TypeTXT,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  nsec3(func(*Hierarchy) error { return nil }),
		},
		{
			Name:   "nsec3-empty-non-terminal-nodata",
			Family: FamilyNSEC3,
			Why:    "RFC 5155 section 7.1 requires an NSEC3 record for every empty non-terminal, unlike NSEC which gives them none. Section 8.5 notes the ordinary NODATA test therefore covers them, with an empty type bitmap. A validator carrying NSEC's special case over to NSEC3 looks for a proof that is not there.",
			Query:  EmptyNonTerminal,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  nsec3(func(*Hierarchy) error { return nil }),
		},
		{
			Name:   "nsec3-wildcard-expanded-answer",
			Family: FamilyNSEC3,
			Why:    "RFC 5155 section 8.8: the wildcard answer offers a candidate closest encloser, and a record covering the next closer name is what turns the candidate into the real one, proving the queried name did not exist and that the right wildcard was used.",
			Query:  WildcardMatch,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  nsec3(func(*Hierarchy) error { return nil }),
		},
		{
			Name:   "nsec3-opt-out-insecure-delegation",
			Family: FamilyNSEC3,
			Why:    "RFC 5155 section 8.9's second branch, and the only place opt-out is allowed to establish anything. The delegation has no NSEC3 record of its own; what proves it insecure is a closest provable encloser proof whose covering record has the Opt-Out bit set. This is the shape almost every large TLD serves, so a validator that cannot read it cannot validate most of the Internet.",
			Query:  UnsignedName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusInsecure,
			Reason: dnssec.ReasonVerified,
			Build:  nsec3(func(*Hierarchy) error { return nil }),
		},
		{
			Name:   "nsec3-nxdomain-without-the-wildcard-denial",
			Family: FamilyNSEC3,
			Why:    "RFC 5155 section 8.4 requires both halves. The closest encloser proof still verifies; the record covering the wildcard is gone, so a wildcard could have answered and the name error is not proved.",
			Query:  MissingName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Build: func(spec Spec) (*Hierarchy, error) {
				h, err := Build(NSEC3Spec().withShift(spec))
				if err != nil {
					return nil, err
				}
				leaf := h.Zone(LeafZone)
				wc := leaf.nsec3Covering(wildcardUnder(LeafZone))
				if len(wc) == 0 {
					return nil, fmt.Errorf("lab: no NSEC3 covers the wildcard at %s", LeafZone)
				}
				return h, h.Replace(LeafZone, wc[0].Header().Name, dns.TypeNSEC3, nil)
			},
		},
		{
			Name:   "nsec3-iterations-above-the-ceiling",
			Family: FamilyNSEC3,
			Why:    "RFC 9276 section 3.2 offers a validator two responses to an expensive NSEC3: report insecure, or refuse. Reporting insecure would let an attacker downgrade a signed zone by publishing an expensive record, and the same section says so — treating a high iterations count as insecure leaves zones subject to attack. So refusing is the answer, and the reason must describe this validator's budget rather than accuse the zone.",
			Query:  MissingName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusIndeterminate,
			Reason: dnssec.ReasonDenialNotImplemented,
			Build: func(spec Spec) (*Hierarchy, error) {
				out := NSEC3Spec().withShift(spec)
				for i := range out.Zones {
					// Far above RFC 9276 Appendix A's measured
					// interoperability figure, and far above anything a
					// zone has any reason to publish.
					out.Zones[i].NSEC3Iterations = 2500
				}
				return Build(out)
			},
		},
		{
			Name:   "nsec3-with-an-unassigned-hash-algorithm",
			Family: FamilyNSEC3,
			Why:    "RFC 5155 section 8.1: a validator MUST ignore NSEC3 RRs with unknown hash types, and the same section states the consequence — responses containing only such records will generally be considered bogus. Ignoring a record the standard says to ignore is not a limitation of the validator, so the response has simply failed to prove its claim. Both reference validators agree, and both caught Daddybound calling this Indeterminate.",
			Query:  MissingName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonNoDenialProof,
			Build: nsec3(func(h *Hierarchy) error {
				return h.SetNSEC3Hash(LeafZone, 99)
			}),
		},
		{
			Name:   "nsec3-nodata-contradicted-by-its-own-record",
			Family: FamilyNSEC3,
			Why:    "RFC 5155 section 8.5: the record matching the name must not have the queried type set. Here it does, and the answer says the type is absent. The zone's own signed statement refutes the response it arrived with, which is what stripping an RRset in transit produces.",
			Query:  AnswerName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonDenialContradicted,
			Build: nsec3(func(h *Hierarchy) error {
				if err := h.Replace(LeafZone, AnswerName, dns.TypeA, nil); err != nil {
					return err
				}
				// Without the removal the name owns nothing, so the lab
				// answers NXDOMAIN rather than NODATA and a different rule
				// catches it. The response code is forced back so that this
				// scenario tests the bitmap check and only that.
				h.ForceRcode(AnswerName, dns.TypeA, dns.RcodeSuccess)
				return nil
			}),
		},
		{
			Name:   "nsec3-record-owned-by-another-zone",
			Family: FamilyNSEC3,
			Why:    "RFC 5155 section 7.1: an NSEC3 owner name is the hash prepended as a single label to the zone name. A validator that matches on the label alone accepts a record placed under a different zone, and the label is the part an attacker can arrange to match. The record here is genuinely signed and its hash is genuinely the right one; only the zone it sits in is wrong.",
			Query:  MissingName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Build: nsec3(func(h *Hierarchy) error {
				leaf := h.Zone(LeafZone)
				cover := leaf.nsec3Covering(MissingName)
				if len(cover) == 0 {
					return fmt.Errorf("lab: no NSEC3 covers %s", MissingName)
				}
				return h.ReownNSEC3(LeafZone, cover[0].Header().Name, "sub."+LeafZone)
			}),
		},
		{
			Name:   "nsec3-encloser-proved-by-a-delegation-record",
			Family: FamilyNSEC3,
			Why:    "RFC 5155 section 8.3: after finding the closest encloser, a validator MUST check that record is from the proper zone — DNAME clear, and NS set only if SOA is set. A delegation record has NS without SOA, and it belongs to the parent, which has no authority over anything below the cut. The RFC states the consequence itself: otherwise an attacker is using them to falsely deny the existence of RRs for which the server is not authoritative.",
			Query:  "missing.example.dnsdaddylab.",
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonDenialWrongZone,
			Build: func(spec Spec) (*Hierarchy, error) {
				h, err := Build(NSEC3Spec().withShift(spec))
				if err != nil {
					return nil, err
				}
				// Every NSEC3 the middle zone signed. Real records, in the
				// zone that made them.
				var planted []dns.RR
				middle := h.Zone(MiddleZone)
				for k, records := range middle.sets {
					if k.rrtype == dns.TypeNSEC3 {
						planted = append(planted, records...)
					}
				}
				sortRecords(planted)

				// Strip the DS and the referral's proof so the walk cannot
				// cross the cut and stays in the parent zone, where these
				// records verify.
				if err := h.Replace(MiddleZone, LeafZone, dns.TypeDS, nil); err != nil {
					return nil, err
				}
				h.SubstituteAuthority(LeafZone, dns.TypeDS, nil)
				h.SubstituteAuthority("missing.example.dnsdaddylab.", dns.TypeA, planted)
				return h, nil
			},
		},
		{
			Name:     "nsec3-opt-out-proves-no-ds",
			Family:   FamilyNSEC3,
			Why:      "RFC 5155 section 8.6's second branch, asked directly. No NSEC3 matches the delegation name, and what establishes that no DS is published is a closest provable encloser proof whose covering record has the Opt-Out bit set. This is the positive case for the one question opt-out is allowed to answer.",
			Query:    UnsignedZone,
			QType:    dns.TypeDS,
			At:       Now(),
			Expect:   dnssec.StatusSecure,
			Reason:   dnssec.ReasonVerified,
			KnownGap: "delv 9.18.39 agrees (fully validated); libunbound 1.19.2 reports the answer insecure instead. RFC 5155 §8.6 is titled \"Validating No Data Responses, QTYPE is DS\" and states what a validator MUST verify; those checks pass, so the response validates. The proof is also sound rather than merely permitted: §7.1 requires an NSEC3 at every secure delegation, so that name's hash is itself an owner in the chain and no record's open interval contains it. An attacker cannot fabricate a signed record, and omitting the real one leaves nothing covering the next closer name, so the proof fails rather than succeeding wrongly. Opt-out therefore cannot hide a secure delegation, and there is nothing left for the weaker verdict to protect against.",
			Build:    nsec3(func(*Hierarchy) error { return nil }),
		},
		{
			Name:   "nsec3-no-ds-claimed-without-opt-out",
			Family: FamilyNSEC3,
			Why:    "the same proof with the Opt-Out bit cleared. RFC 5155 section 6: an Opt-Out record does not assert the existence or non-existence of the insecure delegations it may cover, and a record without the bit asserts that nothing at all lies in its span. So without the bit the absence of a record at the delegation name is not a statement about that name, and reading it as one would let a response prove an insecure delegation by omission — the cheapest downgrade there is.",
			Query:  UnsignedZone,
			QType:  dns.TypeDS,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonDenialIncomplete,
			Build: nsec3(func(h *Hierarchy) error {
				middle := h.Zone(MiddleZone)
				cover := middle.nsec3Covering(UnsignedZone)
				if len(cover) == 0 {
					return fmt.Errorf("lab: no NSEC3 covers %s", UnsignedZone)
				}
				return h.SetNSEC3Flags(MiddleZone, cover[0].Header().Name, 0)
			}),
		},
		{
			Name:   "nsec3-wildcard-answer-without-the-next-closer-denial",
			Family: FamilyNSEC3,
			Why:    "RFC 5155 section 8.8. The wildcard answer and its signature verify, and the same signature is valid for every name under the encloser. RFC 5155 section 7.2.6 requires exactly one record alongside it — the one covering the next closer name — and here a different, equally genuine record from the same zone is sent instead. Without checking what the record covers, one captured wildcard answer becomes replayable over names that have their own records.",
			Query:  WildcardMatch,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonDenialIncomplete,
			Build: nsec3(func(h *Hierarchy) error {
				// Substituting rather than deleting, on purpose. Deleting
				// the record leaves the authority section empty, and the
				// response is then refused for carrying no proof at all —
				// which is a different rule, and would leave this one
				// untested. Sending a real record that proves the wrong
				// thing is also the more realistic attack.
				leaf := h.Zone(LeafZone)
				apex := leaf.nsec3Matching(LeafZone)
				if len(apex) == 0 {
					return fmt.Errorf("lab: %s has no NSEC3 at its apex", LeafZone)
				}
				if containsRR(leaf.nsec3Covering(WildcardMatch), apex[0]) {
					return fmt.Errorf("lab: the apex NSEC3 happens to cover %s, so this scenario would prove nothing", WildcardMatch)
				}
				h.SubstituteAuthority(WildcardMatch, dns.TypeA, apex)
				return nil
			}),
		},
		// CNAME chains. A CNAME answer is a sequence rather than an RRset,
		// so the interesting cases are about what the sequence is worth: a
		// chain is only as authenticated as its weakest link, and each of
		// these pins one way for a link to be weak.
		{
			Name:   "cname-same-zone",
			Why:    "the positive case for aliases. RFC 1034 section 3.6.2 makes a CNAME the answer to a query for any other type at the name, so this is reached by asking for an address. Both the alias and the address it points at are signed by the same zone.",
			Family: FamilyAlias,
			Query:  AliasName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
		},
		{
			Name:   "cname-across-a-zone-cut",
			Why:    "the target is in a sibling zone, so it needs its own walk from the trust anchor rather than the zone the alias lived in. A validator that carried the first hop's keys forward would be authenticating the second zone's data with the wrong ones.",
			Family: FamilyAlias,
			Query:  CrossZoneAlias,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
		},
		{
			Name:   "cname-chain-of-three-hops",
			Why:    "multi-hop chains are ordinary in real DNS, and each hop is a separate RRset with a separate signature. A validator that checked only the first or only the last would report the whole answer on the strength of part of it.",
			Family: FamilyAlias,
			Query:  AliasHop1,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
		},
		{
			Name:   "cname-answering-AAAA",
			Why:    "the alias is the answer to a query for any type at the name, not only the type it happens to point at. Asking for AAAA reaches the same CNAME and then a name with no AAAA, so the chain ends in an authenticated NODATA rather than in records.",
			Family: FamilyAlias,
			Query:  AliasName,
			QType:  dns.TypeAAAA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
		},
		{
			Name:   "cname-from-an-insecure-zone-into-a-signed-one",
			Family: FamilyAlias,
			Why:    "the redirection is the answer. This alias lives in a zone delegated without a DS, so nothing authenticates where it points, while the name it points at is properly signed. Whoever controls the unsigned zone therefore chooses the destination, and the signature on that destination attests that the destination is genuine — never that this query should have been sent there. Reporting Secure would be authenticating an attacker's choice.\n\nDaddybound reaches Insecure by stopping: the parent's NSEC proves no DS exists, everything below is Insecure by RFC 4033 §5, and the walk returns without following the alias at all. So this scenario pins the stop rather than the combination — the combination is what cname-into-an-insecure-zone exercises, where a Secure first hop meets an Insecure second. It stays correct either way: were the chase ever extended to follow this alias, the weakest of Insecure and Secure is still Insecure.",
			Query:  InsecureAliasName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusInsecure,
			Build:  Build,
		},
		{
			Name:   "cname-into-an-insecure-zone",
			Why:    "the alias is signed and the target is below a delegation with no DS. The answer cannot be Secure — anyone can rewrite the unsigned part — and it cannot be Bogus either, because nothing failed to validate. Insecure is the whole answer's status, not just the second hop's, and a validator reporting the first hop's Secure would be calling rewritable data authenticated.",
			Family: FamilyAlias,
			Query:  AliasToInsecure,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusInsecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
		},
		{
			Name:   "cname-from-a-wildcard",
			Why:    "RFC 4035 section 5.3.4 applies to an alias exactly as it does to an address: one signed wildcard CNAME answers for every name under its encloser, so the expansion has to be shown legitimate. A validator that demanded the wildcard proof for addresses and not for aliases would let one captured answer redirect every sibling name.",
			Family: FamilyAlias,
			Query:  WildcardAliasMatch,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusSecure,
			Reason: dnssec.ReasonVerified,
			Build:  Build,
		},
		{
			Name:   "cname-loop",
			Why:    "two aliases pointing at each other. Every record is authentic — the zone signed the loop — so this is a statement about the shape of the data rather than its authenticity, and must not be Bogus. What it must be is finite.",
			Family: FamilyAlias,
			Query:  AliasLoopA,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusIndeterminate,
			Reason: dnssec.ReasonAliasLoop,
			Build:  Build,
		},
		{
			Name:   "cname-with-a-broken-signature",
			Why:    "the alias itself fails to authenticate. The target may be perfectly signed, so a validator that resolved the target and reported its verdict would report Secure for an answer reached through a forged redirection — which is the whole attack.",
			Family: FamilyAlias,
			Query:  AliasName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonSignatureCryptoFailed,
			Build: mutated(func(h *Hierarchy) error {
				return h.CorruptSignature(LeafZone, AliasName, dns.TypeCNAME)
			}),
		},
		{
			Name:   "cname-to-a-broken-terminal",
			Why:    "the mirror image: the alias is genuine and the RRset it points at is tampered with. A validator that stopped once the alias verified would report Secure for data that failed to validate.",
			Family: FamilyAlias,
			Query:  AliasName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonSignatureCryptoFailed,
			Build: mutated(func(h *Hierarchy) error {
				return h.CorruptSignature(LeafZone, AnswerName, dns.TypeA)
			}),
		},
		{
			Name:   "cname-broken-in-the-middle-of-a-chain",
			Why:    "three hops with the middle one tampered with. Neither end of the chain is enough to notice, so this fails a validator that samples the chain rather than checking all of it.",
			Family: FamilyAlias,
			Query:  AliasHop1,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonSignatureCryptoFailed,
			Build: mutated(func(h *Hierarchy) error {
				return h.CorruptSignature(LeafZone, AliasHop2, dns.TypeCNAME)
			}),
		},
		{
			Name:   "two-cnames-at-one-name",
			Why:    "RFC 2181 section 10.1 forbids a CNAME coexisting with other data, and so with a second CNAME. Following one of them means choosing a target out of a response an attacker ordered, which is a verdict they would be choosing. Refusing is the only answer that does not hand them the decision.",
			Family: FamilyAlias,
			Query:  AliasName,
			QType:  dns.TypeA,
			At:     Now(),
			Expect: dnssec.StatusBogus,
			Reason: dnssec.ReasonAliasAmbiguous,
			Build: mutated(func(h *Hierarchy) error {
				return h.AddSecondCNAME(LeafZone, AliasName, MissingName)
			}),
		},
		{
			Name:     "cname-chain-longer-than-the-hop-limit",
			Why:      "a chain arrives from the network and each hop costs a full walk from the trust anchor. Reaching the limit must be Indeterminate rather than Bogus: a deeply aliased zone is unusual, not forged, and accusing it would be this validator blaming data for its own budget.",
			Family:   FamilyAlias,
			Query:    longAliasChainStart,
			QType:    dns.TypeA,
			At:       Now(),
			Expect:   dnssec.StatusIndeterminate,
			Reason:   dnssec.ReasonResourceLimit,
			NoOracle: "the limit under test is Daddybound's shipped hop budget. Every link is correctly signed, so a reference validator either resolves the chain or stops on a budget of its own; either way the disagreement would be about two numbers rather than about the data.",
			Build:    buildLongAliasChain,
		},
		{
			Name:     "no-trust-anchor",
			Family:   FamilyConfiguration,
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

// withoutDenial returns the same specification with one zone publishing no
// NSEC chain.
//
// A signed zone with no denial records is a real and broken configuration,
// and it is the shape that separates "this response failed to prove its
// claim" from "this response proved something else". Building it from the
// specification rather than by deleting records afterwards means the zone is
// internally consistent: nothing else references records that are not there.
func withoutDenial(spec Spec, zone string) Spec {
	out := spec
	out.Zones = append([]ZoneSpec(nil), spec.Zones...)
	for i := range out.Zones {
		if dns.CanonicalName(out.Zones[i].Name) == dns.CanonicalName(zone) {
			out.Zones[i].NoDenial = true
		}
	}
	return out
}

// nsec3 adapts a mutation into a Scenario Build function over the NSEC3
// hierarchy, preserving the time shift the caller asked for.
func nsec3(apply func(*Hierarchy) error) func(Spec) (*Hierarchy, error) {
	return func(spec Spec) (*Hierarchy, error) {
		h, err := Build(NSEC3Spec().withShift(spec))
		if err != nil {
			return nil, err
		}
		if err := apply(h); err != nil {
			return nil, err
		}
		return h, nil
	}
}

// withShift copies the validity window of another specification.
//
// Scenario.Shifted moves a specification's signature window so that a
// reference validator with no clock override sees current fixtures. A
// scenario that builds its own specification from scratch would throw that
// away and produce signatures that expired months ago, and the resulting
// failure would look like a validation bug rather than a harness one.
func (s Spec) withShift(from Spec) Spec {
	out := s
	out.Inception = from.Inception
	out.Expiration = from.Expiration
	return out
}

// sortRecords puts records into a deterministic order, so a planted authority
// section is the same on every run and a failing scenario can be diffed.
func sortRecords(records []dns.RR) {
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i].Header(), records[j].Header()
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Rrtype < b.Rrtype
	})
}

// longAliasChainStart is the head of a correctly signed CNAME chain built to
// be one link longer than the validator will follow.
const longAliasChainStart = "chain00." + LeafZone

// buildLongAliasChain adds a signed CNAME chain longer than
// dnssec.DefaultLimits().MaxAliasHops, terminating at a real address.
//
// The length is derived from the limit rather than written down, so the
// scenario cannot quietly stop testing anything when the budget changes. It
// is the *shipped* budget deliberately: a test-only limit injected into the
// config proves the counter increments, which denial_resource_test.go already
// does directly, whereas this proves the number an operator actually runs
// bounds the work an attacker can ask for.
//
// Every link is properly signed. That is the point — the scenario has to fail
// on length alone, so that a validator which happened to reject it for any
// other reason would still be wrong. Reaching the cap is Indeterminate and
// never Bogus: a long chain is unusual, not forged, and calling it forged
// would be this validator blaming data for its own budget.
func buildLongAliasChain(spec Spec) (*Hierarchy, error) {
	hops := dnssec.DefaultLimits().MaxAliasHops + 1

	out := spec
	out.Zones = append([]ZoneSpec(nil), spec.Zones...)
	for i := range out.Zones {
		if out.Zones[i].Name != LeafZone {
			continue
		}
		records := append([]dns.RR(nil), out.Zones[i].Records...)
		for hop := 0; hop < hops; hop++ {
			target := fmt.Sprintf("chain%02d.%s", hop+1, LeafZone)
			if hop == hops-1 {
				target = AnswerName
			}
			records = append(records, cname(fmt.Sprintf("chain%02d.%s", hop, LeafZone), target))
		}
		out.Zones[i].Records = records
		return Build(out)
	}
	return nil, fmt.Errorf("lab: %s is not in the specification", LeafZone)
}
