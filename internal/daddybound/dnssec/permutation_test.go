package dnssec_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// An RRset is a set. RFC 2181 §5 defines it by (owner, class, type)
// membership and says nothing about order, and a DNS response may carry its
// members in any order at all — an attacker on the path can reorder them
// freely without touching a byte of signed data.
//
// So a validator whose verdict depends on the order records arrive in has a
// verdict an attacker can choose. These tests assert the property directly,
// over every ordering rather than over a sample.

// permutations returns every ordering of n indices.
func permutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var out [][]int
	var rec func(cur []int, left []int)
	rec = func(cur []int, left []int) {
		if len(left) == 0 {
			out = append(out, append([]int{}, cur...))
			return
		}
		for i := range left {
			next := make([]int, 0, len(left)-1)
			next = append(next, left[:i]...)
			next = append(next, left[i+1:]...)
			rec(append(cur, left[i]), next)
		}
	}
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	rec(nil, idx)
	return out
}

// A mixed DS RRset is the case the review found: a usable digest type that
// definitively fails alongside an unusable one that cannot be evaluated.
//
// RFC 6840 §5.2 settles it. DS records with unusable digest types are
// "treated the same way as DS records referring to DNSKEY RRs of unknown or
// unsupported public key algorithms" — that is, filtered out before anything
// is concluded — and only "if none are left" is the zone treated as unsigned.
// A usable path that fails is therefore a real failure, and an unusable
// alternative cannot soften it whatever order the two arrive in.
func TestMixedDSRRsetVerdictIsOrderIndependent(t *testing.T) {
	tests := []struct {
		name string
		// digests describes the DS records to publish for the leaf zone.
		digests []struct {
			dt      dnssec.DigestType
			corrupt bool
		}
		wantStatus dnssec.ValidationStatus
		wantReason dnssec.Reason
	}{
		{
			name: "a usable digest that fails is not softened by an unusable one",
			digests: []struct {
				dt      dnssec.DigestType
				corrupt bool
			}{
				{dnssec.DigestSHA256, true},  // usable, and definitively wrong
				{dnssec.DigestGOST94, false}, // unusable: cannot be evaluated
			},
			wantStatus: dnssec.StatusBogus,
			wantReason: dnssec.ReasonDSDigestMismatch,
		},
		{
			name: "a usable digest that matches authenticates regardless of company",
			digests: []struct {
				dt      dnssec.DigestType
				corrupt bool
			}{
				{dnssec.DigestGOST94, false},
				{dnssec.DigestSHA256, false},
				{dnssec.DigestSHA1, true},
			},
			wantStatus: dnssec.StatusSecure,
			wantReason: dnssec.ReasonVerified,
		},
		{
			name: "only unusable digests leaves nothing to evaluate",
			digests: []struct {
				dt      dnssec.DigestType
				corrupt bool
			}{
				{dnssec.DigestGOST94, false},
				{dnssec.DigestSM3, false},
			},
			wantStatus: dnssec.StatusIndeterminate,
			wantReason: dnssec.ReasonUnsupportedDigest,
		},
		{
			name: "two usable digests, both wrong",
			digests: []struct {
				dt      dnssec.DigestType
				corrupt bool
			}{
				{dnssec.DigestSHA256, true},
				{dnssec.DigestSHA1, true},
			},
			wantStatus: dnssec.StatusBogus,
			wantReason: dnssec.ReasonDSDigestMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, perm := range permutations(len(tc.digests)) {
				h, err := lab.Standard()
				if err != nil {
					t.Fatalf("build: %v", err)
				}

				var dsSet []*dns.DS
				for _, i := range perm {
					ds, err := h.DSFor(lab.LeafZone, tc.digests[i].dt, tc.digests[i].corrupt)
					if err != nil {
						t.Fatalf("DS: %v", err)
					}
					dsSet = append(dsSet, ds)
				}
				if err := h.SetDSRRset(lab.LeafZone, dsSet); err != nil {
					t.Fatalf("set DS: %v", err)
				}

				v, err := h.Validator(lab.Now())
				if err != nil {
					t.Fatalf("validator: %v", err)
				}
				got := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)

				order := fmt.Sprintf("%v", perm)
				if got.Status != tc.wantStatus {
					t.Errorf("order %s: status = %s, want %s\n%s", order, got.Status, tc.wantStatus, got.Trace())
				}
				if got.Reason != tc.wantReason {
					t.Errorf("order %s: reason = %s, want %s\n%s", order, got.Reason, tc.wantReason, got.Trace())
				}
			}
		})
	}
}

// signatureCase describes one RRSIG to attach to the answer RRset.
type signatureCase struct {
	name   string
	mutate func(*dns.RRSIG)
}

// An RRset may legitimately carry several signatures — during a key rollover,
// and permanently in a zone signed with more than one algorithm — and the
// order they arrive in is not meaningful. RFC 6840 §5.4:
//
//	a resolver SHOULD accept any valid RRSIG as sufficient, and only
//	determine that an RRset is Bogus if all RRSIGs fail validation.
//
// So the presence of one valid signature must decide the outcome wherever it
// sits in the list, and when none is valid the reported reason must still be
// a function of the set rather than of the order.
func TestSignaturePermutationDoesNotChangeTheVerdict(t *testing.T) {
	// Corrupting a signature's bytes: admissible, and the arithmetic fails.
	cryptoFail := signatureCase{"crypto-failed", func(s *dns.RRSIG) {
		s.Signature = flipBase64Bit(s.Signature)
	}}
	// Expired: inadmissible before any cryptography is attempted.
	expired := signatureCase{"expired", func(s *dns.RRSIG) {
		s.Inception -= 2 * 365 * 24 * 3600
		s.Expiration -= 365 * 24 * 3600
	}}
	// An algorithm absent from the zone's DNSKEY RRset, which RFC 6840 §5.12
	// requires be disregarded entirely.
	foreignAlg := signatureCase{"foreign-algorithm", func(s *dns.RRSIG) {
		s.Algorithm = uint8(dnssec.AlgED448)
	}}

	tests := []struct {
		name string
		// extra signatures added alongside the zone's own valid one, unless
		// dropValid is set.
		extra      []signatureCase
		dropValid  bool
		wantStatus dnssec.ValidationStatus
		wantReason dnssec.Reason
	}{
		{
			name:       "one valid signature suffices however many unusable ones accompany it",
			extra:      []signatureCase{cryptoFail, expired, foreignAlg},
			wantStatus: dnssec.StatusSecure,
			wantReason: dnssec.ReasonVerified,
		},
		{
			name:       "with no valid signature the most diagnostic reason is reported",
			extra:      []signatureCase{cryptoFail, expired},
			dropValid:  true,
			wantStatus: dnssec.StatusBogus,
			// A signature that was fully admissible and failed the
			// arithmetic localises the problem better than one that expired,
			// and outranks it whichever order they arrive in.
			wantReason: dnssec.ReasonSignatureCryptoFailed,
		},
		{
			name:       "only disregarded signatures is still bogus, never indeterminate",
			extra:      []signatureCase{foreignAlg, foreignAlg},
			dropValid:  true,
			wantStatus: dnssec.StatusBogus,
			wantReason: dnssec.ReasonNoMatchingKey,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, perm := range permutations(len(tc.extra)) {
				h, err := lab.Standard()
				if err != nil {
					t.Fatalf("build: %v", err)
				}
				for _, i := range perm {
					c := tc.extra[i]
					if err := h.AddSignature(lab.LeafZone, lab.AnswerName, dns.TypeA, c.mutate); err != nil {
						t.Fatalf("add %s: %v", c.name, err)
					}
				}
				if tc.dropValid {
					if err := h.DropOriginalSignature(lab.LeafZone, lab.AnswerName, dns.TypeA); err != nil {
						t.Fatalf("drop valid: %v", err)
					}
				}

				v, err := h.Validator(lab.Now())
				if err != nil {
					t.Fatalf("validator: %v", err)
				}
				got := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)

				order := describeOrder(perm, tc.extra)
				if got.Status != tc.wantStatus {
					t.Errorf("order %s: status = %s, want %s\n%s", order, got.Status, tc.wantStatus, got.Trace())
				}
				if got.Reason != tc.wantReason {
					t.Errorf("order %s: reason = %s, want %s\n%s", order, got.Reason, tc.wantReason, got.Trace())
				}
			}
		})
	}
}

func describeOrder(perm []int, cases []signatureCase) string {
	names := make([]string, 0, len(perm))
	for _, i := range perm {
		names = append(names, cases[i].name)
	}
	return fmt.Sprintf("%v", names)
}

// flipBase64Bit corrupts one bit of a base64-encoded signature, leaving it
// well-formed and the right length for its algorithm so that the failure has
// to come from the arithmetic rather than from a length check.
func flipBase64Bit(s string) string {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) == 0 {
		return s
	}
	raw[len(raw)/2] ^= 0x01
	return base64.StdEncoding.EncodeToString(raw)
}

// The same property for the records inside an RRset. Signed data is built
// from a canonical ordering the validator computes for itself (RFC 4034
// §6.3), so the order records arrive in must be irrelevant — and a
// three-member RRset with RDATA lengths that disagree with RDATA ordering is
// exactly where a length-based sort would show through.
func TestRRsetPermutationDoesNotChangeTheVerdict(t *testing.T) {
	for _, perm := range permutations(3) {
		h, err := lab.Standard()
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if err := h.PermuteRRset(lab.LeafZone, lab.MailName, dns.TypeMX, perm); err != nil {
			t.Fatalf("permute: %v", err)
		}

		v, err := h.Validator(lab.Now())
		if err != nil {
			t.Fatalf("validator: %v", err)
		}
		got := v.Validate(context.Background(), lab.MailName, dns.TypeMX)

		if got.Status != dnssec.StatusSecure {
			t.Errorf("order %v: status = %s, want secure\n%s", perm, got.Status, got.Trace())
		}
	}
}

// Failure monotonicity, stated precisely because a loose version of it would
// be wrong.
//
// The property is NOT "adding records can never improve a verdict". That is
// false and must stay false: DNSSEC is deliberately multi-path, and adding a
// valid signature, or a DS with a usable digest, is exactly how a zone in the
// middle of a key or algorithm rollover keeps validating. RFC 6840 §5.4 says
// so directly — "a resolver SHOULD accept any valid RRSIG as sufficient".
//
// The property that must hold is narrower:
//
//	Adding a record that this validator cannot act on must not change the
//	verdict at all.
//
// "Cannot act on" means an RRSIG whose algorithm is absent from the zone's
// DNSKEY RRset (RFC 6840 §5.12 requires it be disregarded) or a DS whose
// digest type is unusable (RFC 6840 §5.2 requires it be set aside). Such a
// record carries no information about the data, so it cannot make a verdict
// better and — the direction that matters — it cannot make a definitive
// Bogus into an allow-prone Indeterminate.
//
// Both defects the review found were violations of exactly this.
func TestUnusableRecordsDoNotChangeTheVerdict(t *testing.T) {
	baseline := func(t *testing.T, mutate func(*lab.Hierarchy) error) dnssec.ValidationResult {
		t.Helper()
		h, err := lab.Standard()
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if mutate != nil {
			if err := mutate(h); err != nil {
				t.Fatalf("mutate: %v", err)
			}
		}
		v, err := h.Validator(lab.Now())
		if err != nil {
			t.Fatalf("validator: %v", err)
		}
		return v.Validate(context.Background(), lab.AnswerName, dns.TypeA)
	}

	// The starting points: one healthy, one definitively broken.
	starts := []struct {
		name   string
		mutate func(*lab.Hierarchy) error
	}{
		{"a correctly signed answer", nil},
		{"a tampered answer", func(h *lab.Hierarchy) error {
			return h.TamperData(lab.LeafZone, lab.AnswerName, dns.TypeA, func(rr dns.RR) {
				rr.(*dns.A).A = netIPv4(198, 51, 100, 66)
			})
		}},
		{"a corrupted delegation digest", func(h *lab.Hierarchy) error {
			return h.CorruptDS(lab.LeafZone)
		}},
		{
			// The start state that isolates RFC 6840 §5.12 from the reason
			// ranking. An answer with no signature at all reports
			// missing_rrsig, which ranks *below* an algorithm-support
			// reason — so if an unusable RRSIG were allowed to contribute a
			// reason, it would win, and the verdict would slide from Bogus
			// to Indeterminate.
			//
			// Every other start state here is already protected by the
			// ranking alone, which is why removing the §5.12 disregard
			// leaves them unchanged. This one is not, and it is the exact
			// downgrade attack the review found.
			"an answer with its signature stripped",
			func(h *lab.Hierarchy) error {
				return h.RemoveSignatures(lab.LeafZone, lab.AnswerName, dns.TypeA)
			},
		},
	}

	// Records a validator must disregard or set aside.
	additions := []struct {
		name string
		add  func(*lab.Hierarchy) error
	}{
		{"an RRSIG naming an algorithm absent from the DNSKEY RRset", func(h *lab.Hierarchy) error {
			return h.AddSignature(lab.LeafZone, lab.AnswerName, dns.TypeA, func(s *dns.RRSIG) {
				s.Algorithm = uint8(dnssec.AlgED448)
			})
		}},
		{"an RRSIG naming an algorithm policy refuses and the zone does not use", func(h *lab.Hierarchy) error {
			return h.AddSignature(lab.LeafZone, lab.AnswerName, dns.TypeA, func(s *dns.RRSIG) {
				s.Algorithm = uint8(dnssec.AlgRSASHA1)
			})
		}},
		{"a DS with a digest type this build cannot compute", func(h *lab.Hierarchy) error {
			existing := h.Set(lab.MiddleZone, lab.LeafZone, dns.TypeDS)
			var dsSet []*dns.DS
			for _, rr := range existing {
				if ds, ok := rr.(*dns.DS); ok {
					dsSet = append(dsSet, ds)
				}
			}
			extra, err := h.DSFor(lab.LeafZone, dnssec.DigestGOST94, false)
			if err != nil {
				return err
			}
			return h.SetDSRRset(lab.LeafZone, append(dsSet, extra))
		}},
	}

	for _, start := range starts {
		t.Run(start.name, func(t *testing.T) {
			before := baseline(t, start.mutate)

			for _, add := range additions {
				t.Run(add.name, func(t *testing.T) {
					after := baseline(t, func(h *lab.Hierarchy) error {
						if start.mutate != nil {
							if err := start.mutate(h); err != nil {
								return err
							}
						}
						return add.add(h)
					})

					// The status, and only the status.
					//
					// The reason may legitimately sharpen: an RRset with no
					// signature reports missing_rrsig, and once an unusable
					// signature is attached the more accurate statement is
					// that no key corresponds to it. Both are Bogus, both
					// point at the data, and insisting on reason equality
					// would forbid a strictly better message.
					//
					// The status is where the security property lives,
					// because Bogus and Indeterminate are what a caller acts
					// on — and the downgrade this test exists to catch shows
					// up here as bogus becoming indeterminate.
					if after.Status != before.Status {
						t.Errorf("adding %s changed the verdict from %s (%s) to %s (%s)\n%s",
							add.name, before.Status, before.Reason, after.Status, after.Reason, after.Trace())
					}
				})
			}
		})
	}
}

// The counterpart, so the property above cannot be satisfied by a validator
// that simply ignores everything it is given. A record the validator *can*
// act on must still be able to change the outcome, which is what multi-path
// DNSSEC depends on.
func TestAUsableRecordCanStillRescueAnRRset(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Break the zone's own signature, then add a valid one from the same
	// key — the shape of a rollover, where one signature is stale and
	// another is current.
	if err := h.AddSignature(lab.LeafZone, lab.AnswerName, dns.TypeA, func(s *dns.RRSIG) {}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := h.CorruptSignatureAt(lab.LeafZone, lab.AnswerName, dns.TypeA, 0); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	got := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)
	if !got.Secure() {
		t.Errorf("one broken and one valid signature should validate (RFC 6840 §5.4); got %s\n%s",
			got.Status, got.Trace())
	}
}

func netIPv4(a, b, c, d byte) net.IP { return net.IPv4(a, b, c, d) }
