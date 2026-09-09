package dnssec_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// Properties every denial proof must have, tested against the proofs the lab
// actually produces rather than against hand-written fixtures.
//
// A scenario says "this input gives that verdict". A property says something
// about *all* inputs of a shape, and the four here are the ones a denial
// implementation tends to get wrong quietly:
//
//   - order independence: an attacker on the path chooses the order records
//     arrive in, so a verdict that depends on it is a verdict they influence;
//   - proof completeness: every record a correct server ships is load-bearing,
//     so removing any one of them must break the proof. A validator that
//     passes without needing a record was never checking it;
//   - tamper resistance: a single flipped bit in any signature must cost the
//     proof, because "the record was there" is not the same as "the record
//     verified";
//   - monotonic security: taking evidence away never improves a verdict.

// provingQuestion is the question whose response carries the proof under test.
//
// For most scenarios that is the query itself. An insecure delegation is the
// exception: what has to be proved is the absence of a DS at the cut, and
// that proof rides on the parent's answer to a DS question the caller never
// asked.
type provingQuestion struct {
	scenario string
	name     string
	rrtype   uint16
	expect   dnssec.ValidationStatus
	spec     func() lab.Spec
}

func provingQuestions() []provingQuestion {
	nsec := lab.StandardSpec
	n3 := lab.NSEC3Spec
	return []provingQuestion{
		{"nxdomain", lab.MissingName, dns.TypeA, dnssec.StatusSecure, nsec},
		{"nodata", lab.AnswerName, dns.TypeTXT, dnssec.StatusSecure, nsec},
		{"empty-non-terminal-nodata", lab.EmptyNonTerminal, dns.TypeA, dnssec.StatusSecure, nsec},
		{"wildcard-expanded-answer", lab.WildcardMatch, dns.TypeA, dnssec.StatusSecure, nsec},
		{"insecure-delegation", lab.UnsignedZone, dns.TypeDS, dnssec.StatusSecure, nsec},

		{"nsec3-nxdomain", lab.MissingName, dns.TypeA, dnssec.StatusSecure, n3},
		{"nsec3-nodata", lab.AnswerName, dns.TypeTXT, dnssec.StatusSecure, n3},
		{"nsec3-empty-non-terminal-nodata", lab.EmptyNonTerminal, dns.TypeA, dnssec.StatusSecure, n3},
		{"nsec3-wildcard-expanded-answer", lab.WildcardMatch, dns.TypeA, dnssec.StatusSecure, n3},
		{"nsec3-opt-out-insecure-delegation", lab.UnsignedZone, dns.TypeDS, dnssec.StatusSecure, n3},
	}
}

// authorityOf returns the records a correct server sends in the authority
// section for one question, and the verdict Daddybound reaches on it.
func authorityOf(t *testing.T, q provingQuestion) ([]dns.RR, dnssec.ValidationStatus) {
	t.Helper()
	h, err := lab.Build(q.spec())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	resp, err := h.Lookup(context.Background(), q.name, q.rrtype)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	got := v.Validate(context.Background(), q.name, q.rrtype)
	return resp.Authority, got.Status
}

// validateWithAuthority replays a question with a substituted authority
// section, which is exactly what an on-path attacker can do: keep the
// signatures, change what arrives.
func validateWithAuthority(t *testing.T, q provingQuestion, authority []dns.RR) dnssec.ValidationResult {
	t.Helper()
	h, err := lab.Build(q.spec())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	h.SubstituteAuthority(q.name, q.rrtype, authority)
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	return v.Validate(context.Background(), q.name, q.rrtype)
}

// TestDenialProofsAreOrderIndependent shuffles the authority section.
//
// Nothing about a DNS message fixes the order of records in a section, and an
// attacker on the path may reorder them freely. A verdict that changes is a
// verdict they have a say in.
func TestDenialProofsAreOrderIndependent(t *testing.T) {
	for _, q := range provingQuestions() {
		t.Run(q.scenario, func(t *testing.T) {
			authority, baseline := authorityOf(t, q)
			if baseline != q.expect {
				t.Fatalf("baseline verdict %s, want %s", baseline, q.expect)
			}

			// Deterministic shuffles: a property test that fails only on
			// some runs is a property test nobody can act on.
			rng := rand.New(rand.NewSource(int64(len(authority)) * 7919)) //nolint:gosec // ordering, not secrets
			for attempt := 0; attempt < 24; attempt++ {
				shuffled := append([]dns.RR(nil), authority...)
				rng.Shuffle(len(shuffled), func(i, j int) {
					shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
				})
				got := validateWithAuthority(t, q, shuffled)
				if got.Status != baseline {
					t.Fatalf("shuffle %d changed the verdict: %s, want %s\n%s",
						attempt, got.Status, baseline, got.Trace())
				}
			}
		})
	}
}

// TestEveryDenialRecordIsLoadBearing removes one record at a time.
//
// A correct server sends exactly the records its proof needs (RFC 4035 §3.1.3,
// RFC 5155 §7.2), so every denial record in the section should be necessary.
// If one can be removed with no effect, the validator was not checking it, and
// the scenario that "passes" is passing for a reason nobody chose.
//
// SOA records are excluded. They are there for a resolver's negative caching
// (RFC 2308) and carry no part of the proof, so Daddybound not needing one is
// correct rather than a gap.
func TestEveryDenialRecordIsLoadBearing(t *testing.T) {
	for _, q := range provingQuestions() {
		t.Run(q.scenario, func(t *testing.T) {
			authority, baseline := authorityOf(t, q)
			if baseline != dnssec.StatusSecure {
				t.Fatalf("baseline verdict %s, want secure", baseline)
			}

			checked := 0
			for i, rr := range authority {
				if !isProofRecord(rr) {
					continue
				}
				checked++
				reduced := make([]dns.RR, 0, len(authority)-1)
				reduced = append(reduced, authority[:i]...)
				reduced = append(reduced, authority[i+1:]...)

				got := validateWithAuthority(t, q, reduced)
				if got.Status == dnssec.StatusSecure {
					t.Errorf("removing %s left the proof intact, so nothing was checking it\n%s",
						describeRR(rr), got.Trace())
				}
			}
			if checked == 0 {
				t.Fatalf("no denial records in the authority section; this test proved nothing")
			}
		})
	}
}

// TestTamperingWithADenialSignatureCostsTheProof flips one bit in each
// signature over a denial record.
//
// The record is still present, still names the right owner, still asserts the
// same interval. Only the arithmetic fails. RFC 4035 §5.4 requires the denial
// RRsets to be authenticated, and this is what "authenticated" has to mean:
// not that a signature accompanied the record, but that it verified.
func TestTamperingWithADenialSignatureCostsTheProof(t *testing.T) {
	for _, q := range provingQuestions() {
		t.Run(q.scenario, func(t *testing.T) {
			authority, baseline := authorityOf(t, q)
			if baseline != dnssec.StatusSecure {
				t.Fatalf("baseline verdict %s, want secure", baseline)
			}

			tampered := 0
			for i, rr := range authority {
				sig, ok := rr.(*dns.RRSIG)
				if !ok || !coversDenial(sig) {
					continue
				}
				tampered++

				broken := append([]dns.RR(nil), authority...)
				clone, ok := dns.Copy(sig).(*dns.RRSIG)
				if !ok {
					t.Fatalf("copying an RRSIG did not produce an RRSIG")
				}
				flipped, err := flipOneBit(clone.Signature)
				if err != nil {
					t.Fatalf("%v", err)
				}
				clone.Signature = flipped
				broken[i] = clone

				got := validateWithAuthority(t, q, broken)
				if got.Status == dnssec.StatusSecure {
					t.Errorf("a signature that does not verify still proved the denial\n%s", got.Trace())
				}
			}
			if tampered == 0 {
				t.Fatalf("no signatures over denial records; this test proved nothing")
			}
		})
	}
}

// TestNoSubsetOfADenialProofStillProvesIt is the monotonicity property,
// stated over subsets rather than over single removals.
//
// Validation is an argument from evidence, so taking evidence away can only
// weaken the conclusion. A validator that stays certain with less to go on has
// a branch treating an absence as a permission, which is the shape of every
// "we could not check it, so it must be fine" bug. Combinations matter here
// and single removals do not catch them: two records can each be individually
// necessary while the code has a path that fires only when both are gone.
//
// Non-proof records are held constant. The SOA is in the section for a
// resolver's negative caching (RFC 2308) and carries no part of the proof, so
// Daddybound not needing one is correct rather than a gap — and asserting
// otherwise would be asserting a property of the harness.
func TestNoSubsetOfADenialProofStillProvesIt(t *testing.T) {
	for _, q := range provingQuestions() {
		t.Run(q.scenario, func(t *testing.T) {
			authority, baseline := authorityOf(t, q)
			if baseline != dnssec.StatusSecure {
				t.Fatalf("baseline verdict %s, want secure", baseline)
			}

			var proofIndex []int
			for i, rr := range authority {
				if isProofRecord(rr) {
					proofIndex = append(proofIndex, i)
				}
			}
			if len(proofIndex) == 0 {
				t.Fatalf("no denial records in the authority section; this test proved nothing")
			}
			if len(proofIndex) > 12 {
				t.Fatalf("%d proof records is more than this power set should enumerate", len(proofIndex))
			}

			// Every subset of the proof records except the full one. Small
			// by construction: a correct server ships a handful.
			for mask := 0; mask < (1<<len(proofIndex))-1; mask++ {
				keep := map[int]bool{}
				for bit, idx := range proofIndex {
					if mask&(1<<bit) != 0 {
						keep[idx] = true
					}
				}

				subset := make([]dns.RR, 0, len(authority))
				for i, rr := range authority {
					if !isProofRecord(rr) || keep[i] {
						subset = append(subset, rr)
					}
				}

				got := validateWithAuthority(t, q, subset)
				if got.Status == dnssec.StatusSecure {
					t.Fatalf("a proper subset of the proof records still proved the denial (mask %0*b)\n%s",
						len(proofIndex), mask, got.Trace())
				}
			}
		})
	}
}

func isProofRecord(rr dns.RR) bool {
	switch rr := rr.(type) {
	case *dns.NSEC, *dns.NSEC3:
		return true
	case *dns.RRSIG:
		return coversDenial(rr)
	}
	return false
}

func coversDenial(sig *dns.RRSIG) bool {
	return sig.TypeCovered == dns.TypeNSEC || sig.TypeCovered == dns.TypeNSEC3
}

func describeRR(rr dns.RR) string {
	h := rr.Header()
	if sig, ok := rr.(*dns.RRSIG); ok {
		return fmt.Sprintf("the RRSIG over %s %s", h.Name, dns.TypeToString[sig.TypeCovered])
	}
	return fmt.Sprintf("the %s at %s", dns.TypeToString[h.Rrtype], h.Name)
}

// flipOneBit changes a single bit in a base64 signature, leaving its length
// and encoding intact so the record still parses and still reaches the
// cryptography.
func flipOneBit(signature string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(raw) == 0 {
		return "", fmt.Errorf("signature is not decodable base64")
	}
	raw[len(raw)/2] ^= 0x01
	return base64.StdEncoding.EncodeToString(raw), nil
}
