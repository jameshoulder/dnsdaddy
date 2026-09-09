package dnssec

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The cross-check for NSEC3 hashing, on the same principle as the name
// ordering: two implementations of RFC 5155 §5, written from the RFC rather
// than from each other, held against one another over a generated corpus.
//
// This one is worth more than most, because a hashing bug is invisible from
// inside. A validator that hashes wrongly but consistently matches nothing in
// any real zone and yet passes every test built on its own hashes.

// TestNSEC3HashMatchesRFC5155AppendixA checks the worked examples the RFC
// publishes, which is the strongest evidence available: a third party's
// numbers, computed before this code existed.
func TestNSEC3HashMatchesRFC5155AppendixA(t *testing.T) {
	// RFC 5155 Appendix A, "Example Zone". Salt aabbccdd, 12 iterations,
	// hash algorithm 1.
	salt, err := hex.DecodeString("aabbccdd")
	if err != nil {
		t.Fatal(err)
	}
	const iterations = 12

	// Owner names and their hashes as published in the RFC's example zone.
	cases := map[string]string{
		"example.":       "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM",
		"a.example.":     "35MTHGPGCU1QG68FAB165KLNSNK3DPVL",
		"ai.example.":    "GJEQE526PLBF1G8MKLP59ENFD789NJGI",
		"ns1.example.":   "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR",
		"ns2.example.":   "Q04JKCEVQVMU85R014C7DKBA38O0JI5R",
		"w.example.":     "K8UDEMVP1J2F7EG6JEBPS17VP3N8I58H",
		"*.w.example.":   "R53BQ7CC2UVMUBFU5OCMM6PERS9TK9EN",
		"x.w.example.":   "B4UM86EGHHDS6NEA196SMVMLO4ORS995",
		"y.w.example.":   "JI6NEOAEPV8B5O6K4EV33ABHA8HT9FGC",
		"x.y.w.example.": "2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S",
		"xx.example.":    "T644EBQK9BIBCNA874GIVR6JOJ62MLHV",
		"2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.": "KOHAR7MBB8DC2CE8A9QVL8HON4K53UHI",
	}

	for name, want := range cases {
		got, ok := nsec3Hash(name, NSEC3HashSHA1, iterations, salt)
		if !ok {
			t.Errorf("%s: hashing refused", name)
			continue
		}
		if got != want {
			t.Errorf("%s\n got %s\nwant %s (RFC 5155 Appendix A)", name, got, want)
		}
	}
}

// TestNSEC3HashAgreesWithAnIndependentImplementation runs the same corpus
// through github.com/miekg/dns, which the test lab uses to build NSEC3 chains.
// If these two ever part company, the lab is signing chains this validator
// cannot read, and every NSEC3 scenario becomes a test of nothing.
func TestNSEC3HashAgreesWithAnIndependentImplementation(t *testing.T) {
	salts := []string{"", "00", "aabbccdd", "ff", "0123456789abcdef0123456789abcdef"}
	iterations := []uint16{0, 1, 2, 12, 100, 500}

	names := []string{".", "example.", "a.example.", "*.example.", "A.EXAMPLE."}
	for i := 0; i < 40; i++ {
		names = append(names, fmt.Sprintf("n%d.deep.example.dnsdaddylab.", i))
	}
	names = append(names, `\000.example.`, `\255.example.`, `*.a.b.c.example.`)

	for _, saltHex := range salts {
		salt, err := hex.DecodeString(saltHex)
		if err != nil {
			t.Fatalf("bad test salt %q: %v", saltHex, err)
		}
		for _, iter := range iterations {
			for _, name := range names {
				got, ok := nsec3Hash(name, NSEC3HashSHA1, iter, salt)
				want := dns.HashName(name, dns.SHA1, iter, saltHex)
				if !ok {
					t.Fatalf("%s salt=%q iter=%d: hashing refused", name, saltHex, iter)
				}
				if got != want {
					t.Fatalf("%s salt=%q iter=%d\n got %s\nwant %s",
						name, saltHex, iter, got, want)
				}
			}
		}
	}
}

// TestNSEC3HashRefusesUnknownAlgorithms is RFC 5155 §8.1: "A validator MUST
// ignore NSEC3 RRs with unknown hash types." There is no other assigned
// value, so there is nothing to fall back to and nothing to guess.
func TestNSEC3HashRefusesUnknownAlgorithms(t *testing.T) {
	for _, alg := range []uint8{0, 2, 3, 255} {
		if _, ok := nsec3Hash("example.", alg, 0, nil); ok {
			t.Errorf("hash algorithm %d was accepted; only SHA-1 (1) is assigned", alg)
		}
	}
}

// The NSEC3 hash allowance belongs to the validation, not to the response.
//
// A validation collects a denial proof for every candidate zone cut, again
// for the answer, again for a wildcard justification, and all of that again
// for each hop of a CNAME chain. A budget created per response therefore
// bounded MaxAliasHops × MaxZones × MaxNSEC3Hashes — some twelve hundred
// times the number Limits.MaxNSEC3Hashes documents, which at the iteration
// ceiling is tens of millions of SHA-1 computations for one query.
//
// Reported by a review bot, which found it by reading the limit's doc comment
// against its construction three files away. That is exactly the check a
// person skips, because the comment says the right thing.
//
// Checked at the source rather than through a validation, and the reason is
// worth stating because a behavioural test would be the more natural
// instinct. Exhausting the budget while probing a candidate zone cut is
// *absorbed* — proveNoDS reports no usable proof and the walk falls back to
// its zone-cut assumption — so an end-to-end measurement mostly observes the
// final proof and returns the same threshold whichever way the budget is
// scoped. The first attempt at this test asserted on a helper written beside
// it and passed with the fix reverted, which is the vacuity trap this suite
// has now hit three times.
//
// What actually went wrong was one expression in one file, so that is what is
// pinned: exactly one hashBudget is ever constructed, in the function that
// begins a validation.
func TestOnlyAValidationMayCreateAHashBudget(t *testing.T) {
	dir := "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the package: %v", err)
	}

	found := map[string]int{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- a test reading its own package
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if n := strings.Count(string(body), "hashBudget{"); n > 0 {
			found[name] = n
		}
	}

	want := map[string]int{"chain.go": 1}
	if len(found) != len(want) {
		t.Fatalf("hashBudget is constructed in %v; it must be constructed once, in %v", found, want)
	}
	for file, n := range want {
		if found[file] != n {
			t.Fatalf("hashBudget is constructed %d times in %s, want %d — a budget made "+
				"anywhere but at the start of a validation bounds a response rather than "+
				"a validation", found[file], file, n)
		}
	}
}

// And the arithmetic the shared pointer exists for: two proofs draw from one
// allowance.
func TestASharedHashBudgetIsSpentOnce(t *testing.T) {
	w := &walk{hashes: &hashBudget{remaining: 10}}

	first := &nsec3Set{budget: w.hashes}
	second := &nsec3Set{budget: w.hashes}

	if !first.budget.spend(6) {
		t.Fatal("spending 6 of 10 failed")
	}
	if second.budget.spend(6) {
		t.Fatal("a second proof spent 6 more from a 10-hash allowance with 4 left")
	}
	if w.hashes.remaining != 0 {
		t.Errorf("remaining = %d, want 0: an over-spend must consume the rest rather than "+
			"leave an allowance a later caller can use", w.hashes.remaining)
	}
}
