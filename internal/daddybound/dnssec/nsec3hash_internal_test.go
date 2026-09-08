package dnssec

import (
	"encoding/hex"
	"fmt"
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
