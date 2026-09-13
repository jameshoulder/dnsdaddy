package detect

import (
	"math"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
)

// Name analysis primitives shared by the detectors.
//
// Everything here operates on names that have already been normalised by
// internal/domainutil: lowercase, no trailing dot. That normalisation costs us
// one detection capability worth stating plainly — base64 payloads become
// indistinguishable from base32 once case is gone — and buys consistency with
// the policy engine, which matters more. See looksEncoded.

// ramp maps v onto 0..1 between floor and ceiling.
//
// Below floor a signal contributes nothing; above ceiling it contributes
// fully. Linear in between, so a finding's arithmetic can be checked by hand
// from the numbers published in its signals.
func ramp(v, floor, ceiling float64) float64 {
	if ceiling <= floor {
		if v >= ceiling {
			return 1
		}
		return 0
	}
	return clamp01((v - floor) / (ceiling - floor))
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
//
// Important caveat, and the reason callers gate on length: entropy per
// character is bounded above by log2(len(s)). An eight-character string cannot
// exceed 3 bits/char however random it is, so comparing a short label against
// a 4.0 threshold measures length, not randomness. Callers only average
// entropy over labels long enough for the measure to mean something
// (minEntropyLabelLen), and publish how many labels went into the average.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	n := 0
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
		n++
	}
	total := float64(n)
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// minEntropyLabelLen is the shortest label for which entropy per character is
// a meaningful measurement. At 12 characters the ceiling is log2(12) ≈ 3.58
// bits, which still sits above the ~3.2 bits/char floor the tunnel detector
// uses, so a genuinely random label can clear the bar and an ordinary word
// cannot.
const minEntropyLabelLen = 12

// maxLabelLen is the DNS protocol limit on a single label (RFC 1035 §2.3.4).
// A tunnel wanting throughput pushes labels towards it.
const maxLabelLen = 63

// looksEncoded reports whether a label looks like encoded binary rather than a
// name somebody chose.
//
// Detection is by character-set conformity plus a mix test. Because names are
// lowercased before they reach here, base64 and base32 collapse into the same
// observable — this function cannot tell them apart and does not try. What it
// can say is "these characters are drawn uniformly from an encoding alphabet
// and this does not read like a word", which is the property that matters.
func looksEncoded(label string) bool {
	if len(label) < 16 || len(label) > maxLabelLen {
		return false
	}

	var (
		hexOnly    = true
		b32Only    = true
		alnumOnly  = true
		digits     int
		b32Digits  int
		vowels     int
		letterOnly = true
	)
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
			letterOnly = false
			if c > '7' || c < '2' {
				b32Only = false
			} else {
				b32Digits++
			}
			if c > '9' {
				hexOnly = false
			}
		case c >= 'a' && c <= 'z':
			if c > 'f' {
				hexOnly = false
			}
			if isVowel(c) {
				vowels++
			}
		case c == '-' || c == '_':
			// Hyphens are legal in labels and common in real names; an
			// encoding alphabet that uses them (base64url) still yields a
			// low vowel ratio, so let the mix test below decide.
			hexOnly, b32Only = false, false
			letterOnly = false
		default:
			return false
		}
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'z') && c != '-' && c != '_' {
			alnumOnly = false
		}
	}
	if !alnumOnly {
		return false
	}

	// A long pure-hex label is encoded by construction: no natural-language
	// name is 16+ characters drawn only from [0-9a-f].
	if hexOnly && digits > 0 {
		return true
	}
	// Base32 uses [a-z2-7]. Requiring at least one digit from that range
	// avoids matching a long all-letter word.
	if b32Only && b32Digits > 0 {
		return true
	}

	// Otherwise fall back on the mix test: encoded output has a vowel
	// distribution unlike written language. English averages roughly 38%
	// vowels; a uniform draw from a 32- or 36-character alphabet gives about
	// 16%. Below 12% over a long label is strong evidence, and a healthy digit
	// fraction in an otherwise word-shaped label points the same way.
	vowelRatio := float64(vowels) / float64(len(label))
	if letterOnly {
		return vowelRatio < 0.12
	}
	digitRatio := float64(digits) / float64(len(label))
	return vowelRatio < 0.20 && digitRatio >= 0.20
}

func isVowel(c byte) bool {
	switch c {
	case 'a', 'e', 'i', 'o', 'u':
		return true
	}
	return false
}

// randomnessIndex scores how algorithmic a single label looks, on 0..1.
//
// This is the DGA heuristic, and it is a heuristic: it measures surface
// statistics of the string, not membership of any generated domain list, and
// it is stated as such wherever it is surfaced. Four independent properties
// are combined so no single one can carry a verdict on its own:
//
//	vowel ratio far from written English
//	long runs of consonants
//	a high digit fraction
//	high per-character entropy
//
// Real algorithmically generated labels typically trip three of the four.
// "cloudflare" trips none. "xn--" internationalised labels are excluded by the
// caller, because punycode is machine-generated by design and would otherwise
// score like a DGA every time.
func randomnessIndex(label string) float64 {
	n := len(label)
	if n < 8 || n > maxLabelLen {
		return 0
	}

	var vowels, digits, run, maxRun int
	for i := 0; i < n; i++ {
		c := label[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
			run = 0
		case isVowel(c):
			vowels++
			run = 0
		case c >= 'a' && c <= 'z':
			run++
			if run > maxRun {
				maxRun = run
			}
		default:
			run = 0
		}
	}

	letters := n - digits
	vowelRatio := 0.0
	if letters > 0 {
		vowelRatio = float64(vowels) / float64(letters)
	}

	// Distance from the middle of the band ordinary words occupy (~25%-50%
	// vowels among letters), normalised.
	var vowelScore float64
	switch {
	case vowelRatio < 0.25:
		vowelScore = ramp(0.25-vowelRatio, 0.03, 0.20)
	case vowelRatio > 0.55:
		vowelScore = ramp(vowelRatio-0.55, 0.05, 0.25)
	}

	runScore := ramp(float64(maxRun), 3, 7)
	digitScore := ramp(float64(digits)/float64(n), 0.15, 0.45)

	entropyScore := 0.0
	if n >= minEntropyLabelLen {
		entropyScore = ramp(shannonEntropy(label), 3.2, 4.0)
	} else {
		// Too short for entropy to mean anything; fall back on the fact that
		// the label is at least long enough to be a generated name.
		entropyScore = ramp(shannonEntropy(label), 2.6, 3.2) * 0.5
	}

	// Equal weighting: no one property is trusted more than the others, which
	// keeps a single quirky-but-legitimate name from scoring highly.
	return clamp01((vowelScore + runScore + digitScore + entropyScore) / 4)
}

// split separates a name into its registered domain (eTLD+1) and everything
// below it.
//
// The implementation moved to internal/domainutil when the first-seen index
// needed the same answer. There is deliberately one registered-domain scheme
// in this repository and not two: a detector and an index that disagreed about
// what "example.co.uk" is would produce findings that could not be looked up.
func split(name string) (parent, sub string, ok bool) {
	return domainutil.RegisteredDomain(name)
}

// labelsOf splits a name into its labels without allocating a slice per call
// for the common short case.
func labelsOf(name string) []string {
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// isInternationalised reports whether a label is punycode. Machine-generated
// by definition, so it is excluded from randomness scoring.
func isInternationalised(label string) bool {
	return strings.HasPrefix(label, "xn--")
}
