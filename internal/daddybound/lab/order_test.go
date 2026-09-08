package lab

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// The cross-check order.go's doc comment promises.
//
// Two implementations of RFC 4034 §6.1 exist on purpose: the validator walks
// label arrays from the right, the lab builds a sort key whose byte order is
// the canonical order. Neither was written from the other. That only buys
// anything if something actually holds them against each other, because the
// failure they are meant to prevent — a chain built wrong and checked wrong
// in the same way, so every test passes over a zone no other implementation
// can read — is invisible from inside either one.

// orderingCorpus builds a deterministic set of names chosen to hit the
// places two implementations of the same ordering tend to part company.
func orderingCorpus() []string {
	// Label octets, not letters. The ordering is defined over wire octets,
	// so an alphabet of readable characters would never exercise the cases
	// that matter: the zero octet (which the sort key has to escape), the
	// high octets, the asterisk, and letters whose case must be folded.
	alphabet := []string{
		`\000`, `\001`, `*`, `-`, `0`, `A`, `a`, `Z`, `z`, `\127`, `\200`, `\255`,
	}

	names := []string{".", "example.", "test."}
	for _, top := range []string{"example.", "test."} {
		for _, one := range alphabet {
			names = append(names, one+"."+top)
			for _, two := range alphabet {
				names = append(names, two+"."+one+"."+top)
			}
		}
	}

	// Names of differing length sharing a suffix, which is where "a suffix
	// sorts before what it is a suffix of" is decided.
	names = append(names,
		"a.example.", "aa.example.", "a.a.example.", "b.a.a.example.",
		"*.example.", `\000.example.`, `\000\000.example.`,
		"example.example.", "zz.example.",
	)

	// Presentation forms that must fold to the same wire name.
	names = append(names, "A.EXAMPLE.", "a.example", "A.Example.")

	// Names with a high-octet rightmost label, and names that cannot be
	// expressed on the wire at all. Both implementations put unorderable
	// names last, and "last" has to mean last relative to *these* — an
	// earlier version of the lab's sort key expressed "last" as a high octet
	// and so sorted an unplaceable name below a real one whose top label
	// begins with 0xFF. That is not an academic ordering quibble: the two
	// sides would then disagree about which NSEC interval covers which name.
	names = append(names,
		`\255.`, `a.\255.`, `\255.\255.`, `\254.`,
		strings.Repeat("a", 64)+".example.",  // a label over 63 octets
		strings.Repeat("a.", 200)+"example.", // a name over 255 octets
	)
	return names
}

func TestLabAndValidatorAgreeOnCanonicalNameOrder(t *testing.T) {
	names := orderingCorpus()

	var mismatches []string
	for _, a := range names {
		for _, b := range names {
			// The lab exposes a strict less-than; the validator a
			// three-way comparison. Comparing them means comparing what
			// each says about the pair in both directions, so that a
			// comparator claiming both a<b and b<a is caught as well as
			// one that simply disagrees.
			labAB := canonicalLess(a, b)
			labBA := canonicalLess(b, a)

			want := dnssec.CompareCanonicalNames(a, b)
			gotAB := want < 0
			gotBA := want > 0

			if labAB != gotAB || labBA != gotBA {
				mismatches = append(mismatches, fmt.Sprintf(
					"%q vs %q: lab says less=%v greater=%v, validator says cmp=%d",
					a, b, labAB, labBA, want))
			}
		}
	}
	if len(mismatches) > 0 {
		shown := mismatches
		if len(shown) > 20 {
			shown = shown[:20]
		}
		for _, m := range shown {
			t.Error(m)
		}
		t.Fatalf("%d of %d name pairs ordered differently by the two implementations",
			len(mismatches), len(names)*len(names))
	}
}

// TestLabAndValidatorSortTheSameCorpusIdentically is the same evidence stated
// as an outcome rather than a pairwise property: an NSEC chain is a sorted
// list, so what actually has to match is the sorted order, not merely the
// comparator's answers taken one pair at a time.
func TestLabAndValidatorSortTheSameCorpusIdentically(t *testing.T) {
	byLab := append([]string(nil), orderingCorpus()...)
	sort.SliceStable(byLab, func(i, j int) bool { return canonicalLess(byLab[i], byLab[j]) })

	byValidator := append([]string(nil), orderingCorpus()...)
	sort.SliceStable(byValidator, func(i, j int) bool {
		return dnssec.CompareCanonicalNames(byValidator[i], byValidator[j]) < 0
	})

	for i := range byLab {
		// Equal names may swap under a stable sort without meaning
		// anything, so compare by the ordering rather than by string.
		if dnssec.CompareCanonicalNames(byLab[i], byValidator[i]) != 0 {
			t.Fatalf("position %d: lab sorted %q there, validator sorted %q there",
				i, byLab[i], byValidator[i])
		}
	}
}

// TestLabIntervalCoverageMatchesTheValidatorsOrdering checks the lab's
// interval arithmetic — which decides which NSEC record is served as a proof
// — against the plain statement of the rule, written here in terms of the
// validator's comparator rather than the lab's.
//
// Stating the rule a third time is the point. The lab computes coverage from
// sort keys; the validator from label walks; this says, in the RFC's own
// terms, what coverage means, and asks both to agree with it.
func TestLabIntervalCoverageMatchesTheValidatorsOrdering(t *testing.T) {
	names := orderingCorpus()

	// Every adjacent pair in canonical order, plus a wrapping pair, so the
	// last-NSEC-in-the-zone case is exercised rather than assumed.
	sorted := append([]string(nil), names...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return dnssec.CompareCanonicalNames(sorted[i], sorted[j]) < 0
	})

	type pair struct{ owner, next string }
	var intervals []pair
	for i := range sorted {
		intervals = append(intervals, pair{sorted[i], sorted[(i+1)%len(sorted)]})
	}
	// The wrap: the greatest name pointing back at the least.
	intervals = append(intervals, pair{sorted[len(sorted)-1], sorted[0]})

	for _, iv := range intervals {
		for _, q := range names {
			got := intervalCovers(q, iv.owner, iv.next)
			want := coversByDefinition(q, iv.owner, iv.next)
			if got != want {
				t.Fatalf("interval (%q, %q) and name %q: lab says covered=%v, the rule says %v",
					iv.owner, iv.next, q, got, want)
			}
		}
	}
}

// coversByDefinition states RFC 4034 §4.1.1 coverage directly: a name is
// covered when it sorts strictly after the owner and strictly before the next
// name, with the last record in a zone wrapping past the end.
func coversByDefinition(name, owner, next string) bool {
	afterOwner := dnssec.CompareCanonicalNames(name, owner) > 0
	beforeNext := dnssec.CompareCanonicalNames(name, next) < 0

	switch c := dnssec.CompareCanonicalNames(owner, next); {
	case c < 0:
		return afterOwner && beforeNext
	case c > 0:
		return afterOwner || beforeNext
	default:
		return dnssec.CompareCanonicalNames(name, owner) != 0
	}
}
