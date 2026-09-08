package dnssec

import (
	"sort"
	"testing"
)

// RFC 4034 §6.1 gives an explicit worked example of canonical name order.
// Using the RFC's own list rather than one of my own devising is the point:
// it is the closest thing to an interoperability test available without a
// second implementation, and it caught nothing I would have thought to write.
//
//	example
//	a.example
//	yljkjljk.a.example
//	Z.a.example
//	zABC.a.EXAMPLE
//	z.example
//	\001.z.example
//	*.z.example
//	\200.z.example
func TestCanonicalNameOrderMatchesTheRFCExample(t *testing.T) {
	ordered := []string{
		"example.",
		"a.example.",
		"yljkjljk.a.example.",
		"Z.a.example.",
		"zABC.a.EXAMPLE.",
		"z.example.",
		"\\001.z.example.",
		"*.z.example.",
		"\\200.z.example.",
	}

	for i := 0; i < len(ordered)-1; i++ {
		if c := compareCanonicalNames(ordered[i], ordered[i+1]); c >= 0 {
			t.Errorf("%q should sort before %q, got %d", ordered[i], ordered[i+1], c)
		}
	}

	// And sorting a shuffled copy must reproduce the RFC's order exactly.
	shuffled := []string{
		"\\200.z.example.", "a.example.", "z.example.", "example.",
		"*.z.example.", "Z.a.example.", "\\001.z.example.",
		"zABC.a.EXAMPLE.", "yljkjljk.a.example.",
	}
	sort.Slice(shuffled, func(i, j int) bool {
		return compareCanonicalNames(shuffled[i], shuffled[j]) < 0
	})
	for i := range ordered {
		if !sameName(shuffled[i], ordered[i]) {
			t.Errorf("position %d: got %q, want %q", i, shuffled[i], ordered[i])
		}
	}
}

func sameName(a, b string) bool { return compareCanonicalNames(a, b) == 0 }

// Case is not significant, and a name that is a suffix of another sorts
// before it — the label-granularity form of "the absence of an octet sorts
// before a zero octet".
func TestCanonicalNameOrderIgnoresCaseAndOrdersSuffixesFirst(t *testing.T) {
	if compareCanonicalNames("EXAMPLE.TEST.", "example.test.") != 0 {
		t.Error("case changed the ordering")
	}
	if compareCanonicalNames("example.test.", "www.example.test.") >= 0 {
		t.Error("a zone apex should sort before names inside it")
	}
	if compareCanonicalNames(".", "example.test.") >= 0 {
		t.Error("the root should sort before everything")
	}
}

// Comparison must be from the rightmost label. Comparing from the left gives
// a plausible total order that no signer uses, so an NSEC interval computed
// with it proves nothing.
func TestCanonicalNameOrderComparesFromTheRight(t *testing.T) {
	// "b.a.test" vs "a.b.test": right-to-left puts a.test before b.test, so
	// b.a.test sorts first. Left-to-right would reverse them.
	if compareCanonicalNames("b.a.test.", "a.b.test.") >= 0 {
		t.Error("names are being compared from the left")
	}
}

func TestNSECIntervalCoverage(t *testing.T) {
	tests := []struct {
		name        string
		qname       string
		owner, next string
		want        bool
	}{
		{"inside an ordinary interval", "m.example.test.", "a.example.test.", "z.example.test.", true},
		{"the owner itself is not covered", "a.example.test.", "a.example.test.", "z.example.test.", false},
		{"the next name is not covered", "z.example.test.", "a.example.test.", "z.example.test.", false},
		{"before the interval", "aa.example.test.", "b.example.test.", "z.example.test.", false},
		{"after the interval", "zz.example.test.", "a.example.test.", "z.example.test.", false},

		// The last NSEC in a zone wraps back to the apex. Without the wrap
		// case the tail of every zone is unprovable.
		{"after the last owner, wrapping", "zz.example.test.", "z.example.test.", "example.test.", true},
		{"the apex is not covered by the wrapping record", "example.test.", "z.example.test.", "example.test.", false},
		{"a name before the owner is not covered by the wrap", "b.example.test.", "z.example.test.", "example.test.", false},

		// A single-name zone points its NSEC back at itself.
		{"single-name zone covers everything else", "x.example.test.", "example.test.", "example.test.", true},
		{"single-name zone does not cover its own name", "example.test.", "example.test.", "example.test.", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := nameInInterval(tc.qname, tc.owner, tc.next); got != tc.want {
				t.Errorf("nameInInterval(%q, %q, %q) = %v, want %v",
					tc.qname, tc.owner, tc.next, got, tc.want)
			}
		})
	}
}

func TestNextCloser(t *testing.T) {
	tests := []struct {
		qname, encloser string
		want            string
		ok              bool
	}{
		{"a.b.c.example.test.", "c.example.test.", "b.c.example.test.", true},
		{"a.b.c.example.test.", "example.test.", "c.example.test.", true},
		{"www.example.test.", "example.test.", "www.example.test.", true},
		// No next closer exists when the encloser is the name itself, or is
		// not an ancestor at all.
		{"example.test.", "example.test.", "", false},
		{"example.test.", "other.test.", "", false},
	}

	for _, tc := range tests {
		got, ok := nextCloser(tc.qname, tc.encloser)
		if ok != tc.ok {
			t.Errorf("nextCloser(%q, %q) ok = %v, want %v", tc.qname, tc.encloser, ok, tc.ok)
			continue
		}
		if ok && !sameName(got, tc.want) {
			t.Errorf("nextCloser(%q, %q) = %q, want %q", tc.qname, tc.encloser, got, tc.want)
		}
	}
}

func TestAncestorsOf(t *testing.T) {
	got := ancestorsOf("a.b.example.test.", "example.test.")
	want := []string{"a.b.example.test.", "b.example.test.", "example.test."}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if !sameName(got[i], want[i]) {
			t.Errorf("position %d: got %q, want %q", i, got[i], want[i])
		}
	}
	if ancestorsOf("elsewhere.test.", "example.test.") != nil {
		t.Error("a name outside the zone should have no ancestors within it")
	}
}
