package differential_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// The differential matrix: what the suite covers, and the one number that
// gates the milestone.
//
// The per-scenario tests already fail on any disagreement. This adds the
// thing a per-scenario test cannot give: a count. A suite can grow to fifty
// entries and still have a blind spot — every NSEC3 case a positive one, say,
// or no scenario at all for a family somebody meant to add — and the only way
// to see that is to count by family and by direction.

// TestTheMatrixCoversEveryFamilyInBothDirections is a coverage assertion, not
// a validation one.
//
// Every family needs both a case that must validate and a case that must not.
// A family with only positives is passed by a validator that returns Secure
// unconditionally; a family with only negatives is passed by one that returns
// Bogus unconditionally. Neither is worth having, and both look like coverage
// from a distance.
func TestTheMatrixCoversEveryFamilyInBothDirections(t *testing.T) {
	type counts struct{ accepts, refuses int }
	byFamily := map[lab.Family]*counts{}

	for _, sc := range lab.Scenarios() {
		if sc.Family == "" {
			t.Errorf("scenario %q has no family, so it is not counted anywhere", sc.Name)
			continue
		}
		if byFamily[sc.Family] == nil {
			byFamily[sc.Family] = &counts{}
		}
		if sc.Expect.String() == "secure" || sc.Expect.String() == "insecure" {
			byFamily[sc.Family].accepts++
		} else {
			byFamily[sc.Family].refuses++
		}
	}

	// Only the two denial families are required to run both ways, and the
	// reason is what each family is for. "positive" and "chain-failure" are
	// each other's counterparts — one exists to hold a
	// refuses-everything validator to account, the other a
	// accepts-everything one — so demanding both directions inside each
	// would be a category error. The denial families are different: they
	// each contain proofs that must be accepted and proofs that must not,
	// and a suite holding only one kind would look like coverage while
	// testing a constant.
	//
	// Configuration scenarios have one correct outcome by nature: "there is
	// no trust anchor" has no positive counterpart to write.
	needsBoth := []lab.Family{lab.FamilyNSEC, lab.FamilyNSEC3}

	var b strings.Builder
	fmt.Fprintf(&b, "\n%-16s %8s %8s\n", "FAMILY", "ACCEPTS", "REFUSES")
	for _, f := range sortedFamilies(byFamily) {
		fmt.Fprintf(&b, "%-16s %8d %8d\n", f, byFamily[f].accepts, byFamily[f].refuses)
	}
	t.Log(b.String())

	for _, f := range needsBoth {
		c := byFamily[f]
		if c == nil {
			t.Errorf("family %q has no scenarios at all", f)
			continue
		}
		if c.accepts == 0 {
			t.Errorf("family %q has no scenario that must validate, so a validator refusing everything passes it", f)
		}
		if c.refuses == 0 {
			t.Errorf("family %q has no scenario that must be refused, so a validator accepting everything passes it", f)
		}
	}

	// The suite as a whole must run both ways even though individual
	// families need not.
	if byFamily[lab.FamilyPositive] == nil || byFamily[lab.FamilyPositive].accepts == 0 {
		t.Error("nothing in the suite must validate, so a validator refusing everything passes it")
	}
	if byFamily[lab.FamilyChainFailure] == nil || byFamily[lab.FamilyChainFailure].refuses == 0 {
		t.Error("no chain-failure scenario, so a validator accepting everything passes the positive family alone")
	}

	// A floor rather than an exact count. Naming one means a future change
	// that quietly drops half the NSEC3 cases is a failure rather than a
	// smaller number nobody reads; leaving it approximate means adding a
	// scenario does not require editing a test.
	if n := len(lab.Scenarios()); n < 45 {
		t.Errorf("the suite is down to %d scenarios; it stood at 49 when this floor was written", n)
	}
}

// TestNoScenarioIsAnnotatedIntoSilence checks the annotations rather than the
// verdicts.
//
// KnownGap suppresses a differential disagreement, so an unexplained one is a
// way to make the suite quieter without making the engine better. The
// comparator already refuses to let an annotation absorb a false Secure; this
// makes sure each annotation at least says something a reviewer can argue
// with.
func TestNoScenarioIsAnnotatedIntoSilence(t *testing.T) {
	for _, sc := range lab.Scenarios() {
		if sc.KnownGap == "" {
			continue
		}
		// An annotation that names no standard is an assertion, not an
		// argument. Every one currently on file cites the section it rests
		// on, and that is the bar.
		if !strings.Contains(sc.KnownGap, "RFC") && !strings.Contains(sc.KnownGap, "section") {
			t.Errorf("scenario %q is annotated as a known gap without citing anything:\n  %s",
				sc.Name, sc.KnownGap)
		}
		if len(sc.KnownGap) < 120 {
			t.Errorf("scenario %q has a known-gap note too short to be an argument:\n  %s",
				sc.Name, sc.KnownGap)
		}
	}
}

func sortedFamilies[T any](m map[lab.Family]T) []lab.Family {
	out := make([]lab.Family, 0, len(m))
	for f := range m {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
