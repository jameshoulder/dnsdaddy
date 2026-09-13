package diag

import (
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/firstseen"
)

func healthy() FirstSeenInput {
	return FirstSeenInput{
		Enabled: true, Available: true,
		Rows: 100, MaxRows: 100_000, MaxNewPerMinute: 200,
		Dropped: map[string]uint64{},
	}
}

// TestADisabledIndexWarnsAndSaysItCannotChangeAnAnswer. The most likely reason
// somebody leaves an observe-only engine off is fear that it will not be, so
// the action says so.
func TestADisabledIndexWarnsAndSaysItCannotChangeAnAnswer(t *testing.T) {
	checks := FirstSeen(FirstSeenInput{Enabled: false})
	if len(checks) != 1 || checks[0].Status != StatusWarn {
		t.Fatalf("got %+v, want one WARN", checks)
	}
	if !strings.Contains(checks[0].Action, "observes only") {
		t.Errorf("the action does not say the engine is observe-only: %q", checks[0].Action)
	}
}

// TestAnEnabledButUnbuiltIndexFails. Configured on and not running is a wiring
// fault, and it is the one state where the operator's setting and reality
// disagree.
func TestAnEnabledButUnbuiltIndexFails(t *testing.T) {
	in := healthy()
	in.Available = false
	checks := FirstSeen(in)
	if checks[0].Status != StatusFail {
		t.Errorf("status = %v, want FAIL", checks[0].Status)
	}
}

// TestAHealthyIndexPassesAndReportsItsBounds.
func TestAHealthyIndexPassesAndReportsItsBounds(t *testing.T) {
	checks := FirstSeen(healthy())
	if len(checks) != 1 || checks[0].Status != StatusPass {
		t.Fatalf("got %+v, want one PASS", checks)
	}
	for _, want := range []string{"100", "100000", "200"} {
		if !strings.Contains(checks[0].Summary, want) {
			t.Errorf("summary %q does not mention %s", checks[0].Summary, want)
		}
	}
	if !strings.Contains(strings.Join(checks[0].Evidence, " "), "retention") {
		t.Error("the evidence does not say the index outlives the query log")
	}
}

// TestANearFullIndexWarnsThatFirstSeenIsAboutToChangeMeaning.
//
// This is the check that earns its place. A full index still answers; it just
// answers "new to this table" instead of "new to this network", and nothing
// in the response says so.
func TestANearFullIndexWarnsThatFirstSeenIsAboutToChangeMeaning(t *testing.T) {
	in := healthy()
	in.Rows = 85_000 // 85% of 100,000

	c, ok := findCheck(FirstSeen(in), "First-seen index near capacity")
	if !ok {
		t.Fatal("an index at 85% produced no warning")
	}
	if c.Status != StatusWarn {
		t.Errorf("status = %v, want WARN", c.Status)
	}
	if !strings.Contains(c.Summary, "recycled") {
		t.Errorf("the summary does not explain what changes: %q", c.Summary)
	}
}

// TestAComfortableIndexIsNotWarnedAbout, so the warning means something.
func TestAComfortableIndexIsNotWarnedAbout(t *testing.T) {
	in := healthy()
	in.Rows = 50_000 // half
	if _, ok := findCheck(FirstSeen(in), "First-seen index near capacity"); ok {
		t.Error("an index at 50% was reported as near capacity")
	}
}

// TestBudgetAndBufferDropsAreReportedSeparately, because they mean different
// things: one is a network discovering domains faster than the budget allows,
// the other is a writer that cannot keep up.
func TestBudgetAndBufferDropsAreReportedSeparately(t *testing.T) {
	in := healthy()
	in.Dropped[firstseen.DropBudget] = 40
	in.Dropped[firstseen.DropFull] = 7

	checks := FirstSeen(in)
	budget, okB := findCheck(checks, "First-seen budget reached")
	buffer, okF := findCheck(checks, "First-seen observations dropped")
	if !okB || !okF {
		t.Fatalf("expected both warnings, got %d checks", len(checks))
	}
	if !strings.Contains(budget.Summary, "40") || !strings.Contains(buffer.Summary, "7") {
		t.Error("the counts are not reported")
	}
	if !strings.Contains(buffer.Evidence[0], "latency") {
		t.Error("the buffer warning does not say the drop cost coverage rather than latency")
	}
}

// TestInvalidNamesAreExplainedNotWarnedAbout. On a network with a search
// suffix most names have no registered domain, and that is normal. It is
// reported so an operator comparing query volume against index growth is not
// left wondering, but it is not a problem.
func TestInvalidNamesAreExplainedNotWarnedAbout(t *testing.T) {
	in := healthy()
	in.Dropped[firstseen.DropInvalid] = 9_000

	checks := FirstSeen(in)
	if len(checks) != 1 || checks[0].Status != StatusPass {
		t.Fatalf("invalid-name drops changed the verdict: %+v", checks)
	}
	if !strings.Contains(strings.Join(checks[0].Evidence, " "), "9000") {
		t.Errorf("the count is not reported: %v", checks[0].Evidence)
	}
}
