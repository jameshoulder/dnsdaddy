package differential_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// The classifier decides whether a disagreement is release-blocking, so its
// behaviour needs a test that runs in every build — not only the one with a
// C toolchain and libunbound installed. These use a stub oracle.

func result(status dnssec.ValidationStatus) dnssec.ValidationResult {
	return dnssec.ValidationResult{Status: status}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name     string
		db       dnssec.ValidationStatus
		ref      dnssec.ValidationStatus
		unres    bool
		refErr   error
		dbErr    error
		knownGap string
		want     differential.Class
	}{
		{name: "both secure", db: dnssec.StatusSecure, ref: dnssec.StatusSecure, want: differential.ClassMatch},
		{name: "both bogus", db: dnssec.StatusBogus, ref: dnssec.StatusBogus, want: differential.ClassMatch},
		{
			name: "reference bogus, daddybound secure",
			db:   dnssec.StatusSecure, ref: dnssec.StatusBogus,
			want: differential.ClassFalseSecure,
		},
		{
			name: "reference secure, daddybound bogus",
			db:   dnssec.StatusBogus, ref: dnssec.StatusSecure,
			want: differential.ClassFalseBogus,
		},
		{
			name: "reference could not answer",
			db:   dnssec.StatusSecure, ref: dnssec.StatusIndeterminate,
			refErr: errors.New("timeout"),
			want:   differential.ClassReferenceError,
		},
		{
			name: "daddybound produced nothing",
			db:   dnssec.StatusIndeterminate, ref: dnssec.StatusSecure,
			dbErr: errors.New("panic"),
			want:  differential.ClassDaddyboundError,
		},
		{
			name: "an unresolved oracle agrees with indeterminate",
			db:   dnssec.StatusIndeterminate, ref: dnssec.StatusInsecure, unres: true,
			want: differential.ClassMatch,
		},
		{
			name: "a justified disagreement is a known gap",
			db:   dnssec.StatusIndeterminate, ref: dnssec.StatusSecure,
			knownGap: "v0.1 cannot reach Insecure",
			want:     differential.ClassKnownGap,
		},
		{
			name: "an unexplained disagreement is not",
			db:   dnssec.StatusIndeterminate, ref: dnssec.StatusSecure,
			want: differential.ClassStatusDisagreement,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := differential.Classify(
				result(tc.db), tc.dbErr,
				differential.ReferenceResult{Status: tc.ref, Unresolved: tc.unres}, tc.refErr,
				tc.knownGap,
			)
			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// The safety property of the whole harness, stated as its own test.
//
// A known-gap annotation is written by whoever adds a scenario. It may rebut
// a false-Bogus classification — that one presumes the oracle is right, and a
// citation can rebut the presumption. It must never be able to quiet a false
// Secure, because that is the failure that would make Daddybound dangerous
// rather than merely wrong. Classify checks for it first for exactly this
// reason, and this is what stops a later edit reordering the checks.
func TestAKnownGapCanNeverExcuseAFalseSecure(t *testing.T) {
	for _, gap := range []string{
		"",
		"a perfectly reasonable sounding explanation",
		"RFC 9999 section 1 says this is fine",
	} {
		got := differential.Classify(
			result(dnssec.StatusSecure), nil,
			differential.ReferenceResult{Status: dnssec.StatusBogus}, nil,
			gap,
		)
		if got != differential.ClassFalseSecure {
			t.Fatalf("known gap %q reclassified a false secure as %s", gap, got)
		}
	}

	// Nor may a reference error, which is checked after it for the same
	// reason: an oracle that established the data is forged has said
	// something, whatever else went wrong afterwards.
	got := differential.Classify(
		result(dnssec.StatusSecure), nil,
		differential.ReferenceResult{Status: dnssec.StatusBogus}, errors.New("also failed"),
		"and an explanation",
	)
	if got != differential.ClassFalseSecure {
		t.Fatalf("a reference error reclassified a false secure as %s", got)
	}
}

// The false-secure rate is a headline number, so its denominator matters.
// Runs where either side produced no verdict are not evidence about
// agreement, and counting them would let a broken oracle flatter the rate.
func TestFalseSecureRateExcludesRunsWithNoVerdict(t *testing.T) {
	r := differential.Report{
		Comparisons: []differential.Comparison{
			{Class: differential.ClassMatch},
			{Class: differential.ClassFalseSecure},
			{Class: differential.ClassReferenceError},
			{Class: differential.ClassDaddyboundError},
		},
	}
	// One false secure out of two comparable runs, not out of four.
	if got := r.FalseSecureRate(); got != 0.5 {
		t.Errorf("rate = %v, want 0.5", got)
	}
	if n := len(r.FalseSecure()); n != 1 {
		t.Errorf("FalseSecure() returned %d, want 1", n)
	}
}

func TestReportSummaryNamesFailuresAndHidesMatches(t *testing.T) {
	r := differential.Report{
		Oracle: "stub 1.0",
		Comparisons: []differential.Comparison{
			{Scenario: "quiet", Class: differential.ClassMatch},
			{Scenario: "loud", Class: differential.ClassFalseSecure,
				Daddybound: result(dnssec.StatusSecure),
				Reference:  differential.ReferenceResult{Status: dnssec.StatusBogus, Detail: "signature crypto failed"}},
		},
	}
	s := r.Summary()
	for _, want := range []string{"stub 1.0", "FALSE_SECURE", "loud", "signature crypto failed"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary does not mention %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "quiet") {
		t.Errorf("summary lists a matching scenario:\n%s", s)
	}
}

// stubOracle is a Reference that answers from a table, so the runner can be
// exercised without a C toolchain.
type stubOracle struct {
	byScenario map[string]dnssec.ValidationStatus
}

func (s stubOracle) Name() string { return "stub oracle" }

func (s stubOracle) Validate(ctx context.Context, qname string, qtype uint16) (differential.ReferenceResult, error) {
	// Answers by question rather than by scenario name, which is all a real
	// oracle gets to see.
	if qname == lab.AnswerName {
		return differential.ReferenceResult{Status: dnssec.StatusBogus}, nil
	}
	return differential.ReferenceResult{Status: dnssec.StatusInsecure, Unresolved: true}, nil
}

// Run must serve each scenario its own freshly built and freshly served
// hierarchy, and must classify every one rather than stopping at the first
// disagreement — a suite that aborts on the first finding reports one where
// there might be ten.
func TestRunClassifiesEveryScenario(t *testing.T) {
	scenarios := lab.Scenarios()
	report, err := differential.Run(context.Background(), stubOracle{}, scenarios)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(report.Comparisons) != len(scenarios) {
		t.Fatalf("compared %d scenarios, want %d", len(report.Comparisons), len(scenarios))
	}
	if report.Oracle != "stub oracle" {
		t.Errorf("oracle = %q", report.Oracle)
	}

	// The stub calls everything at the answer name bogus, so the one
	// scenario Daddybound calls secure must surface as a false secure. If it
	// does not, the runner is not actually comparing anything.
	found := false
	for _, c := range report.Comparisons {
		if c.Scenario == "valid" {
			found = true
			if c.Class != differential.ClassFalseSecure {
				t.Errorf("the valid scenario against an all-bogus oracle classified as %s, want %s",
					c.Class, differential.ClassFalseSecure)
			}
		}
	}
	if !found {
		t.Error("the valid scenario was not compared")
	}
}
