package differential_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// The corpus must compare through more than one resolving view.
//
// Two oracles over one forwarder is two validators reading one resolver's
// answers. That is real evidence about the validators and none at all about
// the records: a resolver serving a stale DNSKEY or a filtered answer makes
// Daddybound, libunbound and delv agree unanimously on the same wrong input,
// which is the most convincing wrong answer available.
//
// Non-vacuity: delete either entry from DefaultViews and this fails.
func TestTheCorpusComparesThroughMoreThanOneView(t *testing.T) {
	views := differential.DefaultViews()

	if len(views) < 2 {
		t.Fatalf("the corpus is configured with %d view(s); one view means every oracle "+
			"reads the same resolver's answers and agreement proves nothing about the records",
			len(views))
	}

	servers := map[string]string{}
	for _, v := range views {
		if v.Server == "" {
			t.Errorf("view %q has no server", v.Name)
		}
		if v.Name == "" {
			t.Errorf("view with server %q has no name; reports are read by people who were not there", v.Server)
		}
		if v.Why == "" {
			t.Errorf("view %q does not say what makes it independent of the others", v.Name)
		}
		if first, dup := servers[v.Server]; dup {
			t.Errorf("views %q and %q are the same resolver (%s); two names for one view is not two views",
				first, v.Name, v.Server)
		}
		servers[v.Server] = v.Name
	}
}

// Two names for one resolver must be refused, not deduplicated.
//
// Silently collapsing them would leave a run reporting two views in its
// header and its counts while reading one resolver — the exact situation this
// change exists to end, reintroduced by a convenience.
func TestTwoNamesForOneResolverAreRefused(t *testing.T) {
	if _, err := differential.ParseViews("a=8.8.8.8:53,b=8.8.8.8:53"); err == nil {
		t.Fatal("two entries pointing at one resolver were accepted as two views")
	}
	// The same address written two ways is still one resolver.
	if _, err := differential.ParseViews("a=8.8.8.8,b=8.8.8.8:53"); err == nil {
		t.Fatal("the same resolver with and without an explicit port was accepted as two views")
	}
	if _, err := differential.ParseViews("a=8.8.8.8,b=9.9.9.10"); err != nil {
		t.Fatalf("two genuinely different resolvers were refused: %v", err)
	}
}

func TestAnEmptyViewSpecFallsBackToTheDefaults(t *testing.T) {
	got, err := differential.ParseViews("   ")
	if err != nil {
		t.Fatalf("ParseViews: %v", err)
	}
	if len(got) != len(differential.DefaultViews()) {
		t.Errorf("empty spec gave %d views, want the %d defaults", len(got), len(differential.DefaultViews()))
	}
}

// A verdict that depends on who supplied the records is an outcome.
//
// Not a skip, not an averaged-away detail, and not a failure either: it says
// the answer depended on the path. With one view there was nothing to differ
// from, so this class of finding could not previously exist.
func TestAViewDisagreementIsReportedRatherThanSkipped(t *testing.T) {
	byScenario := map[string][]differential.ViewVerdict{
		"agrees.example./A": {
			{View: "cloudflare", Status: dnssec.StatusSecure},
			{View: "quad9-unsecured", Status: dnssec.StatusSecure},
		},
		"differs.example./A": {
			{View: "quad9-unsecured", Status: dnssec.StatusBogus, Reason: dnssec.ReasonSignatureExpired},
			{View: "cloudflare", Status: dnssec.StatusSecure},
		},
		"seen-once.example./A": {
			{View: "cloudflare", Status: dnssec.StatusIndeterminate},
		},
	}

	got := differential.FindViewDisagreements(byScenario)

	if len(got) != 1 {
		t.Fatalf("got %d disagreements, want exactly the one question whose verdict depended "+
			"on the view: %+v", len(got), got)
	}
	if got[0].Scenario != "differs.example./A" {
		t.Errorf("reported %q, want differs.example./A", got[0].Scenario)
	}
	// Ordered by view name, so the same disagreement reads the same way in
	// two runs and a diff between reports means something.
	if got[0].Verdicts[0].View != "cloudflare" {
		t.Errorf("verdicts are not ordered by view name: %+v", got[0].Verdicts)
	}
	line := got[0].Line()
	for _, want := range []string{"cloudflare=secure", "quad9-unsecured=bogus"} {
		if !strings.Contains(line, want) {
			t.Errorf("the report line %q does not name %q, so a reader cannot see which view said what",
				line, want)
		}
	}
}

// A question only one view reached is one observation, not an agreement.
//
// Counting it as agreement would be inventing a comparison that never
// happened — the failure mode of every "no news is good news" summary.
func TestASingleObservationIsNeitherAgreementNorDisagreement(t *testing.T) {
	got := differential.FindViewDisagreements(map[string][]differential.ViewVerdict{
		"only-one.example./A": {{View: "cloudflare", Status: dnssec.StatusBogus}},
	})
	if len(got) != 0 {
		t.Errorf("a question seen by one view was reported as a disagreement: %+v", got)
	}
}

// contraryOracle answers every question with the opposite of what the lab
// fixture is built to produce, so a run against it must fail.
type contraryOracle struct{ status dnssec.ValidationStatus }

func (c contraryOracle) Name() string { return "contrary-oracle" }

func (c contraryOracle) Validate(context.Context, string, uint16) (differential.ReferenceResult, error) {
	return differential.ReferenceResult{Status: c.status, Detail: "deliberately contrary"}, nil
}

// A fixture that disagrees with an oracle must fail the run, not be skipped.
//
// This is the property that makes every other differential result mean
// something. A harness that quietly downgraded a mismatch to a note would
// keep reporting green while Daddybound and two reference validators drifted
// apart, and nobody would look at the note.
//
// Run against the real runner rather than against a restatement of its rules,
// so that a change to how the runner classifies is caught here.
func TestAFixtureMismatchAgainstAnOracleFailsTheRun(t *testing.T) {
	scenarios := lab.Scenarios()
	if len(scenarios) == 0 {
		t.Fatal("no scenarios")
	}

	// Every scenario judged against an oracle that always says "secure".
	// Wherever the fixture is built to be rejected, that is a false Secure or
	// a disagreement, and either way a failure.
	report, err := differential.Run(context.Background(), contraryOracle{status: dnssec.StatusSecure}, scenarios)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Comparisons) == 0 {
		t.Fatal("the run produced no comparisons, so it asserts nothing")
	}

	failures := 0
	for _, c := range report.Comparisons {
		if c.Class.IsFailure() {
			failures++
		}
	}
	if failures == 0 {
		t.Fatalf("an oracle that contradicts every negative fixture produced no failing "+
			"comparison across %d scenarios; a mismatch is being absorbed rather than reported",
			len(report.Comparisons))
	}
}

// Only agreement and a declared known gap are not failures.
//
// Written out as a table because the set is a contract: a class added later
// and left out of the switch would silently default to one side or the other,
// and this says which side every class is on.
func TestOnlyAgreementAndADeclaredGapAreNotFailures(t *testing.T) {
	for _, tc := range []struct {
		class differential.Class
		fails bool
	}{
		{differential.ClassMatch, false},
		{differential.ClassKnownGap, false},
		{differential.ClassFalseSecure, true},
		{differential.ClassFalseBogus, true},
		{differential.ClassStatusDisagreement, true},
		{differential.ClassReferenceError, true},
		{differential.ClassDaddyboundError, true},
	} {
		if got := tc.class.IsFailure(); got != tc.fails {
			t.Errorf("%s: IsFailure() = %v, want %v", tc.class, got, tc.fails)
		}
	}
}
