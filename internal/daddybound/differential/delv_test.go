package differential_test

import (
	"context"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential/refdelv"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// The whole suite against BIND's delv, a second and independent validator.
//
// libunbound and delv are separate codebases with separate validators, and
// delv performs its own chain walk rather than relying on a forwarder. Where
// both agree with Daddybound the evidence is much stronger than one oracle
// gives; where they agree with each other and not with Daddybound, the
// question is about Daddybound.
//
// delv has no equivalent of unbound's val-override-date, so it judges
// signatures against the wall clock. The scenarios are therefore shifted to
// surround the moment the test runs: the same zones, keys and mutations, with
// only the timestamps moved. That keeps the suite meaningful on any future
// date without weakening what it asserts.
func TestAgainstDelv(t *testing.T) {
	if !refdelv.Available() {
		t.Skip(refdelv.Why())
	}

	shift := time.Since(lab.Now())
	for _, base := range lab.Scenarios() {
		sc := base.Shifted(shift)
		t.Run(sc.Name, func(t *testing.T) {
			if sc.NoOracle != "" {
				t.Skip(sc.NoOracle)
			}
			h, err := sc.Build(lab.StandardSpec())
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			srv, err := h.StartServer()
			if err != nil {
				t.Fatalf("serve: %v", err)
			}
			defer srv.Close() //nolint:errcheck // the assertions are the outcome

			oracle, err := refdelv.New(refdelv.Config{
				Forward: srv.Addr(), Anchor: h.Anchor, WorkDir: t.TempDir(),
			})
			if err != nil {
				t.Fatalf("oracle: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			v, err := h.Validator(sc.At)
			if err != nil {
				t.Fatalf("validator: %v", err)
			}
			db := v.Validate(ctx, sc.Query, sc.QType)
			ref, refErr := oracle.Validate(ctx, sc.Query, sc.QType)

			class := differential.Classify(db, nil, ref, refErr, sc.KnownGap)
			switch class {
			case differential.ClassFalseSecure:
				t.Fatalf("FALSE SECURE against %s — daddybound accepted data the reference rejected\n"+
					"  why this scenario exists: %s\n  reference: %s\n%s",
					oracle.Name(), sc.Why, ref.Detail, db.Trace())
			case differential.ClassMatch:
			case differential.ClassKnownGap:
				t.Logf("known gap: daddybound=%s reference=%s — %s", db.Status, ref.Status, sc.KnownGap)
			default:
				t.Errorf("%s: daddybound=%s (%s), reference=%s (%s)\n%s",
					class, db.Status, db.Reason, ref.Status, ref.Detail, db.Trace())
			}
		})
	}
}

// Shifting a scenario must move its fixtures and its validation time
// together. If it moved only one, every scenario would fail for a reason that
// looks nothing like a clock problem — which is the failure mode that made
// the original fixture-lifetime defect hard to see.
func TestShiftingAScenarioMovesFixturesAndClockTogether(t *testing.T) {
	const shift = 3 * 365 * 24 * time.Hour

	for _, base := range lab.Scenarios() {
		if base.Expect != dnssec.StatusSecure {
			continue
		}
		sc := base.Shifted(shift)
		h, err := sc.Build(lab.StandardSpec())
		if err != nil {
			t.Fatalf("%s: build: %v", sc.Name, err)
		}
		v, err := h.Validator(sc.At)
		if err != nil {
			t.Fatalf("%s: validator: %v", sc.Name, err)
		}
		got := v.Validate(context.Background(), sc.Query, sc.QType)
		if got.Status != base.Expect {
			t.Errorf("%s shifted by three years: %s, want %s\n%s",
				sc.Name, got.Status, base.Expect, got.Trace())
		}
	}
}
