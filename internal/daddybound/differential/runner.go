package differential

import (
	"context"
	"fmt"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// Run puts every scenario through Daddybound and through the oracle, and
// returns the comparison.
//
// Each scenario gets a freshly built hierarchy and a freshly served copy of
// it, so nothing leaks between them. That costs a listener per scenario and
// buys the property that a failure can be reproduced by running that one
// scenario alone — which is the property that gets a bug fixed.
func Run(ctx context.Context, oracle Reference, scenarios []lab.Scenario) (Report, error) {
	report := Report{Oracle: oracle.Name()}

	for _, sc := range scenarios {
		c, err := runOne(ctx, oracle, sc)
		if err != nil {
			return report, fmt.Errorf("scenario %s: %w", sc.Name, err)
		}
		report.Comparisons = append(report.Comparisons, c)
	}
	return report, nil
}

func runOne(ctx context.Context, oracle Reference, sc lab.Scenario) (Comparison, error) {
	h, err := sc.Build()
	if err != nil {
		return Comparison{}, fmt.Errorf("build: %w", err)
	}

	c := Comparison{Scenario: sc.Name, KnownGap: sc.KnownGap}

	dbResult, dbErr := daddyboundVerdict(ctx, h, sc)
	c.Daddybound = dbResult
	if dbErr != nil {
		c.DaddyboundErr = dbErr.Error()
	}

	// The oracle sees the same hierarchy over real DNS. Same records, same
	// signatures, same bytes — a differential comparison against a
	// separately constructed copy of "the same" zone would make every
	// disagreement ambiguous.
	srv, err := h.StartServer()
	if err != nil {
		return Comparison{}, fmt.Errorf("serve: %w", err)
	}
	defer srv.Close() //nolint:errcheck // the report is the outcome here

	refResult, refErr := oracle.Validate(ctx, sc.Query, sc.QType)
	c.Reference = refResult
	if refErr != nil {
		c.ReferenceErr = refErr.Error()
	}

	c.Class = Classify(dbResult, dbErr, refResult, refErr, sc.KnownGap)
	return c, nil
}

// daddyboundVerdict runs Daddybound, converting a panic into an error.
//
// A panic is a real outcome for a validator fed hostile input, and it is one
// the comparison must record rather than propagate: a suite that aborts on
// the first crash reports one finding where there might be ten. It is
// classified as DADDYBOUND_ERROR, which is never counted as agreement.
func daddyboundVerdict(ctx context.Context, h *lab.Hierarchy, sc lab.Scenario) (result dnssec.ValidationResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("daddybound panicked: %v", r)
		}
	}()

	v, err := h.Validator(sc.At)
	if err != nil {
		return dnssec.ValidationResult{}, err
	}
	return v.Validate(ctx, sc.Query, sc.QType), nil
}
