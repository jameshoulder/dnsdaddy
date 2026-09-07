package dnssec_test

import (
	"context"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// Every lab scenario, run against Daddybound alone. The differential
// comparison against a reference validator is a separate, stronger test; this
// one establishes that Daddybound's own expectations hold before anything is
// compared to anyone else's.
func TestScenarios(t *testing.T) {
	for _, sc := range lab.Scenarios() {
		t.Run(sc.Name, func(t *testing.T) {
			h, err := sc.Build(lab.StandardSpec())
			if err != nil {
				t.Fatalf("build %s: %v", sc.Name, err)
			}
			v, err := h.Validator(sc.At)
			if err != nil {
				t.Fatalf("validator: %v", err)
			}

			got := v.Validate(context.Background(), sc.Query, sc.QType)
			if got.Status != sc.Expect {
				t.Fatalf("%s\nstatus = %s, want %s\nwhy this scenario exists: %s\n%s",
					sc.Name, got.Status, sc.Expect, sc.Why, got.Trace())
			}
			if sc.Reason != "" && got.Reason != sc.Reason {
				t.Errorf("%s\nreason = %s, want %s\n%s", sc.Name, got.Reason, sc.Reason, got.Trace())
			}
		})
	}
}
