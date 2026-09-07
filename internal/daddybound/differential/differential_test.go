package differential_test

import (
	"context"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential/refunbound"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// The whole lab suite, run through Daddybound and through libunbound, with
// both reading the same served hierarchy.
//
// This is the strongest evidence v0.1 produces. Daddybound's own scenario
// test says Daddybound agrees with its author; this one says it agrees with
// an implementation that has been validating DNSSEC in production for two
// decades, and names every case where it does not.
func TestAgainstLibunbound(t *testing.T) {
	if !refunbound.Available() {
		t.Skip(refunbound.Why())
	}

	// Started once to obtain an address for the oracle's forwarder; each
	// scenario then serves its own hierarchy. The address is stable because
	// the runner rebinds an ephemeral port per scenario, so the oracle is
	// built per scenario too.
	for _, sc := range lab.Scenarios() {
		t.Run(sc.Name, func(t *testing.T) {
			runScenario(t, sc)
		})
	}
}

func runScenario(t *testing.T, sc lab.Scenario) {
	t.Helper()

	h, err := sc.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	srv, err := h.StartServer()
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	defer srv.Close() //nolint:errcheck // the assertions below are the outcome

	oracle, err := refunbound.New(refunbound.Config{
		Forward:     srv.Addr(),
		TrustAnchor: h.AnchorDS(),
	})
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	if closer, ok := oracle.(interface{ Close() }); ok {
		defer closer.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
		// The one failure this project treats as release-blocking: the
		// reference established the data does not validate and Daddybound
		// said it does.
		t.Fatalf("FALSE SECURE — daddybound accepted data %s rejected\n"+
			"  scenario: %s\n  why it exists: %s\n  reference: %s\n%s",
			oracle.Name(), sc.Name, sc.Why, ref.Detail, db.Trace())
	case differential.ClassMatch, differential.ClassKnownGap:
		if class == differential.ClassKnownGap {
			t.Logf("known gap: daddybound=%s reference=%s — %s", db.Status, ref.Status, sc.KnownGap)
		}
	default:
		t.Errorf("%s: daddybound=%s (%s), reference=%s (%s)\n%s",
			class, db.Status, db.Reason, ref.Status, ref.Detail, db.Trace())
	}
}
