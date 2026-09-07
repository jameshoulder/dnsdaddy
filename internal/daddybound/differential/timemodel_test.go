package differential_test

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential/refunbound"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// The time model of the differential comparison.
//
// Daddybound takes its notion of the current time from an injected clock,
// because RFC 4035 §5.3.1 phrases both signature-validity checks against
// "the validator's notion of the current time". A reference validator using
// the wall clock is therefore answering a different question, and signature
// validity is precisely where that difference bites: a fixture with a fixed
// window is inside it for one validator and outside it for the other the
// moment the calendar passes the window.
//
// Review caught this before it happened. The fixtures expire on 2027-01-01,
// and from that date the oracle would have reported the valid scenario
// expired while Daddybound validated it at its June 2026 clock — a permanent
// FALSE_SECURE in CI produced by nothing but the date the job ran.
//
// The fix is to remove the wall clock from the comparison rather than to move
// the expiry: the oracle is pinned to the scenario's instant. This test is
// what makes that structural rather than incidental. It walks the fixture
// window's boundaries deliberately, so it fails today if the oracle is ever
// unpinned again — instead of failing silently on some future date.

func TestBothValidatorsJudgeSignaturesAtTheScenarioTime(t *testing.T) {
	if !refunbound.Available() {
		t.Skip(refunbound.Why())
	}

	tests := []struct {
		name string
		at   time.Time
		want dnssec.ValidationStatus
	}{
		{
			name: "inside the fixture window",
			at:   lab.Now(),
			want: dnssec.StatusSecure,
		},
		{
			// A year before the signatures were made. An unpinned oracle
			// sees the wall clock instead and calls this valid.
			name: "before inception",
			at:   lab.Inception.Add(-365 * 24 * time.Hour),
			want: dnssec.StatusBogus,
		},
		{
			// A year after they expired. This is the January 2027 case,
			// asserted now rather than waiting for the calendar.
			name: "after expiration",
			at:   lab.Expiration.Add(365 * 24 * time.Hour),
			want: dnssec.StatusBogus,
		},
		{
			// Far enough out that no plausible future CI run is inside the
			// window by accident.
			name: "fifty years after expiration",
			at:   lab.Expiration.Add(50 * 365 * 24 * time.Hour),
			want: dnssec.StatusBogus,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := lab.Standard()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			srv, err := h.StartServer()
			if err != nil {
				t.Fatalf("serve: %v", err)
			}
			defer srv.Close() //nolint:errcheck // the assertions are the outcome

			oracle, err := refunbound.New(refunbound.Config{
				Forward:        srv.Addr(),
				TrustAnchor:    h.AnchorDS(),
				ValidationTime: tc.at,
			})
			if err != nil {
				t.Fatalf("oracle: %v", err)
			}
			if closer, ok := oracle.(interface{ Close() }); ok {
				defer closer.Close()
			}

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			v, err := h.Validator(tc.at)
			if err != nil {
				t.Fatalf("validator: %v", err)
			}
			db := v.Validate(ctx, lab.AnswerName, dns.TypeA)
			ref, refErr := oracle.Validate(ctx, lab.AnswerName, dns.TypeA)

			if db.Status != tc.want {
				t.Errorf("daddybound at %s: %s, want %s\n%s",
					tc.at.Format(time.RFC3339), db.Status, tc.want, db.Trace())
			}
			if refErr != nil {
				t.Fatalf("reference at %s: %v", tc.at.Format(time.RFC3339), refErr)
			}
			if ref.Status != tc.want {
				t.Errorf("reference at %s: %s, want %s — the oracle is judging signatures against the wall clock rather than the scenario time (%s)",
					tc.at.Format(time.RFC3339), ref.Status, tc.want, ref.Detail)
			}

			// And the comparison itself must not report a disagreement.
			if class := differential.Classify(db, nil, ref, nil, ""); class != differential.ClassMatch {
				t.Errorf("at %s the two validators disagree: %s (daddybound=%s, reference=%s %s)",
					tc.at.Format(time.RFC3339), class, db.Status, ref.Status, ref.Detail)
			}
		})
	}
}

// A cheap invariant that runs in every build, with or without an oracle:
// the instant the scenarios validate at must lie inside the window the
// fixtures are signed for.
//
// Editing one without the other is the easy mistake, and it would otherwise
// surface as every scenario failing for a reason that looks nothing like a
// clock problem.
func TestScenarioTimeLiesInsideTheFixtureWindow(t *testing.T) {
	if !lab.Now().After(lab.Inception) || !lab.Now().Before(lab.Expiration) {
		t.Fatalf("lab.Now() = %s is outside the fixture window [%s, %s]",
			lab.Now().Format(time.RFC3339),
			lab.Inception.Format(time.RFC3339),
			lab.Expiration.Format(time.RFC3339))
	}

	// Scenarios that expect Secure must validate inside the window; the ones
	// that deliberately sit outside it expect Bogus.
	for _, sc := range lab.Scenarios() {
		if sc.Expect != dnssec.StatusSecure {
			continue
		}
		if sc.At.Before(lab.Inception) || sc.At.After(lab.Expiration) {
			t.Errorf("scenario %q expects Secure but validates at %s, outside the fixture window",
				sc.Name, sc.At.Format(time.RFC3339))
		}
	}
}
