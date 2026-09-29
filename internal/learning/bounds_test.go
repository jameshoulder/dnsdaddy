package learning

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestPersistedSampleCountsRejectInvalidBoundsAndMultiplicationOverflow(t *testing.T) {
	for _, tc := range []struct {
		name             string
		windows, queries uint64
		minimum, maximum int
		valid            bool
	}{
		{"empty", 0, 0, 20, 8192, true},
		{"queries without windows", 0, 1, 20, 8192, false},
		{"minimum population", 2, 40, 20, 8192, true},
		{"maximum population", 2, 16384, 20, 8192, true},
		{"below minimum", 2, 39, 20, 8192, false},
		{"above maximum", 2, 16385, 20, 8192, false},
		{"negative minimum", 1, 20, -1, 8192, false},
		{"negative maximum", 1, 20, 20, -1, false},
		{"zero minimum", 1, 20, 0, 8192, false},
		{"unbounded minimum", 1, 20, math.MaxInt, 8192, false},
		{"unbounded maximum", 1, 20, 20, math.MaxInt, false},
		{"inverted bounds", 1, 20, 30, 20, false},
		// Without the division guard, both products below wrap to zero and
		// accept an impossible nonzero number of windows with zero queries.
		{"product wraps to zero", 1 << 48, 0, 65536, 65536, false},
		{"largest fitting product", math.MaxUint64 / 65536, math.MaxUint64 / 65536 * 65536, 65536, 65536, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validPersistedSampleCounts(tc.windows, tc.queries, tc.minimum, tc.maximum); got != tc.valid {
				t.Fatalf("sample counts accepted=%v, want %v", got, tc.valid)
			}
		})
	}
}

func TestReadinessRejectsInvalidSignedWarmupCounts(t *testing.T) {
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	b := baseline{Windows: math.MaxUint64, FirstAt: at, LastAt: at.Add(time.Hour)}
	for _, warmup := range []int{-1, 0, 1, 10001, math.MaxInt} {
		if b.ready(Options{WarmupWindows: warmup, WarmupDuration: time.Minute}) {
			t.Fatalf("invalid warmup count %d reported a ready baseline", warmup)
		}
	}
	if !b.ready(Options{WarmupWindows: 10000, WarmupDuration: time.Minute}) {
		t.Fatal("valid upper warmup bound was rejected")
	}
}

func TestTrainingRejectsInvalidCountsWithoutChangingFittedState(t *testing.T) {
	o, err := testOptions().withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	original := baseline{
		Windows: 4, Queries: 160, FirstAt: at.Add(-4 * time.Minute), LastAt: at,
		Mean: [FeatureCount]float64{1, 2, 3, .4, .5, 6},
	}
	for _, eligible := range []int{-1, 0, 1, o.MinWindowQueries - 1, o.MaxWindowQueries + 1, 65537, math.MaxInt} {
		b := original
		if b.train([FeatureCount]float64{2, 3, 4, .5, .6, 7}, Window{Start: at, End: at.Add(time.Minute), EligibleQueries: eligible}, o) {
			t.Fatalf("trained on invalid eligible count %d", eligible)
		}
		if b != original {
			t.Fatalf("rejected count %d changed fitted state", eligible)
		}
	}
}

func TestTrainingStopsAtPersistableCounterLimitsWithoutWrapping(t *testing.T) {
	o, err := testOptions().withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	w := Window{Start: at, End: at.Add(time.Minute), Queries: 40, EligibleQueries: 40}
	for _, tc := range []struct {
		name          string
		b             baseline
		firstAccepted bool
	}{
		{"last window fits", baseline{Windows: maxBaselineWindows - 1, Queries: 160}, true},
		{"last query increment fits", baseline{Windows: 4, Queries: maxBaselineQueries - 40}, true},
		{"window limit exhausted", baseline{Windows: maxBaselineWindows, Queries: 160}, false},
		{"query increment exceeds limit", baseline{Windows: 4, Queries: maxBaselineQueries - 39}, false},
		{"window counter would wrap", baseline{Windows: math.MaxUint64, Queries: 160}, false},
		{"query counter would wrap", baseline{Windows: 4, Queries: math.MaxUint64}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, before := tc.b, tc.b
			if accepted := b.train([FeatureCount]float64{}, w, o); accepted != tc.firstAccepted {
				t.Fatalf("first update accepted=%v, want %v", accepted, tc.firstAccepted)
			}
			if tc.firstAccepted {
				if b.Windows != before.Windows+1 || b.Queries != before.Queries+40 {
					t.Fatalf("last valid increment changed counters unexpectedly: %+v", b)
				}
				before = b
			} else if b != before {
				t.Fatal("rejected first update changed fitted state")
			}
			if b.train([FeatureCount]float64{1, 2, 3, .4, .5, 6}, w, o) || b != before {
				t.Fatal("exhausted counter accepted an update or changed fitted state")
			}
		})
	}
}

func TestExhaustedBaselineDoesNotClaimSuccessfulTraining(t *testing.T) {
	m, at := trainedModel(t)
	b := &m.clients["192.0.2.10"].Baseline
	b.Windows = maxBaselineWindows
	b.Queries = maxBaselineWindows * 40
	before := *b
	trained := m.windows.Trained
	r := feedWindow(m, benignWindow(at, "192.0.2.10", 40), at)
	if r.Trained || r.State != "excluded" || !strings.Contains(strings.Join(r.ExcludedReasons, ","), "baseline_sample_limit") {
		t.Fatalf("exhausted baseline reported fitting success: %+v", r)
	}
	if *b != before || m.windows.Trained != trained || m.windows.Quarantined != 1 {
		t.Fatal("exhausted baseline changed parameters or its update accounting")
	}
}
