package retention

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTimeoutDoesNotConsumeLaterStepBudget(t *testing.T) {
	var first context.Context
	ranNext := false
	result := Run(context.Background(), 5*time.Millisecond, []Step{
		{Name: "slow", Prune: func(ctx context.Context) (int64, error) {
			first = ctx
			<-ctx.Done()
			return 0, ctx.Err()
		}},
		{Name: "next", Prune: func(ctx context.Context) (int64, error) {
			ranNext = true
			if ctx.Err() != nil {
				t.Fatal("next step inherited exhausted deadline")
			}
			if first.Err() == nil {
				t.Fatal("slow step did not actually time out")
			}
			return 2, nil
		}},
	})
	if !ranNext || !errors.Is(result[0].Err, context.DeadlineExceeded) || result[1].Err != nil || result[1].Removed != 2 {
		t.Fatalf("unexpected retention results: %+v", result)
	}
}

func TestShutdownPreventsLaterWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := Run(ctx, time.Second, []Step{
		{Name: "first", Prune: func(context.Context) (int64, error) { cancel(); return 0, nil }},
		{Name: "later", Prune: func(context.Context) (int64, error) { t.Fatal("write after shutdown"); return 0, nil }},
	})
	for _, result := range results {
		if !errors.Is(result.Err, context.Canceled) {
			t.Fatalf("shutdown not reported: %+v", result)
		}
	}
}

func TestFailureKeepsPartialCountAndCancelsChild(t *testing.T) {
	var child context.Context
	problem := errors.New("fixture failure")
	results := Run(context.Background(), time.Second, []Step{{Name: "partial", Prune: func(ctx context.Context) (int64, error) {
		child = ctx
		return 3, problem
	}}})
	if results[0].Removed != 3 || !errors.Is(results[0].Err, problem) || child.Err() == nil {
		t.Fatalf("lost partial result or leaked context: %+v", results)
	}
}
