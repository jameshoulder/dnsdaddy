// Package retention runs independent, bounded cleanup steps sequentially.
package retention

import (
	"context"
	"errors"
	"time"
)

// StepTimeout bounds each cooperative database operation, not a shared sweep.
// A slow table must not consume the next table's budget. Shutdown still cancels
// every child. Calls are synchronous: a timed-out writer is never abandoned in
// a goroutine which could overlap the next sweep.
const StepTimeout = 20 * time.Second

type Step struct {
	Name  string
	Prune func(context.Context) (int64, error)
}

type Result struct {
	Name    string
	Removed int64
	Err     error
}

// Run attempts every step unless its parent is cancelled. Each receives a fresh
// timeout. A shared database outage can still fail multiple steps; these results
// do not guarantee removal or an exact physical-erasure deadline.
func Run(ctx context.Context, timeout time.Duration, steps []Step) []Result {
	out := make([]Result, 0, len(steps))
	for _, step := range steps {
		result := Result{Name: step.Name}
		switch {
		case ctx.Err() != nil:
			result.Err = ctx.Err()
		case timeout <= 0 || step.Prune == nil:
			result.Err = errors.New("invalid retention step or timeout")
		default:
			child, cancel := context.WithTimeout(ctx, timeout)
			result.Removed, result.Err = step.Prune(child)
			// Do not count completion after its deadline as verified success,
			// even if a driver returned no error. Preserve any row count.
			if result.Err == nil {
				result.Err = child.Err()
			}
			cancel()
		}
		out = append(out, result)
	}
	return out
}
