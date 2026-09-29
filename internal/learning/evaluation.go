package learning

import (
	"fmt"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
)

// EvaluateWindow scores a held-out window against a copy of the prior model.
// Neither fitted parameters nor operational counters are changed. This is an
// offline evaluation primitive, not a DNS or external-provider lookup.
// Observations must belong to a single client and one complete window.
func (m *Model) EvaluateWindow(observations []detect.Observation) (Result, error) {
	if len(observations) == 0 || len(observations) > m.opts.MaxWindowQueries+1 {
		return Result{}, fmt.Errorf("evaluation requires 1..%d observations in one window", m.opts.MaxWindowQueries+1)
	}
	first := observations[0]
	key, ok := clientKey(first)
	if !ok || first.Time.IsZero() {
		return Result{}, fmt.Errorf("invalid evaluation subject or time")
	}
	start := first.Time.UTC().Truncate(m.opts.Window)
	for _, o := range observations {
		k, valid := clientKey(o)
		if !valid || k != key || o.Time.UTC().Truncate(m.opts.Window) != start {
			return Result{}, fmt.Errorf("evaluation window mixes clients or times")
		}
	}
	copyModel, err := NewModel(m.opts)
	if err != nil {
		return Result{}, err
	}
	if c := m.clients[key]; c != nil {
		if start.Before(c.Baseline.LastAt) {
			return Result{}, fmt.Errorf("held-out window precedes the end of training")
		}
		copyClient := *c
		copyClient.window = nil
		copyModel.clients[key] = &copyClient
	}
	for _, o := range observations {
		copyModel.Observe(o)
	}
	out := copyModel.Advance(start.Add(m.opts.Window))
	if len(out) != 1 {
		return Result{}, fmt.Errorf("evaluation observations did not form a valid window")
	}
	return out[0], nil
}
