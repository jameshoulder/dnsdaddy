package learning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
)

// Engine keeps model fitting, persistence and findings off the DNS response
// path. Saturation drops observations immediately and exposes the loss.
type Engine struct {
	mu                sync.RWMutex
	checkpointMu      sync.Mutex
	model             *Model
	opts              Options
	ch                chan detect.Observation
	sink              detect.Sink
	log               *slog.Logger
	done              chan struct{}
	started           atomic.Bool
	stopped           atomic.Bool
	running           atomic.Bool
	received          atomic.Uint64
	dropped           atomic.Uint64
	privacySkipped    atomic.Uint64
	inflight          atomic.Int64
	markedDrops       uint64
	persistence       PersistenceStatus
	findingsEmitted   uint64
	findingErrors     uint64
	findingSuppressed uint64
}

// New fails explicitly on corrupt or incompatible saved parameters. The
// caller can report a disabled learner while DNS keeps operating, or require
// the operator to repair the state. It must not silently claim a loaded model.
func New(o Options, sink detect.Sink, log *slog.Logger) (*Engine, error) {
	m, err := NewModel(o)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	e := &Engine{model: m, opts: m.opts, ch: make(chan detect.Observation, m.opts.BufferSize), sink: sink, log: log, done: make(chan struct{}), persistence: PersistenceStatus{Enabled: o.StatePath != ""}}
	if err = e.load(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) Observe(o detect.Observation) bool {
	if e == nil {
		return false
	}
	e.received.Add(1)
	if e.stopped.Load() {
		e.dropped.Add(1)
		return false
	}
	e.inflight.Add(1)
	defer e.inflight.Add(-1)
	if e.stopped.Load() {
		e.dropped.Add(1)
		return false
	}
	// Refuse unreasonable copies before queueing them. Domain parsing and
	// statistics remain in the worker, so this seam has bounded cost.
	if len(o.QName) > 254 || len(o.ClientIP) > 64 || len(o.ClientName) > 256 || len(o.NetworkID) > 128 || len(o.QType) > 10 || len(o.Rcode) > 16 {
		e.dropped.Add(1)
		return false
	}
	select {
	case e.ch <- o:
		return true
	default:
		e.dropped.Add(1)
		return false
	}
}

// SkipPrivacy records that policy/global privacy settings prohibited a model
// sample without retaining any part of that query or its client identity.
func (e *Engine) SkipPrivacy() {
	if e != nil {
		e.privacySkipped.Add(1)
	}
}

func (e *Engine) Done() <-chan struct{} { return e.done }

func (e *Engine) Run(ctx context.Context) {
	if !e.started.CompareAndSwap(false, true) {
		return
	}
	e.running.Store(true)
	defer func() { e.running.Store(false); e.stopped.Store(true); close(e.done) }()
	interval := min(e.opts.Window/4, 30*time.Second)
	ticker := time.NewTicker(interval)
	checkpoint := time.NewTicker(e.opts.CheckpointInterval)
	defer ticker.Stop()
	defer checkpoint.Stop()
	for {
		select {
		case o := <-e.ch:
			e.process(ctx, o)
		case now := <-ticker.C:
			e.advance(ctx, now.UTC())
		case <-checkpoint.C:
			if err := e.Checkpoint(); err != nil {
				e.log.Error("local learning checkpoint failed", "err", err)
			}
		case <-ctx.Done():
			e.stopped.Store(true)
			// A sender that passed the first stop check may still be copying
			// into the channel. Wait for those bounded, non-blocking sends
			// before draining so an accepted sample cannot arrive after Done.
			for e.inflight.Load() != 0 {
				runtime.Gosched()
			}
			// The channel is never closed while resolver goroutines can send.
			// A bounded drain preserves accepted observations on clean exit.
			for range cap(e.ch) {
				select {
				case o := <-e.ch:
					e.process(ctx, o)
				default:
					goto drained
				}
			}
		drained:
			e.advance(ctx, time.Now().UTC())
			if err := e.Checkpoint(); err != nil {
				e.log.Error("local learning final checkpoint failed", "err", err)
			}
			return
		}
	}
}

func (e *Engine) markLossLocked() {
	if n := e.dropped.Load(); n != e.markedDrops {
		e.model.MarkLoss()
		e.markedDrops = n
	}
}
func (e *Engine) process(ctx context.Context, o detect.Observation) {
	e.mu.Lock()
	e.markLossLocked()
	results := e.model.Observe(o)
	e.mu.Unlock()
	e.emit(ctx, results)
}
func (e *Engine) advance(ctx context.Context, now time.Time) {
	e.mu.Lock()
	e.markLossLocked()
	results := e.model.Advance(now)
	e.mu.Unlock()
	e.emit(ctx, results)
}

func (e *Engine) emit(ctx context.Context, results []Result) {
	for _, r := range results {
		if r.State != "anomaly" || e.sink == nil {
			continue
		}
		e.mu.Lock()
		c := e.model.clients[r.Client]
		if c == nil || (!c.LastFinding.IsZero() && r.Window.End.Sub(c.LastFinding) < e.opts.Cooldown) {
			e.findingSuppressed++
			e.mu.Unlock()
			continue
		}
		e.mu.Unlock()
		f := finding(r)
		err := e.sink.Emit(ctx, f)
		e.mu.Lock()
		if err != nil {
			e.findingErrors++
		} else {
			e.findingsEmitted++
			if c = e.model.clients[r.Client]; c != nil {
				c.LastFinding = r.Window.End
			}
		}
		e.mu.Unlock()
		if err != nil {
			e.log.Error("local learning finding was not stored", "err", err)
		}
	}
}

func finding(r Result) detect.Finding {
	id := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s", Algorithm, r.Client, r.Window.Start.Format(time.RFC3339Nano))))
	client := detect.Client{NetworkID: r.NetworkID}
	if !strings.HasPrefix(r.Client, "network:") && r.Client != "unattributed" {
		client.IP = r.Client
	}
	signals := make([]detect.Signal, 0, len(r.Features))
	for _, feature := range r.Features {
		if feature.Z == nil {
			continue
		}
		n := math.Min(12, *feature.Z) / 12
		signals = append(signals, detect.Signal{Name: feature.Name, Description: "Absolute deviation from this client's prior local baseline, in standard-deviation units", Value: *feature.Z, Floor: 0, Ceiling: 12, Normalised: n, Weight: 1.0 / FeatureCount, Contribution: n / FeatureCount})
	}
	distance := 0.0
	if r.Score != nil {
		distance = *r.Score
	}
	return detect.Finding{
		SchemaVersion: detect.SchemaVersion, ID: hex.EncodeToString(id[:16]), Time: r.Window.End, EventType: EventType, Severity: detect.SeverityLow,
		Confidence: 0, Score: distance / 12, Client: client, Title: "Local DNS behaviour changed",
		Summary: fmt.Sprintf("%d successful queries differ from this client's prior %d-window baseline in %d features; investigate the change before acting.", r.Window.EligibleQueries, r.BaselineWindows, r.AnomalousSignals),
		Signals: signals, Evidence: map[string]any{"algorithm": Algorithm, "modelVersion": ModelVersion, "anomalyDistance": distance, "threshold": r.Threshold, "scoreMeaning": "normalised mean capped absolute standardised deviation, not maliciousness probability", "confidenceAvailable": false, "confidenceMeaning": "no empirical probability calibration; confidence is unknown", "enforces": false, "trainedOnThisWindow": false, "baselineWindows": r.BaselineWindows, "baselineQueries": r.BaselineQueries, "baselineAgeSeconds": r.BaselineAgeSeconds, "features": r.Features, "excludedReasons": r.ExcludedReasons},
		Window: detect.Window{Start: r.Window.Start, End: r.Window.End, Queries: r.Window.Queries}, MITRE: []detect.Technique{},
		FalsePositives: []string{"Software deployment or a newly active application", "CDN and endpoint-security telemetry", "Client address reassignment, NAT aggregation or a changed working pattern"},
		NextSteps:      []string{"Inspect recorded queries and the original policy decisions for this client and window.", "Compare the feature measurements with the prior baseline and confirm the client identity.", "Record the investigated outcome; review labels do not automatically allow domains or train this model."}, Detector: Algorithm, Maturity: detect.MaturityExperimental,
	}
}

func (e *Engine) Status() Status {
	if e == nil {
		return DisabledStatus()
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	m := e.model
	s := Status{Enabled: true, Running: e.running.Load(), Mode: "learn", Experimental: true, Algorithm: Algorithm, ModelVersion: ModelVersion, CounterScope: "since_start; client baseline counts persist across restarts", ScoreMeaning: "mean capped absolute standardised deviation; not maliciousness probability", WindowSeconds: int64(e.opts.Window.Seconds()), MinWindowQueries: e.opts.MinWindowQueries, WarmupWindows: e.opts.WarmupWindows, WarmupSeconds: int64(e.opts.WarmupDuration.Seconds()), MemoryHalfLifeWindows: math.Log(0.5) / math.Log(1-e.opts.Alpha), Observations: m.observations, Windows: m.windows, Persistence: e.persistence, LastProcessedAt: m.lastProcessed, Recent: make([]Result, 0, len(m.recent)), FindingsEmitted: e.findingsEmitted, FindingErrors: e.findingErrors, FindingSuppressed: e.findingSuppressed}
	s.Observations.Received = e.received.Load()
	s.Available = true
	s.Limitations = sampleLimitations()
	s.Observations.Dropped = e.dropped.Load()
	s.Observations.PrivacySkipped = e.privacySkipped.Load()
	s.Clients = ClientCounts{Tracked: len(m.clients), Max: e.opts.MaxClients, Evicted: m.evicted}
	for _, c := range m.clients {
		if c.Baseline.ready(e.opts) {
			s.Clients.Ready++
		} else {
			s.Clients.Warming++
		}
	}
	for i := len(m.recent) - 1; i >= 0; i-- {
		r := m.recent[i]
		r.Features = append([]Feature(nil), r.Features...)
		r.ExcludedReasons = append([]string{}, r.ExcludedReasons...)
		s.Recent = append(s.Recent, r)
	}
	s.Queue.Depth = len(e.ch)
	s.Queue.Capacity = cap(e.ch)
	return s
}
func (e *Engine) Inspect(client string) (ClientView, bool) {
	if e == nil {
		return ClientView{}, false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.model.Inspect(client)
}
func (e *Engine) Clients(limit int) []ClientView {
	if e == nil {
		return []ClientView{}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.model.Clients(limit)
}
