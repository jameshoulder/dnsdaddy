package detect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Observation is one DNS question as the resolver saw it.
//
// This is the only thing the DNS path knows about detection. It is a plain
// value with no pointers into resolver state, so handing one over cannot
// couple the lifetime of a detector's memory to the lifetime of a query.
type Observation struct {
	Time       time.Time
	ClientIP   string
	ClientName string
	NetworkID  string
	// QName is already normalised: lowercase, no trailing dot.
	QName string
	QType string
	Proto string
	// Rcode is the response code as a string ("NOERROR", "NXDOMAIN",
	// "SERVFAIL"). Empty when the query never reached an upstream.
	Rcode string
	// Blocked reports that DNS Daddy synthesised this answer from policy.
	//
	// This flag is load-bearing. A blocked name is answered NXDOMAIN by
	// default, so counting blocks as upstream NXDOMAIN would make an
	// effective blocklist look like a DGA outbreak — the better the filtering,
	// the louder the false alarm. Every rcode-derived signal in this package
	// ignores blocked observations for that reason.
	Blocked bool
	Cached  bool
	// AnswerTTL is the smallest TTL in the answer section, or 0 if there was
	// no answer. The beaconing detector uses it to separate a client polling
	// on its own schedule from a client re-querying because its cache expired.
	AnswerTTL uint32
	// AuthenticatedData reports that the upstream set the AD bit, meaning it
	// validated the answer with DNSSEC.
	AuthenticatedData bool
}

// Event is an Observation enriched with the derived fields every detector
// needs, computed once by the engine rather than repeatedly per detector.
//
// The public-suffix lookup in particular is not free, and doing it six times
// per query would be the single largest cost in this package.
type Event struct {
	Observation

	// Parent is the registered domain (eTLD+1); Sub is everything below it.
	// HasParent is false for single labels, names that are themselves a public
	// suffix, and names under a private-namespace TLD such as .local or .corp.
	// See split.
	Parent    string
	Sub       string
	HasParent bool

	// Excluded marks a name whose parent is on the behavioural exclusion list.
	// Excluded names are still counted for volume but never produce findings.
	Excluded bool

	// NXDomain and ServFail are derived from Rcode and are false for any
	// blocked query — see Observation.Blocked.
	NXDomain bool
	ServFail bool

	// Labels is the name split into labels, computed once.
	Labels []string
}

// ClientKey identifies the subject of a client-scoped finding.
//
// When log_client_ip is off there is no per-device identity to key on, so
// behaviour is aggregated to the network. That makes the detectors coarser and
// is stated in the finding rather than hidden: an operator who turned off
// device attribution for privacy reasons has accepted exactly this trade.
func (e *Event) ClientKey() string {
	if e.ClientIP != "" {
		return e.ClientIP
	}
	if e.NetworkID != "" {
		return "network:" + e.NetworkID
	}
	return "unattributed"
}

// Detector is one behavioural heuristic.
//
// Detectors are driven from a single goroutine: Observe, Evaluate and Sweep
// are never called concurrently with each other, so implementations hold
// state without locking. Tracked may be called from another goroutine and
// must therefore be safe to read at any time — implementations satisfy this
// by publishing an atomic count from the engine goroutine.
type Detector interface {
	// Name is the stable detector identifier.
	Name() string
	// Info describes the detector for the catalogue endpoint and docs.
	Info() DetectorInfo
	// Observe folds one event into the detector's state. It must not allocate
	// unboundedly and must not block.
	Observe(e *Event)
	// Evaluate emits findings for any state whose window has closed.
	Evaluate(now time.Time) []Finding
	// Sweep discards state that has gone idle.
	Sweep(now time.Time)
	// Tracked reports how many keys the detector currently holds.
	Tracked() int
}

// DetectorInfo describes a detector so that the API, the dashboard and the
// documentation all state the same thing about what it does and how far it can
// be trusted.
type DetectorInfo struct {
	Name        string      `json:"name"`
	EventType   string      `json:"eventType"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Maturity    Maturity    `json:"maturity"`
	MaxSeverity Severity    `json:"maxSeverity"`
	Window      string      `json:"window"`
	MITRE       []Technique `json:"mitre"`
	// SignalNames lists what the detector measures, in the order it weights
	// them.
	SignalNames []string `json:"signals"`
	// FalsePositives is the benign traffic known to look like this.
	FalsePositives []string `json:"falsePositives"`
	// Enforces states whether the detector can block. It is false for every
	// detector in this package, and the field exists so that stays visible.
	Enforces bool `json:"enforces"`
}

// Sink receives findings.
type Sink interface {
	Emit(ctx context.Context, f Finding) error
}

// Options configures the engine.
type Options struct {
	// BufferSize bounds the observation queue. Full means dropped-and-counted,
	// never blocking the resolver.
	BufferSize int
	// EvalInterval is how often closed windows are evaluated.
	EvalInterval time.Duration
	// Cooldown suppresses repeat findings for the same subject and type.
	// Without it, a tunnel running for an hour produces one alert per window
	// for an hour, which trains the reader to close the tab.
	Cooldown time.Duration
	// MinSeverity drops findings below the given severity before they reach a
	// sink.
	MinSeverity Severity
}

// Engine drains observations, runs detectors, and forwards findings to a sink.
type Engine struct {
	ch         chan Observation
	detectors  []Detector
	sink       Sink
	exclusions *Exclusions
	log        *slog.Logger

	evalInterval time.Duration
	cooldown     time.Duration
	minSeverity  Severity

	// lastEmit implements the cooldown. It is only touched from the engine
	// goroutine and is swept alongside detector state.
	lastEmit map[string]time.Time

	observed   atomic.Uint64
	dropped    atomic.Uint64
	emitted    atomic.Uint64
	suppressed atomic.Uint64
	excluded   atomic.Uint64
	tracked    atomic.Int64

	countsMu sync.Mutex
	counts   map[countKey]uint64

	done chan struct{}
}

type countKey struct {
	eventType string
	severity  Severity
}

// New builds an engine. Run must be called to start it.
func New(detectors []Detector, sink Sink, exclusions *Exclusions, o Options, log *slog.Logger) *Engine {
	buf := o.BufferSize
	if buf <= 0 {
		buf = 4096
	}
	interval := o.EvalInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	cooldown := o.Cooldown
	if cooldown <= 0 {
		cooldown = 15 * time.Minute
	}
	min := o.MinSeverity
	if !min.Valid() {
		min = SeverityLow
	}
	return &Engine{
		ch:           make(chan Observation, buf),
		detectors:    detectors,
		sink:         sink,
		exclusions:   exclusions,
		log:          log,
		evalInterval: interval,
		cooldown:     cooldown,
		minSeverity:  min,
		lastEmit:     map[string]time.Time{},
		counts:       map[countKey]uint64{},
		done:         make(chan struct{}),
	}
}

// Observe queues an observation. It never blocks and never returns an error:
// the DNS path has nothing useful to do about a full detection queue, and
// making it wait would put a behavioural heuristic in the latency path of
// every page load on the network.
func (e *Engine) Observe(o Observation) {
	if e == nil {
		return
	}
	select {
	case e.ch <- o:
	default:
		e.dropped.Add(1)
	}
}

// Run drains observations until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	defer close(e.done)

	ticker := time.NewTicker(e.evalInterval)
	defer ticker.Stop()

	// Sweeping is cheaper than evaluating and only needs to keep memory
	// bounded, so it runs an order of magnitude less often.
	sweep := time.NewTicker(10 * e.evalInterval)
	defer sweep.Stop()

	for {
		select {
		case <-ctx.Done():
			// Drain what is queued so a shutdown does not lose the last few
			// seconds, then evaluate once so a window that closed during
			// shutdown still reports.
			for {
				select {
				case o := <-e.ch:
					e.ingest(o)
					continue
				default:
				}
				break
			}
			e.evaluate(context.WithoutCancel(ctx), time.Now())
			return

		case o := <-e.ch:
			e.ingest(o)

		case now := <-ticker.C:
			e.evaluate(ctx, now)

		case now := <-sweep.C:
			for _, d := range e.detectors {
				d.Sweep(now)
			}
			e.sweepCooldowns(now)
		}
	}
}

// Wait blocks until Run has returned.
func (e *Engine) Wait() { <-e.done }

// ingest enriches an observation and offers it to every detector.
func (e *Engine) ingest(o Observation) {
	e.observed.Add(1)

	if o.QName == "" {
		return
	}
	ev := Event{Observation: o}
	ev.Parent, ev.Sub, ev.HasParent = split(o.QName)
	ev.Labels = labelsOf(o.QName)

	// Our own block responses are not upstream failures. See
	// Observation.Blocked.
	if !o.Blocked {
		switch o.Rcode {
		case "NXDOMAIN":
			ev.NXDomain = true
		case "SERVFAIL":
			ev.ServFail = true
		}
	}

	ev.Excluded = e.exclusions.Excluded(o.QName)
	if ev.Excluded {
		e.excluded.Add(1)
	}

	for _, d := range e.detectors {
		d.Observe(&ev)
	}
}

// evaluate runs every detector's window evaluation and forwards the findings
// that survive severity filtering and cooldown.
func (e *Engine) evaluate(ctx context.Context, now time.Time) {
	var total int64
	for _, d := range e.detectors {
		for _, f := range d.Evaluate(now) {
			e.publish(ctx, f, now)
		}
		total += int64(d.Tracked())
	}
	e.tracked.Store(total)
}

func (e *Engine) publish(ctx context.Context, f Finding, now time.Time) {
	if f.Severity.Rank() < e.minSeverity.Rank() {
		e.suppressed.Add(1)
		return
	}

	key := f.EventType + "|" + f.Client.IP + "|" + f.Client.NetworkID + "|" + f.Domain
	if last, ok := e.lastEmit[key]; ok && now.Sub(last) < e.cooldown {
		e.suppressed.Add(1)
		return
	}
	e.lastEmit[key] = now

	if f.ID == "" {
		f.ID = newID()
	}
	f.SchemaVersion = SchemaVersion

	e.emitted.Add(1)
	e.countsMu.Lock()
	e.counts[countKey{f.EventType, f.Severity}]++
	e.countsMu.Unlock()

	if e.sink == nil {
		return
	}
	if err := e.sink.Emit(ctx, f); err != nil {
		e.log.Error("emit finding", "event_type", f.EventType, "error", err)
	}
}

// sweepCooldowns drops cooldown entries that can no longer suppress anything,
// so a long-running instance does not accumulate one map entry per subject
// ever seen.
func (e *Engine) sweepCooldowns(now time.Time) {
	for k, t := range e.lastEmit {
		if now.Sub(t) >= 2*e.cooldown {
			delete(e.lastEmit, k)
		}
	}
}

// Stats reports engine counters for /metrics.
type Stats struct {
	Observed   uint64
	Dropped    uint64
	Emitted    uint64
	Suppressed uint64
	Excluded   uint64
	Tracked    int64
}

// Stats returns a snapshot of the engine counters.
func (e *Engine) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	return Stats{
		Observed:   e.observed.Load(),
		Dropped:    e.dropped.Load(),
		Emitted:    e.emitted.Load(),
		Suppressed: e.suppressed.Load(),
		Excluded:   e.excluded.Load(),
		Tracked:    e.tracked.Load(),
	}
}

// FindingCount pairs an event type and severity with how many have been
// emitted since start.
type FindingCount struct {
	EventType string
	Severity  Severity
	Count     uint64
}

// Counts returns per-type, per-severity emission counts, sorted for stable
// metric output.
func (e *Engine) Counts() []FindingCount {
	if e == nil {
		return nil
	}
	e.countsMu.Lock()
	out := make([]FindingCount, 0, len(e.counts))
	for k, v := range e.counts {
		out = append(out, FindingCount{EventType: k.eventType, Severity: k.severity, Count: v})
	}
	e.countsMu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].EventType != out[j].EventType {
			return out[i].EventType < out[j].EventType
		}
		return out[i].Severity.Rank() > out[j].Severity.Rank()
	})
	return out
}

// Catalogue describes every registered detector.
func (e *Engine) Catalogue() []DetectorInfo {
	if e == nil {
		return nil
	}
	out := make([]DetectorInfo, 0, len(e.detectors))
	for _, d := range e.detectors {
		out = append(out, d.Info())
	}
	return out
}

// newID returns a random finding identifier.
//
// crypto/rand rather than a counter or a timestamp: findings are exported to
// systems that deduplicate on ID, and a restart must not be able to reissue an
// identifier that has already been used for something else.
func newID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on any platform this runs on, but a
		// finding with no ID is worse than one with a time-based ID.
		return "f" + hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}
