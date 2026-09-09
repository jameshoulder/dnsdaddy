package observe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// Validator is the part of Daddybound this package drives.
//
// An interface so a test can make the validator do things a real one will not
// do on demand — return Bogus, block past a deadline, panic — and check that
// none of them reaches a client.
type Validator interface {
	Validate(ctx context.Context, qname string, rrtype uint16) dnssec.ValidationResult
}

// Sink receives completed observations.
//
// Implementations must not block: this runs on a worker whose only other job
// is validating, and a sink that waits on a database would convert a slow disk
// into a stalled observation queue. internal/store's writer buffers.
type Sink interface {
	Record(Observation)
}

// Request is one query worth observing, captured at the moment its answer was
// decided.
type Request struct {
	// ID correlates with the query log row. See Observation.ID.
	ID     string
	Domain string
	QName  string
	QType  uint16
	// Cached reports that the client's answer came from cache.
	Cached bool
	// UpstreamStatus is what the upstream asserted, copied from the query
	// event. Carried so the observation row is self-contained; never read
	// while validating.
	UpstreamStatus string
}

// Options configures an Observer.
type Options struct {
	// Workers bounds concurrent validations. Zero picks a default.
	Workers int
	// Queue is how many requests may wait. Zero picks a default.
	Queue int
	// Timeout bounds one observation including its supporting queries.
	Timeout time.Duration
	Log     *slog.Logger
}

func (o Options) withDefaults() Options {
	if o.Workers <= 0 {
		o.Workers = 2
	}
	if o.Queue <= 0 {
		o.Queue = 256
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return o
}

// Stats is what the feature has done so far.
type Stats struct {
	// Observed is how many validations completed, of any status.
	Observed uint64
	// Dropped is how many were discarded because the queue was full.
	//
	// Exposed rather than swallowed: dropping biases the sample towards quiet
	// periods, and a reader shown "10,000 observed" without "and 4,000
	// dropped" will draw a conclusion the sample cannot support.
	Dropped uint64
	// Panics is how many validations aborted in the containment boundary.
	// Should be zero; a non-zero value is a bug report, not an operational
	// statistic.
	Panics uint64
	// ByStatus counts completed observations per status.
	ByStatus map[Status]uint64
	// Disagreements counts local-versus-upstream classes.
	Disagreements map[string]uint64
	// LastAt and LastStatus describe the most recent observation.
	LastAt     time.Time
	LastStatus Status
}

// Observer validates real queries off the answer path.
type Observer struct {
	v    Validator
	sink Sink
	opts Options

	queue chan Request

	// started guards Run, which must be called exactly once.
	started atomic.Bool
	done    chan struct{}

	observed atomic.Uint64
	dropped  atomic.Uint64
	panics   atomic.Uint64

	mu            sync.Mutex
	byStatus      map[Status]uint64
	disagreements map[string]uint64
	lastAt        time.Time
	lastStatus    Status
}

// New builds an Observer. It does no work until Run is called.
func New(v Validator, sink Sink, o Options) *Observer {
	o = o.withDefaults()
	return &Observer{
		v:             v,
		sink:          sink,
		opts:          o,
		queue:         make(chan Request, o.Queue),
		done:          make(chan struct{}),
		byStatus:      map[Status]uint64{},
		disagreements: map[string]uint64{},
	}
}

// NewID returns a correlation identifier for one query.
//
// Random rather than sequential because the query log row and the observation
// row are written independently and asynchronously: there is no moment at
// which a shared counter could be allocated without coordinating the two, and
// coordinating them would put the observation on the answer path.
//
// A failure of the system random source returns the empty string, which every
// caller treats as "no correlation available". Panicking here would let an
// exhausted entropy pool take down a DNS server.
func NewID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// Observe enqueues a query for validation and returns whether it was accepted.
//
// Never blocks, never allocates on the fast path beyond the send, and never
// returns an error a caller has to handle. That is the property the whole
// milestone rests on: the answer path does a non-blocking channel send and a
// counter increment, so no validation — however slow, however hostile the zone
// — can add latency to a client's answer.
func (o *Observer) Observe(r Request) bool {
	select {
	case o.queue <- r:
		return true
	default:
		o.dropped.Add(1)
		return false
	}
}

// Run starts the workers and blocks until ctx is cancelled.
//
// The context here is the process lifetime, never a request context. A request
// context is cancelled the moment its response is written, which is before the
// observation starts; deriving from it would cancel every observation
// immediately and record a run of timeouts that mean nothing.
func (o *Observer) Run(ctx context.Context) {
	if !o.started.CompareAndSwap(false, true) {
		return
	}
	defer close(o.done)

	var wg sync.WaitGroup
	for i := 0; i < o.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o.work(ctx)
		}()
	}
	wg.Wait()
}

// Wait blocks until Run has returned.
func (o *Observer) Wait() { <-o.done }

func (o *Observer) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-o.queue:
			o.validate(ctx, req)
		}
	}
}

// validate runs one observation and records it.
func (o *Observer) validate(ctx context.Context, req Request) {
	// A deadline per observation, derived from the process context so that
	// shutdown cancels a walk in flight rather than waiting for it.
	vctx, cancel := context.WithTimeout(ctx, o.opts.Timeout)
	defer cancel()

	start := time.Now()
	res, panicked := o.runValidator(vctx, req)
	elapsed := time.Since(start)

	var (
		status Status
		reason string
		text   string
	)
	switch {
	case panicked:
		status, reason = StatusInternalError, "validator_panic"
		text = "the validator aborted; this is a defect, not a property of the zone"
	default:
		status, reason = classify(res)
		text = res.Reason.Explain()
	}

	obs := Observation{
		ID:             req.ID,
		Time:           time.Now().UTC(),
		Domain:         req.Domain,
		QType:          qtypeString(req.QType),
		Cached:         req.Cached,
		UpstreamStatus: req.UpstreamStatus,
		Status:         status,
		ReasonCode:     reason,
		Reason:         sanitiseReason(text),
		Duration:       elapsed,
	}

	o.record(obs)
	if o.sink != nil {
		o.sink.Record(obs)
	}
}

// runValidator calls the engine with a containment boundary around it.
//
// Daddybound is written not to panic and is fuzzed to establish that. This
// recover is not a substitute for that work and does not excuse it: a panic
// here is counted, logged and surfaced in Stats precisely so it is treated as
// a bug report rather than absorbed.
//
// It exists because of where this code runs. Observation happens on a
// background worker inside the DNS server process, and an unrecovered panic on
// any goroutine takes the whole process down — so the blast radius of a
// validator defect would be every client's DNS, not one observation. That is
// exactly the coupling this milestone exists to prevent, and it is worth one
// deferred function to make it impossible.
func (o *Observer) runValidator(ctx context.Context, req Request) (res dnssec.ValidationResult, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			o.panics.Add(1)
			o.opts.Log.Error("daddybound observation panicked",
				"domain", req.Domain,
				"qtype", qtypeString(req.QType),
				"panic", fmt.Sprint(r))
		}
	}()
	return o.v.Validate(ctx, req.QName, req.QType), false
}

func (o *Observer) record(obs Observation) {
	o.observed.Add(1)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.byStatus[obs.Status]++
	if class := DisagreementClass(obs.UpstreamStatus, obs.Status); class != "" {
		o.disagreements[class]++
	}
	o.lastAt = obs.Time
	o.lastStatus = obs.Status
}

// Stats returns a snapshot.
func (o *Observer) Stats() Stats {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := Stats{
		Observed:      o.observed.Load(),
		Dropped:       o.dropped.Load(),
		Panics:        o.panics.Load(),
		ByStatus:      make(map[Status]uint64, len(o.byStatus)),
		Disagreements: make(map[string]uint64, len(o.disagreements)),
		LastAt:        o.lastAt,
		LastStatus:    o.lastStatus,
	}
	for k, v := range o.byStatus {
		s.ByStatus[k] = v
	}
	for k, v := range o.disagreements {
		s.Disagreements[k] = v
	}
	return s
}

// Upstream DNSSEC statuses, as internal/store records them. Duplicated as
// constants rather than imported, because this package must not depend on the
// storage layer — see the package comment.
const (
	upstreamValidated   = "validated"
	upstreamUnvalidated = "unvalidated"
)

// Disagreement classes. A closed set, because these become metric labels and
// a label whose values come from data is a cardinality incident.
const (
	DisagreeLocalSecureUpstreamUnvalidated  = "local_secure_upstream_unvalidated"
	DisagreeLocalBogusUpstreamValidated     = "local_bogus_upstream_validated"
	DisagreeLocalInsecureUpstreamValidated  = "local_insecure_upstream_validated"
	DisagreeLocalIndeterminateUpstreamValid = "local_indeterminate_upstream_validated"
	DisagreeLocalBogusUpstreamUnvalidated   = "local_bogus_upstream_unvalidated"
)

// DisagreementClasses lists every class, so counters exist at zero.
func DisagreementClasses() []string {
	return []string{
		DisagreeLocalSecureUpstreamUnvalidated,
		DisagreeLocalBogusUpstreamValidated,
		DisagreeLocalInsecureUpstreamValidated,
		DisagreeLocalIndeterminateUpstreamValid,
		DisagreeLocalBogusUpstreamUnvalidated,
	}
}

// DisagreementClass names how a local verdict differs from what the upstream
// asserted, or "" when they are consistent or not comparable.
//
// "Consistent" needs care, because the two are not the same measurement and
// agreement is not always defined. The upstream's `unvalidated` means "no AD
// bit came back", which covers an unsigned zone and an upstream that does not
// validate equally — so local Insecure against upstream unvalidated is not a
// disagreement, it is the expected reading of an unsigned name. Only the
// combinations where one side makes a claim the other contradicts are counted.
//
// Operational statuses are never a disagreement with anything: a timeout is a
// statement about the observer, and filing it against the upstream's verdict
// would put network weather into a security metric.
func DisagreementClass(upstream string, local Status) string {
	if !local.IsSecurityState() {
		return ""
	}
	switch upstream {
	case upstreamValidated:
		switch local {
		case StatusBogus:
			return DisagreeLocalBogusUpstreamValidated
		case StatusInsecure:
			return DisagreeLocalInsecureUpstreamValidated
		case StatusIndeterminate:
			return DisagreeLocalIndeterminateUpstreamValid
		}
	case upstreamUnvalidated:
		switch local {
		case StatusSecure:
			return DisagreeLocalSecureUpstreamUnvalidated
		case StatusBogus:
			return DisagreeLocalBogusUpstreamUnvalidated
		}
	}
	return ""
}

func qtypeString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return "TYPE" + fmt.Sprint(t)
}
