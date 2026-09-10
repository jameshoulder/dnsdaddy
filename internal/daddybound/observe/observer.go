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

// Resolver is a Daddybound that fetches the records it validates.
//
// The capability Learn mode exists to exercise. A Validator reads records from
// wherever its source gets them, which in the forwarding arrangement means the
// operator's upstream resolvers — so a Secure verdict says the signatures on
// the records Cloudflare or Quad9 chose to hand over check out. A Resolver
// walks from the root to the authoritative servers and validates what it
// fetched itself, which is a different and much stronger sentence, and is the
// code path Live mode runs.
//
// Learn drives this one where it is available, because evidence collected
// through a forwarder would be evidence about a code path nobody is proposing
// to switch on. Which one produced a row is recorded on the row: see
// Observation.Resolution.
//
// A resolution failure comes back in Outcome.Failure and is never a verdict.
// "I could not reach the servers for this zone" and "this zone's data does not
// authenticate" are statements about different things, and folding the first
// into the second would let anyone manufacture a security state by dropping
// packets.
type Resolver interface {
	ResolveAndValidate(ctx context.Context, qname string, rrtype uint16) Outcome
}

// Outcome is one native resolve-and-validate, and what it cost.
//
// A failure is reported here rather than as an error because it is a result:
// "the authoritative servers for this zone could not be reached" is one of the
// things Learn mode exists to measure, and a deployment that cannot reach them
// is a deployment for which Live mode would answer nothing at all. Losing that
// down an error return would leave the readiness evidence quietly incomplete.
type Outcome struct {
	// Result is what Daddybound concluded about the records it fetched.
	// Meaningless when Failure is set.
	Result dnssec.ValidationResult
	// Queries is how many questions went to authoritative servers.
	Queries int
	// Delegations is how many zone cuts were crossed.
	Delegations int
	// Lookups is how many record lookups validation asked for.
	Lookups int

	// Failure, when set, says the resolution did not complete and what kind
	// of failure it was. Always operational — StatusTimeout,
	// StatusResourceLimit, StatusUnreachable — and never one of RFC 4033's
	// four.
	//
	// Classifying it is the implementation's job rather than this package's,
	// because the sentinels belong to the resolver and this package does not
	// import it. See the package comment. What this package does enforce is
	// that whatever comes back is not read as a verdict: see validate.
	Failure Status
	// FailureReason is a sentence for a person, and a typed code for a
	// metric.
	FailureReason string
	FailureCode   string
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

	// Store reports whether a per-query row may be written for this
	// observation.
	//
	// False when the operator's query-log settings say this query is not to
	// be recorded — either the instance-wide switch or the policy's own. An
	// observation row carries the queried domain, so writing one for a query
	// the operator asked not to log would defeat that setting through a
	// feature they turned on for a different reason.
	//
	// The verdict is still counted either way: the counters and metrics are
	// aggregate and name nothing, so the evidence this milestone exists to
	// collect survives a privacy setting that the per-query rows must not.
	Store bool
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
		// Long enough for a cold native resolution, which is root, then TLD,
		// then the authoritative servers, with a DNSKEY and a DS at each
		// level: several round trips in series rather than one to a forwarder
		// that already has the answer.
		o.Timeout = 5 * time.Second
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

	// Resolution is how this observer obtains records: ResolutionNative or
	// ResolutionForwarded. On the summary rather than only on the rows,
	// because the first question to ask of any of these numbers is which
	// code path produced them.
	Resolution string
	// Queries is how many questions native resolution has sent to
	// authoritative servers across every observation, and Delegations how
	// many zone cuts it has crossed. Both zero when forwarding.
	//
	// The cost of Learn, stated plainly. Learn sends real DNS traffic that
	// the deployment would not otherwise send, and an operator deciding
	// whether to leave it on is entitled to see how much.
	Queries     uint64
	Delegations uint64
}

// Observer validates real queries off the answer path.
type Observer struct {
	v    Validator
	r    Resolver
	sink Sink
	opts Options

	queue chan Request

	// started guards Run, which must be called exactly once.
	started atomic.Bool
	done    chan struct{}

	observed atomic.Uint64
	dropped  atomic.Uint64
	panics   atomic.Uint64
	queries  atomic.Uint64
	delegs   atomic.Uint64

	mu            sync.Mutex
	byStatus      map[Status]uint64
	disagreements map[string]uint64
	lastAt        time.Time
	lastStatus    Status
}

// New builds an Observer over a validator that reads records from wherever its
// source supplies them. It does no work until Run is called.
//
// NewNative is the arrangement Learn mode actually ships; this one remains for
// the forwarding path and for tests that need a validator whose behaviour they
// choose.
func New(v Validator, sink Sink, o Options) *Observer {
	return newObserver(v, nil, sink, o)
}

// NewNative builds an Observer over a Daddybound that fetches what it
// validates.
//
// The difference is the whole of Learn mode. Through New, a Secure verdict says
// the signatures on records the operator's upstream chose to hand over check
// out. Through NewNative, it says Daddybound walked from the root to the
// authoritative servers and authenticated what it read there — which is the
// code path Live mode runs, and therefore the only path whose evidence is
// evidence about Live.
func NewNative(r Resolver, sink Sink, o Options) *Observer {
	return newObserver(nil, r, sink, o)
}

func newObserver(v Validator, r Resolver, sink Sink, o Options) *Observer {
	o = o.withDefaults()
	return &Observer{
		v:             v,
		r:             r,
		sink:          sink,
		opts:          o,
		queue:         make(chan Request, o.Queue),
		done:          make(chan struct{}),
		byStatus:      map[Status]uint64{},
		disagreements: map[string]uint64{},
	}
}

// Resolution reports how this observer obtains the records it validates.
func (o *Observer) Resolution() string {
	if o.r != nil {
		return ResolutionNative
	}
	return ResolutionForwarded
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
	out, panicked := o.runEngine(vctx, req)
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
	case out.Failure != "":
		// A failure to obtain the records is never a verdict about them. The
		// implementation has already said which operational kind it was; this
		// only refuses to promote whatever is in out.Result, which for a
		// failed resolution describes nothing.
		//
		// The guard is here rather than trusted to the caller because it is
		// the one mistake that would be invisible: a Bogus manufactured by an
		// unreachable server looks exactly like a Bogus earned by a forged
		// signature, and an attacker who can drop packets could condemn any
		// zone in the operator's report.
		status, reason = out.Failure, out.FailureCode
		if status.IsSecurityState() {
			status, reason = StatusInternalError, "failure_misclassified"
		}
		text = out.FailureReason
	default:
		status, reason = classify(out.Result)
		text = out.Result.Reason.Explain()
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
		Lookups:        out.Lookups,
		Resolution:     o.Resolution(),
		Queries:        out.Queries,
		Delegations:    out.Delegations,
	}

	// Counted always; stored only when the operator's query-log settings
	// permit a row naming this domain. See Request.Store.
	o.record(obs)
	if o.sink != nil && req.Store {
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
func (o *Observer) runEngine(ctx context.Context, req Request) (out Outcome, panicked bool) {
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
	if o.r != nil {
		return o.r.ResolveAndValidate(ctx, req.QName, req.QType), false
	}
	return Outcome{Result: o.v.Validate(ctx, req.QName, req.QType)}, false
}

func (o *Observer) record(obs Observation) {
	o.observed.Add(1)
	if obs.Queries > 0 {
		o.queries.Add(uint64(obs.Queries))
	}
	if obs.Delegations > 0 {
		o.delegs.Add(uint64(obs.Delegations))
	}
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
		Resolution:    o.Resolution(),
		Queries:       o.queries.Load(),
		Delegations:   o.delegs.Load(),
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
