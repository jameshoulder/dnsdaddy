package apiprovider

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// ReputationMode is how much the policy engine may rely on external providers.
//
// Three values rather than a boolean, because "use live reputation" hides the
// only question that matters: may a DNS answer wait on a third party? An
// operator who ticks a box labelled "enable live reputation" has not agreed to
// that, and should not discover it during a provider outage.
type ReputationMode string

const (
	// ModeOff never consults providers from the resolution path. The default.
	ModeOff ReputationMode = "off"

	// ModeCacheOnly reads the local cache and never waits. A miss returns
	// unknown immediately and queues a lookup, so the answer is there next
	// time. Costs a map read per query and cannot fail.
	ModeCacheOnly ReputationMode = "cache_only"

	// ModeBlocking reads the cache and, on a miss, waits up to the configured
	// budget for an answer. On expiry it returns unknown — never a block —
	// and the lookup continues in the background.
	//
	// The mode to think hard about. It is the only one where a provider's
	// latency is in the DNS path, and the budget is a ceiling on that, not a
	// target.
	ModeBlocking ReputationMode = "blocking"
)

// Valid reports whether m is a mode this build understands.
func (m ReputationMode) Valid() bool {
	switch m {
	case ModeOff, ModeCacheOnly, ModeBlocking:
		return true
	}
	return false
}

// ParseReputationMode maps configuration onto a mode, defaulting to off.
//
// An unrecognised value becomes off rather than an error. Configuration
// outlives code, and a typo must not be the thing that puts a network call in
// the resolution path — nor the thing that refuses to start the resolver.
// Rank orders the modes by how much reach a third party has over resolution:
// none, then the cache, then the DNS path itself.
//
// It exists so the mode can be a ceiling rather than a switch. The
// configuration file names the highest mode a deployment will ever use, and
// nothing reachable over the network can raise it — an operator can turn
// reputation down or off from the dashboard during an incident, but putting a
// provider's latency in front of DNS answers stays a decision somebody made
// while reading dnsdaddy.yaml.
func (m ReputationMode) Rank() int {
	switch m {
	case ModeCacheOnly:
		return 1
	case ModeBlocking:
		return 2
	default:
		return 0
	}
}

func ParseReputationMode(s string) ReputationMode {
	m := ReputationMode(s)
	if m.Valid() {
		return m
	}
	return ModeOff
}

// Options configures the Engine.
type Options struct {
	// Mode is how the policy engine may use reputation.
	Mode ReputationMode
	// Budget is the hard ceiling on a blocking-mode wait.
	Budget time.Duration
	// Workers drain the lookup queue.
	Workers int
	// QueueSize bounds the queue. Full means drop and count, never block.
	QueueSize int
	// CacheEntries bounds the in-memory layer.
	CacheEntries int
	// Enrichment turns on the asynchronous enrichment pipeline.
	Enrichment bool
	// DefaultTTL is used when a provider gives no freshness hint.
	DefaultTTL time.Duration
	// Log receives structured events. Never a credential.
	Log *slog.Logger
	// Store persists verdicts and enrichment across restarts. Optional: the
	// engine works without one, it just forgets on restart.
	Store VerdictStore
}

// VerdictStore is the persistence the engine needs, as an interface so this
// package does not depend on internal/store.
//
// Small on purpose. A larger interface would mean this package's tests need a
// database, and the dependency direction — domain logic importing persistence
// — is the one that makes packages hard to move.
type VerdictStore interface {
	SaveVerdict(ctx context.Context, subject, providerID string, v Verdict, expires time.Time) error
	// FreshVerdicts returns unexpired verdicts, soonest-expiring last, at most
	// limit of them. Read once at startup to warm the memory cache — never
	// from the resolution path, which touches memory and nothing else.
	FreshVerdicts(ctx context.Context, limit int) ([]StoredVerdict, error)
	SaveEnrichment(ctx context.Context, subject, providerID string, e Enrichment, expires time.Time) error
}

// StoredVerdict is a persisted verdict with the two things the cache needs
// that a Verdict does not carry: what it was about, and who said it.
type StoredVerdict struct {
	Subject    string
	ProviderID string
	Verdict    Verdict
	ExpiresAt  time.Time
}

// Instance is one configured provider, ready to be called.
type Instance struct {
	ID           string
	Name         string
	Kind         string
	Provider     Provider
	Client       *Client
	Capabilities []Capability
	CacheTTL     time.Duration
	// PolicyScope limits the provider to named policies. Empty means all.
	PolicyScope []string
	// Err is why this provider could not be built, when it could not. A
	// provider that failed to construct is kept in the list rather than
	// dropped: the dashboard has to show the operator why their configuration
	// is not working, and a provider that vanishes silently is worse than one
	// that reports an error.
	Err error
}

// Usable reports whether the instance can actually be called.
func (i *Instance) Usable() bool { return i.Err == nil && i.Provider != nil }

// HasCapability reports whether the operator enabled a capability AND the
// adapter implements it. Both halves: an operator can tick a box the adapter
// cannot honour, and an adapter can support something the operator did not
// ask for.
func (i *Instance) HasCapability(c Capability) bool {
	if !i.Usable() {
		return false
	}
	for _, have := range i.Capabilities {
		if have == c {
			return Supports(i.Provider, c)
		}
	}
	return false
}

// AppliesTo reports whether this provider is in scope for a policy.
func (i *Instance) AppliesTo(policyID string) bool {
	if len(i.PolicyScope) == 0 {
		return true
	}
	for _, id := range i.PolicyScope {
		if id == policyID {
			return true
		}
	}
	return false
}

// task is one queued lookup.
type task struct {
	subject  Subject
	instance *Instance
	kind     Capability
	// done, when non-nil, receives the verdict. Buffered by the sender, so a
	// worker never blocks writing to a caller that has already given up.
	done chan Verdict
}

// Engine owns the provider instances, the cache, and the workers.
//
// The resolution path touches exactly two things on it: the mode (an atomic
// load) and the cache (a sharded map read). Everything else — the store, the
// HTTP clients, the instance list — is behind a lock the DNS path never takes.
type Engine struct {
	opts Options
	log  *slog.Logger

	cache *MemoryCache

	// mode is read on every query in cache_only and blocking mode, so it is
	// atomic rather than behind the instance lock.
	mode atomic.Pointer[ReputationMode]

	mu        sync.RWMutex
	instances []*Instance

	queue   chan task
	wg      sync.WaitGroup
	stopped atomic.Bool
	cancel  context.CancelFunc

	// Counters. Dropped is the one that matters operationally: a queue that
	// is dropping is a queue that is too small or a provider that is too slow,
	// and either way the operator is getting fewer answers than they think.
	enqueued  atomic.Uint64
	dropped   atomic.Uint64
	completed atomic.Uint64
	cacheHits atomic.Uint64
	cacheMiss atomic.Uint64
}

// NewEngine returns a stopped engine. Call Start to run the workers.
func NewEngine(o Options) *Engine {
	if o.Workers <= 0 {
		o.Workers = 2
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 1024
	}
	if o.CacheEntries <= 0 {
		o.CacheEntries = 4096
	}
	if o.DefaultTTL <= 0 {
		o.DefaultTTL = 6 * time.Hour
	}
	if o.Budget <= 0 {
		o.Budget = 50 * time.Millisecond
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if !o.Mode.Valid() {
		o.Mode = ModeOff
	}

	e := &Engine{
		opts:  o,
		log:   o.Log,
		cache: NewMemoryCache(o.CacheEntries),
		queue: make(chan task, o.QueueSize),
	}
	mode := o.Mode
	e.mode.Store(&mode)
	return e
}

// Start launches the workers.
func (e *Engine) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	for i := 0; i < e.opts.Workers; i++ {
		e.wg.Add(1)
		go e.worker(ctx)
	}
	e.log.Info("external intelligence engine started",
		"workers", e.opts.Workers,
		"queue_size", e.opts.QueueSize,
		"reputation_mode", string(*e.mode.Load()),
		"enrichment", e.opts.Enrichment)
}

// Stop drains and shuts down. Safe to call more than once.
func (e *Engine) Stop() {
	if e.stopped.Swap(true) {
		return
	}
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
}

// Mode returns the current reputation mode.
func (e *Engine) Mode() ReputationMode { return *e.mode.Load() }

// SetMode changes the mode at runtime.
func (e *Engine) SetMode(m ReputationMode) {
	if !m.Valid() {
		m = ModeOff
	}
	e.mode.Store(&m)
}

// SetInstances replaces the provider list.
//
// Called at startup and after any configuration change, so an edit in the
// dashboard takes effect on the next lookup rather than the next restart. The
// swap is under a write lock the DNS path never takes: it reads the cache and
// the mode, neither of which is behind this.
func (e *Engine) SetInstances(list []*Instance) {
	e.mu.Lock()
	old := e.instances
	e.instances = list
	e.mu.Unlock()

	// Cached answers from a provider that is gone, or whose credential has
	// been rotated, are answers nobody can trace to a live source.
	present := make(map[string]bool, len(list))
	for _, i := range list {
		present[i.ID] = true
	}
	for _, i := range old {
		if !present[i.ID] {
			e.cache.Forget(i.ID)
		}
	}
}

// Instances returns the current provider list.
func (e *Engine) Instances() []*Instance {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]*Instance(nil), e.instances...)
}

// Instance returns one provider by id.
func (e *Engine) Instance(id string) (*Instance, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, i := range e.instances {
		if i.ID == id {
			return i, true
		}
	}
	return nil, false
}

// InvalidateProvider drops a provider's cached answers.
func (e *Engine) InvalidateProvider(id string) { e.cache.Forget(id) }

// WarmCache loads unexpired verdicts from the persistent store into memory.
//
// Called once, at startup, after the instances are built. Without it
// intel_verdicts would be write-only: every restart would begin with a cold
// cache and re-ask every provider for answers already sitting on disk, which
// on a metered API is the operator's quota spent to learn nothing.
//
// It is not on any hot path and never becomes one. The resolution path reads
// the memory cache and nothing else, which is the property that lets
// cache_only mode promise it cannot slow a query down.
//
// Verdicts for providers that no longer exist are skipped rather than loaded:
// a provider the operator deleted must not go on influencing resolution from
// a row the cascade has not reached yet.
func (e *Engine) WarmCache(ctx context.Context) (int, error) {
	if e.opts.Store == nil {
		return 0, nil
	}
	rows, err := e.opts.Store.FreshVerdicts(ctx, e.opts.CacheEntries)
	if err != nil {
		return 0, err
	}

	known := make(map[string]bool)
	for _, inst := range e.Instances() {
		known[inst.ID] = true
	}

	now := time.Now()
	loaded := 0
	for _, row := range rows {
		if !known[row.ProviderID] || !row.ExpiresAt.After(now) {
			continue
		}
		e.cache.Put(row.Subject, CachedVerdict{
			Verdict:    row.Verdict,
			ProviderID: row.ProviderID,
			ExpiresAt:  row.ExpiresAt,
		})
		loaded++
	}
	if loaded > 0 {
		e.log.Info("warmed the external verdict cache from disk", "verdicts", loaded)
	}
	return loaded, nil
}

// Consult is what the policy engine calls. It is the whole hot-path surface.
//
// The contract, in order of how much it matters:
//
//  1. In ModeOff it returns immediately, having touched nothing. No map read,
//     no lock, no allocation. A deployment with this feature switched off pays
//     one atomic load per query and nothing else.
//  2. It never returns a blocking verdict it is not sure of. A miss, a
//     timeout, a failure and a disabled provider all produce unknown, and
//     unknown never blocks a name.
//  3. In ModeBlocking the wait is bounded by the budget and by ctx, whichever
//     is shorter. There is no path through this function that waits longer.
func (e *Engine) Consult(ctx context.Context, policyID, domain string) (Verdict, bool) {
	mode := *e.mode.Load()
	if mode == ModeOff {
		return Verdict{Disposition: DispositionUnknown}, false
	}

	subject := DomainSubject(domain)
	now := time.Now()

	// The cache first, always, in both live modes.
	e.mu.RLock()
	instances := e.instances
	e.mu.RUnlock()

	var (
		worst   Verdict
		haveHit bool
		misses  []*Instance
	)
	for _, inst := range instances {
		if !inst.HasCapability(CapReputation) || !inst.AppliesTo(policyID) {
			continue
		}
		if hit, ok := e.cache.Get(subject.Value, inst.ID, now); ok {
			e.cacheHits.Add(1)
			if !haveHit || hit.Verdict.Score > worst.Score {
				worst, haveHit = hit.Verdict, true
			}
			continue
		}
		e.cacheMiss.Add(1)
		misses = append(misses, inst)
	}

	// A cached malicious verdict is an answer. Nothing below can improve on
	// it, and waiting for a second opinion on a domain one provider has
	// already condemned is latency spent to change nothing.
	if haveHit && worst.Disposition == DispositionMalicious {
		e.warm(subject, misses)
		return worst, true
	}

	if mode == ModeCacheOnly || len(misses) == 0 {
		e.warm(subject, misses)
		if haveHit {
			return worst, true
		}
		return Verdict{Disposition: DispositionUnknown}, false
	}

	// Blocking mode, and something is not cached. Wait, but only for the
	// budget, and only for the first answer that would change the outcome.
	return e.waitForFirst(ctx, subject, misses, worst, haveHit)
}

// waitForFirst enqueues the misses and waits up to the budget.
func (e *Engine) waitForFirst(ctx context.Context, subject Subject, misses []*Instance, best Verdict, haveBest bool) (Verdict, bool) {
	// Buffered to the number of senders, so a worker that answers after the
	// budget expired writes into the buffer and moves on rather than blocking
	// forever on a channel nobody is reading. This is the leak that a naive
	// unbuffered channel produces, and it leaks a worker per timed-out query.
	done := make(chan Verdict, len(misses))

	queued := 0
	for _, inst := range misses {
		if e.enqueue(task{subject: subject, instance: inst, kind: CapReputation, done: done}) {
			queued++
		}
	}
	if queued == 0 {
		if haveBest {
			return best, true
		}
		return Verdict{Disposition: DispositionUnknown}, false
	}

	timer := time.NewTimer(e.opts.Budget)
	defer timer.Stop()

	for i := 0; i < queued; i++ {
		select {
		case v := <-done:
			// The first answer that would block is worth returning at once.
			if v.Disposition == DispositionMalicious {
				return v, true
			}
			// An unknown answer is not an answer. A failed lookup, a provider
			// with nothing on file and a timed-out call all arrive here as
			// unknown, and letting one become "best" would make Consult report
			// ok=true — which tells the policy engine a provider spoke when
			// none did. It is the difference between "no evidence" and
			// "evidence of nothing", and only one of them is true.
			if v.Disposition == DispositionUnknown {
				continue
			}
			if !haveBest || v.Score > best.Score {
				best, haveBest = v, true
			}
		case <-timer.C:
			// The budget is a ceiling, not a target. Whatever has not answered
			// keeps running in the background and warms the cache.
			if haveBest {
				return best, true
			}
			return Verdict{Disposition: DispositionUnknown}, false
		case <-ctx.Done():
			return Verdict{Disposition: DispositionUnknown}, false
		}
	}
	if haveBest {
		return best, true
	}
	return Verdict{Disposition: DispositionUnknown}, false
}

// warm queues lookups whose answers nobody is waiting for.
func (e *Engine) warm(subject Subject, misses []*Instance) {
	for _, inst := range misses {
		e.enqueue(task{subject: subject, instance: inst, kind: CapReputation})
	}
}

// Enrich queues enrichment for a subject. Never waits, and never called from
// the resolution path.
func (e *Engine) Enrich(domain string) {
	if !e.opts.Enrichment {
		return
	}
	subject := DomainSubject(domain)
	for _, inst := range e.Instances() {
		if inst.HasCapability(CapEnrichment) {
			e.enqueue(task{subject: subject, instance: inst, kind: CapEnrichment})
		}
	}
}

// enqueue offers a task to the queue, dropping it if the queue is full.
//
// The non-blocking send is the single most important line in this file. A
// blocking send here would put the queue's depth into the DNS path: with the
// workers busy on a slow provider, every query would wait for a queue slot,
// and a provider being slow would become the resolver being slow. Dropping and
// counting is the behaviour the query log already has for the same reason.
func (e *Engine) enqueue(t task) bool {
	if e.stopped.Load() {
		return false
	}
	select {
	case e.queue <- t:
		e.enqueued.Add(1)
		return true
	default:
		e.dropped.Add(1)
		return false
	}
}

func (e *Engine) worker(ctx context.Context) {
	defer e.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-e.queue:
			e.run(ctx, t)
		}
	}
}

// run performs one queued lookup.
func (e *Engine) run(ctx context.Context, t task) {
	defer e.completed.Add(1)

	switch t.kind {
	case CapReputation:
		e.runReputation(ctx, t)
	case CapEnrichment:
		e.runEnrichment(ctx, t)
	}
}

func (e *Engine) runReputation(ctx context.Context, t task) {
	rep, ok := t.instance.Provider.(ReputationProvider)
	if !ok {
		e.deliver(t, Verdict{Disposition: DispositionUnknown})
		return
	}

	v, err := rep.Reputation(ctx, t.subject)
	if err != nil {
		// An open circuit is expected operation, not an incident: it is the
		// breaker doing exactly what it is for, and logging it per query would
		// bury the failures that made it open.
		if !errors.Is(err, ErrCircuitOpen) {
			e.log.Warn("provider reputation lookup failed",
				"provider", t.instance.Name,
				"provider_id", t.instance.ID,
				"kind", t.instance.Kind,
				// The subject is a domain from this network. Logged because an
				// operator debugging a provider needs to know which lookup
				// failed, and it is already in the query log.
				"subject", t.subject.Value,
				// err is the adapter's, which is documented never to carry the
				// credential and is tested for it.
				"error", err.Error())
		}
		e.deliver(t, Verdict{Disposition: DispositionUnknown})
		return
	}

	ttl := v.TTL
	if ttl <= 0 {
		ttl = t.instance.CacheTTL
	}
	if ttl <= 0 {
		ttl = e.opts.DefaultTTL
	}
	expires := time.Now().Add(ttl)

	e.cache.Put(t.subject.Value, CachedVerdict{
		Verdict: v, ProviderID: t.instance.ID, ExpiresAt: expires,
	})
	if e.opts.Store != nil {
		if err := e.opts.Store.SaveVerdict(ctx, t.subject.Value, t.instance.ID, v, expires); err != nil {
			e.log.Warn("could not persist verdict", "provider_id", t.instance.ID, "error", err.Error())
		}
	}
	e.deliver(t, v)
}

func (e *Engine) runEnrichment(ctx context.Context, t task) {
	enr, ok := t.instance.Provider.(Enricher)
	if !ok {
		return
	}
	data, err := enr.Enrich(ctx, t.subject)
	if err != nil {
		if !errors.Is(err, ErrCircuitOpen) && !errors.Is(err, ErrNotSupported) {
			e.log.Warn("provider enrichment failed",
				"provider", t.instance.Name, "provider_id", t.instance.ID,
				"subject", t.subject.Value, "error", err.Error())
		}
		return
	}
	if e.opts.Store == nil {
		return
	}
	ttl := data.TTL
	if ttl <= 0 {
		ttl = t.instance.CacheTTL
	}
	if ttl <= 0 {
		ttl = e.opts.DefaultTTL
	}
	if err := e.opts.Store.SaveEnrichment(ctx, t.subject.Value, t.instance.ID, data, time.Now().Add(ttl)); err != nil {
		e.log.Warn("could not persist enrichment", "provider_id", t.instance.ID, "error", err.Error())
	}
}

// deliver hands a verdict to a waiting caller, if there is one.
//
// The send is non-blocking even though the channel is buffered to the number
// of senders. Belt and braces: the buffer makes it impossible to block today,
// and the default makes it impossible to block if somebody later changes how
// the channel is sized. A worker blocked on a caller that gave up is a worker
// lost for the life of the process.
func (e *Engine) deliver(t task, v Verdict) {
	if t.done == nil {
		return
	}
	select {
	case t.done <- v:
	default:
	}
}

// EngineStats is what the dashboard and metrics report.
type EngineStats struct {
	Mode        ReputationMode `json:"reputationMode"`
	Workers     int            `json:"workers"`
	QueueSize   int            `json:"queueSize"`
	QueueDepth  int            `json:"queueDepth"`
	Enqueued    uint64         `json:"enqueued"`
	Dropped     uint64         `json:"dropped"`
	Completed   uint64         `json:"completed"`
	CacheHits   uint64         `json:"cacheHits"`
	CacheMisses uint64         `json:"cacheMisses"`
	CacheSize   int            `json:"cacheSize"`
	Enrichment  bool           `json:"enrichment"`
}

// Stats snapshots the engine's counters.
func (e *Engine) Stats() EngineStats {
	return EngineStats{
		Mode:        *e.mode.Load(),
		Workers:     e.opts.Workers,
		QueueSize:   e.opts.QueueSize,
		QueueDepth:  len(e.queue),
		Enqueued:    e.enqueued.Load(),
		Dropped:     e.dropped.Load(),
		Completed:   e.completed.Load(),
		CacheHits:   e.cacheHits.Load(),
		CacheMisses: e.cacheMiss.Load(),
		CacheSize:   e.cache.Len(),
		Enrichment:  e.opts.Enrichment,
	}
}
