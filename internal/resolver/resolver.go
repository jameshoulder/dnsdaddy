// Package resolver forwards DNS questions to upstream resolvers, with an
// answer cache and in-flight request de-duplication in front.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

// Resolver forwards questions upstream.
type Resolver struct {
	upstreams []*Upstream
	mode      string
	timeout   time.Duration
	cache     *Cache
	log       *slog.Logger

	// requestAD sets the AD bit on outgoing queries so a validating upstream
	// reports what it concluded. See forward.
	requestAD bool

	// inflight collapses identical concurrent questions into one upstream
	// query. A single machine spraying the same lookup — which is exactly what
	// a beaconing implant looks like — costs us one query, not hundreds.
	inflightMu sync.Mutex
	inflight   map[string]*call

	// sem bounds how many upstream network exchanges run at once
	// (dns.max_inflight). Cache hits and collapsed duplicates never touch it —
	// only a genuine new upstream query acquires a slot. A flood of unique
	// random-subdomain queries queues here instead of opening an unbounded
	// number of upstream connections; each waiter still respects the caller's
	// context, so it gives up at the query's own timeout rather than forever.
	sem          chan struct{}
	inflightNow  atomic.Int64
	inflightPeak atomic.Int64

	collapsed     atomicCounter
	failures      atomicCounter
	limitTimeouts atomicCounter
}

type call struct {
	done chan struct{}
	msg  *dns.Msg
	err  error
}

// New builds a Resolver from configuration.
func New(cfg config.DNS, cacheCfg config.Cache, log *slog.Logger) (*Resolver, error) {
	timeout := cfg.Timeout.D()
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	maxInflight := cfg.MaxInflight
	if maxInflight <= 0 {
		maxInflight = 2048
	}

	r := &Resolver{
		mode:      cfg.UpstreamMode,
		timeout:   timeout,
		log:       log,
		requestAD: cfg.DNSSECTelemetry,
		inflight:  map[string]*call{},
		sem:       make(chan struct{}, maxInflight),
		cache: NewCache(CacheOptions{
			Enabled:     cacheCfg.Enabled,
			MaxEntries:  cacheCfg.MaxEntries,
			MinTTL:      cacheCfg.MinTTL,
			MaxTTL:      cacheCfg.MaxTTL,
			NegativeTTL: cacheCfg.NegativeTTL,
		}),
	}

	for _, spec := range cfg.Upstreams {
		u, err := ParseUpstream(spec, timeout)
		if err != nil {
			return nil, err
		}
		r.upstreams = append(r.upstreams, u)
	}
	if len(r.upstreams) == 0 {
		return nil, errors.New("no upstream resolvers configured")
	}
	return r, nil
}

// Cache exposes the answer cache.
func (r *Resolver) Cache() *Cache { return r.cache }

// Upstreams returns the configured forwarders.
func (r *Resolver) Upstreams() []*Upstream { return r.upstreams }

// Close releases upstream connections.
func (r *Resolver) Close() {
	for _, u := range r.upstreams {
		u.Close()
	}
}

// Result carries a response and how it was obtained.
type Result struct {
	Msg    *dns.Msg
	Cached bool
	// Upstream is the spec of the forwarder that answered, empty on a cache hit.
	Upstream string
	// Rcode is the response code the upstream returned.
	Rcode int
	// Validated reports that the upstream set the AD bit, meaning it validated
	// the answer against the DNSSEC chain of trust.
	//
	// This is read from the upstream's response before the AD bit is stripped
	// for clients that did not ask for it, so the telemetry is complete even
	// though the wire response stays RFC-conformant. See reattach.
	Validated bool
	// MinTTL is the smallest TTL in the answer section, or 0 when there is no
	// answer. The beaconing detector uses it to tell a client polling on its
	// own clock from one re-resolving because its cache expired.
	MinTTL uint32
}

// Resolve answers a question, consulting the cache first. generation is the
// blocklist generation the answer is valid under.
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg, generation uint64) (Result, error) {
	if len(req.Question) == 0 {
		return Result{}, errors.New("query has no question")
	}
	q := req.Question[0]
	key := Key(q, dnssecRequested(req))

	// reattach rather than SetReply: SetReply forces RcodeSuccess, which would
	// turn a cached NXDOMAIN into a NOERROR/no-answer response.
	if cached := r.cache.Get(key, generation); cached != nil {
		return Result{
			Msg:       reattach(cached, req),
			Cached:    true,
			Rcode:     cached.Rcode,
			Validated: cached.AuthenticatedData,
			MinTTL:    minAnswerTTL(cached),
		}, nil
	}

	msg, upstream, err := r.forwardOnce(ctx, key, req, generation)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Msg:       reattach(msg, req),
		Upstream:  upstream,
		Rcode:     msg.Rcode,
		Validated: msg.AuthenticatedData,
		MinTTL:    minAnswerTTL(msg),
	}, nil
}

// forwardOnce performs the upstream query, collapsing duplicate concurrent
// questions onto a single flight.
func (r *Resolver) forwardOnce(ctx context.Context, key string, req *dns.Msg, generation uint64) (*dns.Msg, string, error) {
	r.inflightMu.Lock()
	if c, ok := r.inflight[key]; ok {
		r.inflightMu.Unlock()
		r.collapsed.inc()
		select {
		case <-c.done:
			if c.err != nil {
				return nil, "", c.err
			}
			return c.msg.Copy(), "", nil
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	c := &call{done: make(chan struct{})}
	r.inflight[key] = c
	r.inflightMu.Unlock()

	msg, upstream, err := r.forward(ctx, req)
	if err == nil && msg != nil {
		r.cache.Put(key, msg, generation)
		c.msg = msg
	}
	c.err = err
	close(c.done)

	r.inflightMu.Lock()
	delete(r.inflight, key)
	r.inflightMu.Unlock()

	if err != nil {
		r.failures.inc()
		return nil, "", err
	}
	return msg.Copy(), upstream, nil
}

func (r *Resolver) forward(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	if !r.acquireSlot(ctx) {
		return nil, "", fmt.Errorf("upstream concurrency limit reached: %w", ctx.Err())
	}
	defer r.releaseSlot()

	// Upstreams must not see our client's message ID or any client-specific
	// state; send a clean copy.
	out := req.Copy()
	out.Id = dns.Id()

	// Ask the upstream to report its DNSSEC verdict.
	//
	// RFC 6840 §5.7 defines the AD bit in a *query* as the requester saying it
	// understands and wants the AD bit in the response. Crucially this is not
	// the DO bit: it does not ask for DNSSEC records to be included, so
	// responses do not grow and nothing about the answer changes. It costs one
	// bit and turns "we forward to validating resolvers" from a claim in the
	// documentation into a per-query measurement.
	//
	// DNS Daddy still does not validate anything itself. What this records is
	// the upstream's conclusion, which is a weaker statement, and the
	// documentation and the finding text both say so.
	if r.requestAD {
		out.AuthenticatedData = true
	}

	if r.mode == "race" {
		return r.race(ctx, out)
	}
	return r.failover(ctx, out)
}

// acquireSlot blocks until an upstream concurrency slot is free or ctx is
// done, whichever comes first — so a query that cannot get a slot in time
// fails at its own timeout rather than piling up indefinitely.
func (r *Resolver) acquireSlot(ctx context.Context) bool {
	select {
	case r.sem <- struct{}{}:
		cur := r.inflightNow.Add(1)
		for {
			peak := r.inflightPeak.Load()
			if cur <= peak || r.inflightPeak.CompareAndSwap(peak, cur) {
				break
			}
		}
		return true
	case <-ctx.Done():
		r.limitTimeouts.inc()
		return false
	}
}

func (r *Resolver) releaseSlot() {
	<-r.sem
	r.inflightNow.Add(-1)
}

func (r *Resolver) failover(ctx context.Context, m *dns.Msg) (*dns.Msg, string, error) {
	var lastErr error
	for _, u := range r.upstreams {
		if ctx.Err() != nil {
			break
		}
		resp, err := u.Exchange(ctx, m)
		if err == nil && resp != nil {
			return resp, u.Spec, nil
		}
		lastErr = err
		r.log.Debug("upstream failed, trying next", "upstream", u.Spec, "error", err)
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream produced a response")
	}
	return nil, "", fmt.Errorf("all upstreams failed: %w", lastErr)
}

// race asks every upstream at once and takes the first good answer. It costs
// more upstream traffic in exchange for latency that tracks the fastest
// resolver rather than the first configured one.
func (r *Resolver) race(ctx context.Context, m *dns.Msg) (*dns.Msg, string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		msg      *dns.Msg
		upstream string
		err      error
	}
	results := make(chan outcome, len(r.upstreams))

	for _, u := range r.upstreams {
		go func(u *Upstream) {
			resp, err := u.Exchange(ctx, m.Copy())
			results <- outcome{msg: resp, upstream: u.Spec, err: err}
		}(u)
	}

	var lastErr error
	for i := 0; i < len(r.upstreams); i++ {
		select {
		case res := <-results:
			if res.err == nil && res.msg != nil {
				return res.msg, res.upstream, nil
			}
			lastErr = res.err
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream produced a response")
	}
	return nil, "", fmt.Errorf("all upstreams failed: %w", lastErr)
}

// Stats reports resolver-level counters.
func (r *Resolver) Stats() (collapsed, failures uint64) {
	return r.collapsed.get(), r.failures.get()
}

// InflightStats reports how the upstream concurrency limit (dns.max_inflight)
// is being used: how many upstream exchanges are running right now, the
// highest concurrent count observed since start, and how many requests gave
// up waiting for a free slot.
func (r *Resolver) InflightStats() (current, peak int64, limitTimeouts uint64) {
	return r.inflightNow.Load(), r.inflightPeak.Load(), r.limitTimeouts.get()
}

// reattach copies a response onto the client's question and message ID.
func reattach(msg *dns.Msg, req *dns.Msg) *dns.Msg {
	out := msg.Copy()
	out.Id = req.Id
	out.Question = req.Question
	out.Response = true
	out.RecursionDesired = req.RecursionDesired
	out.RecursionAvailable = true

	// RFC 4035 §3.2.3: do not set AD unless the client asked for it, by
	// setting DO or AD in its own query.
	//
	// Because we now set AD on every upstream query for telemetry, the
	// upstream's verdict comes back on answers no client requested it for —
	// including answers served from cache to a different client than the one
	// that populated it. Passing that through would tell a client its answer
	// was authenticated when it never asked us to check, which is precisely
	// the assurance the AD bit is not allowed to give.
	if !clientWantsAD(req) {
		out.AuthenticatedData = false
	}
	return out
}

// clientWantsAD reports whether the client signalled interest in the AD bit,
// by setting DO in EDNS0 or AD in the query header.
func clientWantsAD(req *dns.Msg) bool {
	if req == nil {
		return false
	}
	if req.AuthenticatedData {
		return true
	}
	if opt := req.IsEdns0(); opt != nil {
		return opt.Do()
	}
	return false
}

// minAnswerTTL returns the smallest TTL in the answer section, or 0 when there
// is none.
func minAnswerTTL(msg *dns.Msg) uint32 {
	if msg == nil || len(msg.Answer) == 0 {
		return 0
	}
	min := msg.Answer[0].Header().Ttl
	for _, rr := range msg.Answer[1:] {
		if t := rr.Header().Ttl; t < min {
			min = t
		}
	}
	return min
}

func dnssecRequested(m *dns.Msg) bool {
	if opt := m.IsEdns0(); opt != nil {
		return opt.Do()
	}
	return false
}
