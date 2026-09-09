package observe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// Exchanger sends one DNS message and returns the reply.
//
// The narrowest possible dependency on "how DNS Daddy talks to the internet",
// and deliberately so: *resolver.Upstream already satisfies it, so the wiring
// can hand this package the operator's own upstreams — the same servers,
// transports and connection pools client queries use — without this package
// importing the resolver. See ADR 0002 §4.
//
// Using the operator's upstreams rather than a hard-coded resolver is a
// security property, not a convenience. An operator who configured DNS-over-TLS
// must not silently acquire plaintext DNSSEC traffic to somewhere else because
// a validator was switched on.
type Exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
}

// SourceOptions configures the runtime record source.
type SourceOptions struct {
	// MaxEntries bounds the record cache. Zero picks a default.
	MaxEntries int
	// MaxTTL caps how long any record is held, whatever its own TTL says.
	MaxTTL time.Duration
	// UDPSize is the advertised EDNS0 buffer.
	UDPSize uint16
	// Now is the clock, for tests.
	Now func() time.Time
}

func (o SourceOptions) withDefaults() SourceOptions {
	if o.MaxEntries <= 0 {
		o.MaxEntries = 4096
	}
	if o.MaxTTL <= 0 {
		o.MaxTTL = time.Hour
	}
	if o.UDPSize == 0 {
		// DNS Flag Day 2020: large enough for most signed answers, small
		// enough to stay under the common path MTU so truncation is answered
		// by a TCP retry rather than by fragments that get dropped.
		o.UDPSize = 1232
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Source is a dnssec.Source over DNS Daddy's own upstreams.
//
// It is not the resolver's cache and shares nothing with it. Every question it
// asks carries DO and CD:
//
//   - DO, because without RRSIG, NSEC and NSEC3 records there is nothing to
//     validate;
//   - CD, because a validating upstream answers a bogus zone with SERVFAIL and
//     no records. Without CD, Daddybound would never see the data it most
//     needs to look at, and its verdict would be a restatement of the
//     upstream's rather than an independent one.
type Source struct {
	opts      SourceOptions
	upstreams []Exchanger

	mu    sync.Mutex
	cache map[question]cached

	stats SourceStats
}

type question struct {
	name   string
	rrtype uint16
}

type cached struct {
	resp    dnssec.Response
	expires time.Time
}

// SourceStats counts what observation cost upstream.
type SourceStats struct {
	Lookups int64
	Hits    int64
	Errors  int64
}

// NewSource returns a Source over the given upstreams, tried in order.
func NewSource(upstreams []Exchanger, o SourceOptions) *Source {
	return &Source{
		opts:      o.withDefaults(),
		upstreams: upstreams,
		cache:     map[question]cached{},
	}
}

// Stats returns a snapshot.
func (s *Source) Stats() SourceStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Lookup answers one question for the validator.
func (s *Source) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	if len(s.upstreams) == 0 {
		return dnssec.Response{}, errors.New("observe: no upstreams configured")
	}
	q := question{name: dns.CanonicalName(name), rrtype: rrtype}

	if resp, ok := s.get(q); ok {
		return resp, nil
	}

	resp, ttl, err := s.exchange(ctx, q)
	if err != nil {
		s.count(func(st *SourceStats) { st.Errors++ })
		return dnssec.Response{}, err
	}
	s.count(func(st *SourceStats) { st.Lookups++ })
	// Only successes are cached. A cached failure is a lost packet promoted
	// to a fact: every later name needing this DNSKEY inherits it, and an
	// operator sees a wave of Indeterminate verdicts tracing back to one
	// dropped datagram.
	s.put(q, resp, ttl)
	return resp, nil
}

func (s *Source) get(q question) (dnssec.Response, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.cache[q]
	if !ok {
		return dnssec.Response{}, false
	}
	if !s.opts.Now().Before(e.expires) {
		delete(s.cache, q)
		return dnssec.Response{}, false
	}
	s.stats.Hits++
	return e.resp, true
}

func (s *Source) put(q question, resp dnssec.Response, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	if ttl > s.opts.MaxTTL {
		ttl = s.opts.MaxTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.cache) >= s.opts.MaxEntries {
		s.evictLocked()
	}
	s.cache[q] = cached{resp: resp, expires: s.opts.Now().Add(ttl)}
}

// evictLocked makes room, expired entries first.
//
// If nothing has expired it drops a few arbitrary entries. Go randomises map
// iteration, so "arbitrary" is genuinely arbitrary rather than always the same
// key — which matters, because an attacker who could predict the victim would
// have a way to keep one zone's DNSKEY permanently out of cache and multiply
// the upstream queries every observation costs.
func (s *Source) evictLocked() {
	now := s.opts.Now()
	for k, e := range s.cache {
		if !now.Before(e.expires) {
			delete(s.cache, k)
		}
	}
	const forced = 16
	if len(s.cache) < s.opts.MaxEntries {
		return
	}
	dropped := 0
	for k := range s.cache {
		delete(s.cache, k)
		if dropped++; dropped >= forced {
			return
		}
	}
}

// exchange asks the upstreams in order, returning the first usable reply and
// the TTL its records permit.
func (s *Source) exchange(ctx context.Context, q question) (dnssec.Response, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(q.name, q.rrtype)
	// SetEdns0 with DO. The advertised size also sizes the UDP read buffer:
	// miekg/dns reads it back off this OPT record, so a signed answer larger
	// than 512 octets is received rather than failing to unpack.
	m.SetEdns0(s.opts.UDPSize, true)
	m.CheckingDisabled = true
	m.RecursionDesired = true

	var lastErr error
	for _, u := range s.upstreams {
		if err := ctx.Err(); err != nil {
			return dnssec.Response{}, 0, err
		}
		resp, err := u.Exchange(ctx, m.Copy())
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil {
			lastErr = errors.New("empty response")
			continue
		}
		// Only NOERROR and NXDOMAIN carry DNSSEC evidence. Every other rcode
		// is the upstream saying it could not answer, and handing one to the
		// validator turns an operational failure into a security verdict: an
		// empty SERVFAIL for a zone's DNSKEY is indistinguishable, to the
		// walk, from a zone that publishes no keys, and it would be reported
		// as Bogus. An upstream outage or a rate limit would then arrive in
		// the disagreement table this milestone exists to fill. Try the next
		// upstream instead; with none left the walk sees a lookup error and
		// reports Indeterminate, which is what "we could not tell" means.
		//
		// SERVFAIL is worth stating separately: these queries set CD, so a
		// validating upstream must not be failing them on validation grounds.
		// A SERVFAIL here is a broken or overloaded upstream either way.
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			lastErr = fmt.Errorf("upstream returned %s", dns.RcodeToString[resp.Rcode])
			continue
		}
		return dnssec.Response{
				Rcode:     resp.Rcode,
				Answer:    resp.Answer,
				Authority: resp.Ns,
			},
			minTTL(resp), nil
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream produced a response")
	}
	return dnssec.Response{}, 0, fmt.Errorf("observe: %s %s: %w",
		q.name, dns.TypeToString[q.rrtype], lastErr)
}

// minTTL is the smallest TTL across the records that matter for caching.
//
// The authority section counts because that is where a denial proof lives, and
// a NODATA or NXDOMAIN answer is exactly the case whose lifetime is decided by
// the SOA rather than by an answer record.
func minTTL(m *dns.Msg) time.Duration {
	min := ^uint32(0)
	seen := false
	for _, set := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range set {
			if _, isOPT := rr.(*dns.OPT); isOPT {
				continue
			}
			if t := rr.Header().Ttl; t < min {
				min, seen = t, true
			}
		}
	}
	if !seen {
		return 0
	}
	return time.Duration(min) * time.Second
}

func (s *Source) count(f func(*SourceStats)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(&s.stats)
}
