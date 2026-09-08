// Package netsource reads DNS records from a real recursive resolver, so that
// Daddybound can be pointed at the live Internet.
//
// It is a test and diagnostic seam, not part of DNS Daddy's resolution path.
// Nothing in internal/resolver imports it, and validating a live name still
// produces a verdict rather than an enforcement decision — the runtime
// integration is a separate, later milestone.
//
// Two flags on every query decide whether this works at all:
//
//   - DO, so the upstream returns the RRSIG, NSEC and NSEC3 records without
//     which there is nothing to validate;
//   - CD, "checking disabled", so the upstream hands over answers its own
//     validator would have refused. Without CD a bogus zone comes back as
//     SERVFAIL with no records, and Daddybound would report Indeterminate for
//     exactly the data it most needs to see. CD is what makes an independent
//     verdict possible rather than a rubber stamp on the upstream's.
package netsource

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// Config is a Source's settings.
type Config struct {
	// Server is the recursive resolver, host:port.
	Server string
	// Timeout bounds one exchange.
	Timeout time.Duration
	// Attempts is how many times one question is asked before giving up.
	// UDP loss is ordinary on the open Internet and a lost packet is not
	// evidence about a zone.
	Attempts int
	// UDPSize is the advertised EDNS0 buffer.
	UDPSize uint16
}

func (c Config) withDefaults() Config {
	if c.Server == "" {
		c.Server = "1.1.1.1:53"
	}
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Attempts == 0 {
		c.Attempts = 3
	}
	if c.UDPSize == 0 {
		// 1232 is the DNS Flag Day 2020 recommendation: large enough for
		// most signed answers and small enough to stay under the common
		// path MTU, so truncation is answered by a TCP retry rather than by
		// fragments that get dropped.
		c.UDPSize = 1232
	}
	return c
}

// Source is a dnssec.Source backed by a recursive resolver.
//
// Answers are cached for the lifetime of the Source. That is not an
// optimisation detail: a chain walk asks for the same root and TLD DNSKEY and
// DS records for every name it validates, so a corpus of several hundred
// names would otherwise send tens of thousands of duplicate queries to a
// public resolver. The cache also makes one corpus run internally consistent
// — every name in it is validated against the same view of the root and the
// TLDs, so a key rollover part-way through cannot look like a Daddybound
// defect.
type Source struct {
	cfg Config

	mu    sync.Mutex
	cache map[question]*entry
	stats Stats
}

type question struct {
	name   string
	rrtype uint16
}

type entry struct {
	once sync.Once
	resp dnssec.Response
	err  error
}

// Stats counts what a run cost, for a report that has to be believable.
type Stats struct {
	Queries int
	Cached  int
	Errors  int
	Truncat int
}

// New returns a Source reading from cfg.Server.
func New(cfg Config) *Source {
	return &Source{cfg: cfg.withDefaults(), cache: map[question]*entry{}}
}

// Stats returns a snapshot of the counters.
func (s *Source) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Lookup answers one question, from cache where possible.
func (s *Source) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	q := question{name: dns.CanonicalName(name), rrtype: rrtype}

	s.mu.Lock()
	e, hit := s.cache[q]
	if !hit {
		e = &entry{}
		s.cache[q] = e
	} else {
		s.stats.Cached++
	}
	s.mu.Unlock()

	// sync.Once rather than holding the mutex across the network call: two
	// goroutines asking the same question wait for one exchange instead of
	// sending two, and no other question is blocked meanwhile.
	e.once.Do(func() { e.resp, e.err = s.exchange(ctx, q) })

	if e.err != nil {
		// Failures are not cached. A cached failure is a lost packet
		// promoted to a fact for the rest of the run: every later name that
		// needs this DNSKEY or DS inherits it, and a corpus report then
		// shows dozens of Indeterminates tracing back to one dropped
		// datagram. Dropping the entry lets the next caller try again, and
		// the retry loop inside exchange has already decided this was not a
		// momentary blip.
		s.mu.Lock()
		if s.cache[q] == e {
			delete(s.cache, q)
		}
		s.mu.Unlock()
	}
	return e.resp, e.err
}

func (s *Source) exchange(ctx context.Context, q question) (dnssec.Response, error) {
	m := new(dns.Msg)
	m.SetQuestion(q.name, q.rrtype)
	m.SetEdns0(s.cfg.UDPSize, true)
	// CD: the upstream must hand over what it has, including answers its own
	// validator rejects. Daddybound's whole purpose is to reach that verdict
	// itself.
	m.CheckingDisabled = true
	m.RecursionDesired = true

	var lastErr error
	for attempt := 0; attempt < s.cfg.Attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return dnssec.Response{}, err
		}
		resp, err := s.once(ctx, m, "udp")
		if err == nil && resp.Truncated {
			s.count(func(st *Stats) { st.Truncat++ })
			resp, err = s.once(ctx, m, "tcp")
		}
		if err == nil {
			s.count(func(st *Stats) { st.Queries++ })
			return dnssec.Response{
				Rcode:     resp.Rcode,
				Answer:    resp.Answer,
				Authority: resp.Ns,
			}, nil
		}
		lastErr = err
	}
	s.count(func(st *Stats) { st.Errors++ })
	return dnssec.Response{}, fmt.Errorf("netsource: %s %s: %w",
		q.name, dns.TypeToString[q.rrtype], lastErr)
}

func (s *Source) once(ctx context.Context, m *dns.Msg, network string) (*dns.Msg, error) {
	c := &dns.Client{Net: network, Timeout: s.cfg.Timeout, UDPSize: s.cfg.UDPSize}
	resp, _, err := c.ExchangeContext(ctx, m, s.cfg.Server)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("empty response")
	}
	return resp, nil
}

func (s *Source) count(f func(*Stats)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(&s.stats)
}
