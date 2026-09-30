package native

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
)

// ExchangeFunc obtains one complete DNS message through an operator-selected
// transport. The encrypted runtime injects the same authenticated exchange for
// answer data, validation material and managed-key refreshes. This package has
// no socket, bootstrap resolver, fallback transport or deployment dependency.
type ExchangeFunc func(context.Context, *dns.Msg) (*dns.Msg, error)

// Bound retained bytes as well as entry count: 64 individually valid large
// messages must not turn every concurrent client into a multi-megabyte cache.
const maxForwardMaterialBytes = 1 << 20

// ForwardConfig keeps local authentication independent of the upstream's AD
// bit. The upstream supplies records; only Daddybound's configured anchors and
// verifier decide whether those records authenticate.
type ForwardConfig struct {
	Exchange     ExchangeFunc
	Anchors      dnssec.TrustAnchors
	AnchorSource func() dnssec.TrustAnchors
	Policy       dnssec.Policy
	Clock        dnssec.Clock
	Verifier     dnssec.SignatureVerifier
	Limits       dnssec.Limits
	// MaxQueries bounds all wire queries in one operation, including aliases,
	// DNSKEY, DS and denial evidence. Material is cached only for that operation.
	MaxQueries int
}

// ForwardEngine authenticates the exact answer obtained from a recursive
// upstream. It implements ClientEngine, so Live retains the same DNSSEC wire
// behavior, concurrency limit, deadline and fail-closed adapter as recursion.
// It does not claim to have observed the upstream's delegation walk.
type ForwardEngine struct{ cfg ForwardConfig }

func NewForwardEngine(cfg ForwardConfig) (*ForwardEngine, error) {
	if cfg.Exchange == nil {
		return nil, errors.New("forward validation: an exchange is required")
	}
	if cfg.MaxQueries == 0 {
		cfg.MaxQueries = 64
	}
	if cfg.MaxQueries < 1 || cfg.MaxQueries > 256 {
		return nil, errors.New("forward validation: max queries must be between 1 and 256")
	}
	if cfg.Limits.MaxZones == 0 {
		cfg.Limits = dnssec.DefaultLimits()
	}
	if cfg.Limits.MaxAliasHops <= 0 {
		cfg.Limits.MaxAliasHops = dnssec.DefaultLimits().MaxAliasHops
	}
	return &ForwardEngine{cfg: cfg}, nil
}

func (e *ForwardEngine) Resolve(ctx context.Context, name string, rrtype uint16) (*Answer, error) {
	started := time.Now()
	s := e.session()
	res, err := s.resolve(ctx, name, rrtype)
	if err != nil {
		return nil, err
	}
	resolved := time.Now()
	msg, questions, synthetic, err := clientContent(res, name, rrtype)
	if err != nil {
		return nil, err
	}
	p := newPin(res).bind(s)
	verdict := validateContent(ctx, p, e.validationConfig(), msg, questions, synthetic)
	if s.limitHit {
		verdict.Status, verdict.Reason = dnssec.StatusIndeterminate, dnssec.ReasonResourceLimit
	}
	verdict.Name, verdict.RRType = dns.CanonicalName(name), rrtype
	lookups, pinned := p.counts()
	return &Answer{
		Msg: msg, Validation: verdict, Queries: s.queries, Lookups: lookups, Pinned: pinned,
		ResolveElapsed: resolved.Sub(started), ValidateElapsed: time.Since(resolved),
	}, nil
}

// ResolveUnchecked honors a client's CD request without changing the selected
// transport or any access/policy/rebinding checks outside this adapter.
func (e *ForwardEngine) ResolveUnchecked(ctx context.Context, name string, rrtype uint16) (*Answer, error) {
	started := time.Now()
	s := e.session()
	res, err := s.resolve(ctx, name, rrtype)
	if err != nil {
		return nil, err
	}
	msg, _, _, err := clientContent(res, name, rrtype)
	if err != nil {
		return nil, err
	}
	return &Answer{Msg: msg, Queries: s.queries, ResolveElapsed: time.Since(started)}, nil
}

func (e *ForwardEngine) Anchors() dnssec.TrustAnchors {
	if e.cfg.AnchorSource != nil {
		return e.cfg.AnchorSource()
	}
	return e.cfg.Anchors
}

func (e *ForwardEngine) validationConfig() dnssec.Config {
	return dnssec.Config{Anchors: e.Anchors(), Policy: e.cfg.Policy, Clock: e.cfg.Clock,
		Verifier: e.cfg.Verifier, Limits: e.cfg.Limits}
}

func (e *ForwardEngine) session() *forwardSession {
	return &forwardSession{exchange: e.cfg.Exchange, maxQueries: e.cfg.MaxQueries,
		maxAliases: e.cfg.Limits.MaxAliasHops, material: make(map[question]*dns.Msg)}
}

// forwardSession is bounded by a single client deadline and wire-work budget.
// An old Secure verdict is never cached across client queries, clock changes or
// trust-anchor revocations. A failed fetch cannot become retained evidence.
type forwardSession struct {
	exchange      ExchangeFunc
	maxQueries    int
	maxAliases    int
	queries       int
	limitHit      bool
	material      map[question]*dns.Msg
	materialBytes int
}

func (s *forwardSession) fetch(ctx context.Context, name string, rrtype uint16) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := question{dns.CanonicalName(name), rrtype}
	if msg, found := s.material[key]; found {
		return msg.Copy(), nil
	}
	if s.queries >= s.maxQueries {
		s.limitHit = true
		return nil, fmt.Errorf("%w: forwarded material query budget exhausted", recursive.ErrLimit)
	}
	s.queries++
	msg, err := forwardExchange(ctx, s.exchange, key.name, rrtype)
	if err != nil {
		return nil, err
	}
	bytes := msg.Len()
	if bytes > maxForwardMaterialBytes-s.materialBytes {
		s.limitHit = true
		return nil, fmt.Errorf("%w: forwarded material byte budget exhausted", recursive.ErrLimit)
	}
	s.materialBytes += bytes
	s.material[key] = msg.Copy()
	return msg, nil
}

func (s *forwardSession) resolve(ctx context.Context, name string, rrtype uint16) (*recursive.Result, error) {
	name = dns.CanonicalName(name)
	res := &recursive.Result{}
	seen := make(map[string]bool)
	var follow func(string, int) (*dns.Msg, error)
	follow = func(qname string, depth int) (*dns.Msg, error) {
		if depth > s.maxAliases || seen[qname] {
			return nil, fmt.Errorf("%w: forwarded alias loop or depth limit", recursive.ErrLimit)
		}
		seen[qname] = true
		msg, err := s.fetch(ctx, qname, rrtype)
		if err != nil {
			return nil, err
		}
		msg, target, err := recursive.PrepareAliasResponse(msg, qname, rrtype)
		if err != nil {
			return nil, err
		}
		// This is the reply actually used for this alias step. A fresh target
		// lookup replaces bundled target records before any are authenticated,
		// so one reply cannot be served while another is checked.
		res.Chain = append(res.Chain, recursive.Hop{QName: qname, QType: rrtype, Msg: msg})
		if target == "" {
			return msg, nil
		}
		next, err := follow(target, depth+1)
		if err != nil {
			return nil, err
		}
		out := next.Copy()
		out.Question = []dns.Question{{Name: qname, Qtype: rrtype, Qclass: dns.ClassINET}}
		out.Answer = append(recursive.FirstAliasRecords(msg, qname), next.Answer...)
		return out, nil
	}
	msg, err := follow(name, 0)
	if err != nil {
		return nil, err
	}
	res.Msg, res.Queries = msg, s.queries
	return res, nil
}

func (s *forwardSession) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	res, err := s.resolve(ctx, name, rrtype)
	if err != nil {
		return dnssec.Response{}, err
	}
	return dnssec.Response{Rcode: res.Msg.Rcode, Answer: res.Msg.Answer, Authority: res.Msg.Ns}, nil
}

// A forwarding response does not reveal which referrals the upstream crossed.
// A missing DS still needs an authenticated denial, never a fabricated zone cut.
func (s *forwardSession) ZoneCutsFor(context.Context, string) (map[string]bool, bool) {
	return nil, false
}

func forwardExchange(ctx context.Context, exchange ExchangeFunc, name string, rrtype uint16) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if exchange == nil {
		return nil, errors.New("forward validation: no exchange is available")
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, errors.New("forward validation: invalid DNS name")
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.CanonicalName(name), rrtype)
	q.RecursionDesired = true
	q.CheckingDisabled = true // Obtain evidence even when the upstream rejects its signatures.
	q.SetEdns0(1232, true)    // No client ID, cookies, ECS or upstream AD enters validation.
	msg, err := exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if msg == nil || msg.Truncated {
		return nil, errors.New("forward validation: no complete upstream response")
	}
	if !msg.Response || msg.Opcode != dns.OpcodeQuery || msg.Id != q.Id || len(msg.Question) != 1 {
		return nil, errors.New("forward validation: mismatched upstream response")
	}
	want, got := q.Question[0], msg.Question[0]
	if !strings.EqualFold(dns.CanonicalName(got.Name), want.Name) || got.Qtype != want.Qtype || got.Qclass != want.Qclass {
		return nil, errors.New("forward validation: upstream answered a different question")
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("%w: upstream returned %s", recursive.ErrNoReachableServer, dns.RcodeToString[msg.Rcode])
	}
	out := msg.Copy()
	out.AuthenticatedData = false
	out.Extra = nil
	return out, nil
}

// ForwardKeySource obtains rollover evidence over the exact exchange used for
// encrypted validation. Receiving keys does not trust them: the RFC 5011
// manager still requires existing trust and the normal hold-down period.
type ForwardKeySource struct{ exchange ExchangeFunc }

func NewForwardKeySource(exchange ExchangeFunc) *ForwardKeySource {
	return &ForwardKeySource{exchange: exchange}
}

func (s *ForwardKeySource) DNSKEY(ctx context.Context, zone string) ([]dns.RR, error) {
	msg, err := forwardExchange(ctx, s.exchange, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("forward validation: DNSKEY returned %s", dns.RcodeToString[msg.Rcode])
	}
	var keys []dns.RR
	for _, rr := range msg.Answer {
		if dns.CanonicalName(rr.Header().Name) != dns.CanonicalName(zone) {
			continue
		}
		typ := rr.Header().Rrtype
		if sig, ok := rr.(*dns.RRSIG); ok {
			typ = sig.TypeCovered
		}
		if typ == dns.TypeDNSKEY {
			keys = append(keys, rr)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("forward validation: no DNSKEY evidence in response")
	}
	return keys, nil
}
