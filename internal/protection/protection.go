// Package protection implements bounded per-client admission and DNS rebinding
// checks. Neither control learns exceptions from traffic or consults a provider.
package protection

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
)

const SettingKey = "protection.settings.v1"

var ErrVersionConflict = errors.New("protection settings changed; reload before saving")
var ErrPersistence = errors.New("could not persist protection settings")

type RateLimitConfig struct {
	Enabled     bool    `json:"enabled" yaml:"enabled"`
	QPS         float64 `json:"qps" yaml:"qps"`
	Burst       int     `json:"burst" yaml:"burst"`
	MaxClients  int     `json:"maxClients" yaml:"max_clients"`
	IdleSeconds int     `json:"idleSeconds" yaml:"idle_seconds"`
}

type RebindingConfig struct {
	Enabled      bool     `json:"enabled" yaml:"enabled"`
	AllowDomains []string `json:"allowDomains" yaml:"allow_domains"`
	AllowCIDRs   []string `json:"allowCIDRs" yaml:"allow_cidrs"`
}

type Config struct {
	Version   uint64          `json:"version" yaml:"-"`
	RateLimit RateLimitConfig `json:"rateLimit" yaml:"rate_limit"`
	Rebinding RebindingConfig `json:"rebinding" yaml:"rebinding"`
}

func Default() Config {
	return Config{Version: 1,
		RateLimit: RateLimitConfig{Enabled: true, QPS: 50, Burst: 100, MaxClients: 4096, IdleSeconds: 300},
		Rebinding: RebindingConfig{Enabled: true, AllowDomains: []string{}, AllowCIDRs: []string{}},
	}
}

type snapshot struct {
	cfg     Config
	limiter *limiter
	cidrs   []netip.Prefix
}

// Controller publishes immutable settings and records only bounded counters.
// The persistence callback runs before a new revision becomes effective.
type Controller struct {
	mu       sync.Mutex
	current  atomic.Pointer[snapshot]
	persist  func(context.Context, Config) error
	limited  atomic.Uint64
	overflow atomic.Uint64
	rebound  atomic.Uint64
}

type Counters struct {
	RateLimited      uint64 `json:"rateLimited"`
	RateOverflow     uint64 `json:"rateOverflow"`
	TrackedClients   int    `json:"trackedClients"`
	RebindingBlocked uint64 `json:"rebindingBlocked"`
}

func New(cfg Config, persist func(context.Context, Config) error) (*Controller, error) {
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	s, err := compile(cfg)
	if err != nil {
		return nil, err
	}
	c := &Controller{persist: persist}
	c.current.Store(s)
	return c, nil
}

func copyConfig(c Config) Config {
	c.Rebinding.AllowDomains = append([]string{}, c.Rebinding.AllowDomains...)
	c.Rebinding.AllowCIDRs = append([]string{}, c.Rebinding.AllowCIDRs...)
	return c
}

func (c *Controller) Config() Config { return copyConfig(c.current.Load().cfg) }

func (c *Controller) Update(ctx context.Context, next Config) (Config, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	before := c.current.Load()
	if next.Version != before.cfg.Version {
		return Config{}, ErrVersionConflict
	}
	if next.Version == math.MaxUint64 {
		return Config{}, errors.New("settings version exhausted")
	}
	next.Version++
	s, err := compile(next)
	if err != nil {
		return Config{}, err
	}
	if c.persist != nil {
		if err := c.persist(ctx, copyConfig(s.cfg)); err != nil {
			return Config{}, fmt.Errorf("%w: %w", ErrPersistence, err)
		}
	}
	// A rebinding-only edit cannot refill every client's rate-limit bucket.
	if before.cfg.RateLimit == s.cfg.RateLimit {
		s.limiter = before.limiter
	}
	c.current.Store(s)
	return copyConfig(s.cfg), nil
}

func compile(cfg Config) (*snapshot, error) {
	r := cfg.RateLimit
	if math.IsNaN(r.QPS) || math.IsInf(r.QPS, 0) || r.QPS < 1 || r.QPS > 100000 {
		return nil, errors.New("rateLimit.qps must be between 1 and 100000")
	}
	if r.Burst < 1 || r.Burst > 1000000 {
		return nil, errors.New("rateLimit.burst must be between 1 and 1000000")
	}
	if r.MaxClients < 1 || r.MaxClients > 65536 {
		return nil, errors.New("rateLimit.maxClients must be between 1 and 65536")
	}
	if r.IdleSeconds < 5 || r.IdleSeconds > 3600 {
		return nil, errors.New("rateLimit.idleSeconds must be between 5 and 3600")
	}
	if len(cfg.Rebinding.AllowDomains) > 256 || len(cfg.Rebinding.AllowCIDRs) > 256 {
		return nil, errors.New("at most 256 domain and 256 CIDR rebinding exceptions are allowed")
	}
	cfg = copyConfig(cfg)
	for i, raw := range cfg.Rebinding.AllowDomains {
		if len(raw) > 253 {
			return nil, errors.New("rebinding exception domain is too long")
		}
		name := domainutil.Normalize(strings.TrimSpace(raw))
		if name == "" || strings.ContainsAny(raw, "/*:@") {
			return nil, fmt.Errorf("invalid rebinding exception domain %q", raw)
		}
		if _, err := netip.ParseAddr(name); err == nil {
			return nil, errors.New("use allowCIDRs for address exceptions")
		}
		if suffix, icann := publicsuffix.PublicSuffix(name); icann && suffix == name {
			return nil, fmt.Errorf("a public suffix such as %q is too broad; use a domain you control", name)
		}
		cfg.Rebinding.AllowDomains[i] = name
	}
	s := &snapshot{cfg: cfg, limiter: newLimiter(r)}
	for i, raw := range cfg.Rebinding.AllowCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || p.Bits() == 0 {
			return nil, fmt.Errorf("invalid or unrestricted rebinding exception CIDR %q", raw)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return nil, fmt.Errorf("invalid IPv4-mapped exception CIDR %q", raw)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			if p.Bits() == 0 {
				return nil, errors.New("unrestricted IPv4 exception is not allowed")
			}
		}
		p = p.Masked()
		s.cidrs = append(s.cidrs, p)
		s.cfg.Rebinding.AllowCIDRs[i] = p.String()
	}
	return s, nil
}

// Allow uses the verified client address plus the attributed network ID, never
// a token or a raw forwarding header. Overflow clients share a bounded bucket;
// active entries are never evicted to give a spraying client a fresh burst.
func (c *Controller) Allow(client netip.Addr, network string, now time.Time) bool {
	if c == nil {
		return true
	}
	s := c.current.Load()
	if !s.cfg.RateLimit.Enabled {
		return true
	}
	client = client.Unmap().WithZone("")
	if len(network) > 128 {
		network = "oversized-network-id"
	}
	ok, overflow := s.limiter.allow(clientKey{client, network}, now)
	if overflow {
		c.overflow.Add(1)
	}
	if !ok {
		c.limited.Add(1)
	}
	return ok
}

func (c *Controller) Counters() Counters {
	if c == nil {
		return Counters{}
	}
	l := c.current.Load().limiter
	l.mu.Lock()
	n := len(l.clients)
	l.mu.Unlock()
	return Counters{RateLimited: c.limited.Load(), RateOverflow: c.overflow.Load(), TrackedClients: n, RebindingBlocked: c.rebound.Load()}
}

type clientKey struct {
	addr    netip.Addr
	network string
}
type bucket struct {
	key           clientKey
	tokens        float64
	updated, seen time.Time
}
type limiter struct {
	mu       sync.Mutex
	cfg      RateLimitConfig
	clients  map[clientKey]*list.Element
	recent   *list.List
	overflow bucket
}

func newLimiter(cfg RateLimitConfig) *limiter {
	return &limiter{cfg: cfg, clients: make(map[clientKey]*list.Element), recent: list.New(), overflow: bucket{tokens: float64(cfg.Burst)}}
}

func (l *limiter) allow(key clientKey, now time.Time) (bool, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.clients[key]; e != nil {
		l.recent.MoveToFront(e)
		return l.take(e.Value.(*bucket), now), false
	}
	// At most eight expired entries are reclaimed per new identity, bounding
	// cleanup work independently of client count. Only idle entries expire.
	for i := 0; i < 8; i++ {
		e := l.recent.Back()
		if e == nil {
			break
		}
		b := e.Value.(*bucket)
		if now.Sub(b.seen) < time.Duration(l.cfg.IdleSeconds)*time.Second {
			break
		}
		delete(l.clients, b.key)
		l.recent.Remove(e)
	}
	if len(l.clients) >= l.cfg.MaxClients {
		return l.take(&l.overflow, now), true
	}
	b := &bucket{key: key, tokens: float64(l.cfg.Burst), updated: now, seen: now}
	l.clients[key] = l.recent.PushFront(b)
	return l.take(b, now), false
}

func (l *limiter) take(b *bucket, now time.Time) bool {
	if !b.updated.IsZero() && now.After(b.updated) {
		b.tokens = math.Min(float64(l.cfg.Burst), b.tokens+now.Sub(b.updated).Seconds()*l.cfg.QPS)
	}
	// A backwards wall clock must not mint a second refill when it catches up.
	if b.updated.IsZero() || now.After(b.updated) {
		b.updated = now
	}
	if b.seen.IsZero() || now.After(b.seen) {
		b.seen = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// CheckResponse checks every address-bearing response section after resolution,
// including aliases' records and SVCB/HTTPS address hints. The exception is
// matched against the ORIGINAL question, so an attacker-controlled CNAME cannot
// obtain an exception by pointing at a trusted internal suffix.
func (c *Controller) CheckResponse(qname string, msg *dns.Msg) string {
	if c == nil || msg == nil {
		return ""
	}
	s := c.current.Load()
	if !s.cfg.Rebinding.Enabled {
		return ""
	}
	name := domainutil.Normalize(qname)
	for _, allowed := range s.cfg.Rebinding.AllowDomains {
		if name == allowed || strings.HasSuffix(name, "."+allowed) {
			return ""
		}
	}
	check := func(raw []byte) string {
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			return "invalid address in DNS answer"
		}
		addr = addr.Unmap().WithZone("")
		for _, p := range s.cidrs {
			if p.Contains(addr) {
				return ""
			}
		}
		if protectedAddress(addr) {
			return "DNS rebinding protection rejected a non-public address: " + addr.String()
		}
		return ""
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			var reason string
			switch r := rr.(type) {
			case *dns.A:
				reason = check(r.A)
			case *dns.AAAA:
				reason = check(r.AAAA)
			case *dns.SVCB:
				reason = checkHints(r.Value, check)
			case *dns.HTTPS:
				reason = checkHints(r.Value, check)
			}
			if reason != "" {
				c.rebound.Add(1)
				return reason
			}
		}
	}
	return ""
}

func checkHints(values []dns.SVCBKeyValue, check func([]byte) string) string {
	for _, v := range values {
		switch h := v.(type) {
		case *dns.SVCBIPv4Hint:
			for _, ip := range h.Hint {
				if reason := check(ip); reason != "" {
					return reason
				}
			}
		case *dns.SVCBIPv6Hint:
			for _, ip := range h.Hint {
				if reason := check(ip); reason != "" {
					return reason
				}
			}
		}
	}
	return ""
}

// Static IANA special-purpose classifications, reviewed 2026-09-29. This is
// address classification, not a routing table or an online registry lookup.
// Explicitly global protocol allocations take precedence over broad parents.
var publicProtocol = []netip.Prefix{
	netip.MustParsePrefix("192.0.0.9/32"), netip.MustParsePrefix("192.0.0.10/32"),
	netip.MustParsePrefix("2001:1::1/128"), netip.MustParsePrefix("2001:1::2/128"), netip.MustParsePrefix("2001:1::3/128"),
	netip.MustParsePrefix("2001:3::/32"), netip.MustParsePrefix("2001:4:112::/48"),
	netip.MustParsePrefix("2001:20::/28"), netip.MustParsePrefix("2001:30::/28"),
}

var nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
var sixToFour = netip.MustParsePrefix("2002::/16")

var special = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

func protectedAddress(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range publicProtocol {
		if p.Contains(a) {
			return false
		}
	}
	for _, p := range special {
		if p.Contains(a) {
			return true
		}
	}
	if a.Is6() {
		b := a.As16()
		// RFC 6052 well-known NAT64 and RFC 3056 6to4 must not hide a
		// private IPv4 destination behind a superficially global IPv6 value.
		if nat64WellKnown.Contains(a) {
			return protectedAddress(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
		}
		if sixToFour.Contains(a) {
			return protectedAddress(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
		}
	}
	return false
}
