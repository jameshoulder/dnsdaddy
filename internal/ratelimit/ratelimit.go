// Package ratelimit bounds how much of the resolver any one client may use.
//
// The threat is T18: an authorised client — a compromised host, a broken
// application in a retry loop, a load test nobody told you about — consuming
// the whole resolver, which on the 1 vCPU box this project targets is not a
// high bar. The ACL decides who may ask. This decides how often.
//
// # Why this is not a blocking control
//
// Refusing a client's queries breaks that client's network. That is an outage
// caused by a threshold, which is the same objection that keeps the
// behavioural detectors alert-only. The answer here is different from the
// detectors' answer for one reason: this threshold is a rate, not a judgement.
// A detector deciding "this looks like a DGA" can be wrong about a name. A
// limiter deciding "this source has sent 40,000 queries in the last minute"
// cannot be wrong about the count. What it can be wrong about is whether that
// count is legitimate, which is why the default is set far above what any
// legitimate client does rather than at a level that tries to be clever.
//
// The default is a backstop, not a quota. See docs/algorithms.md.
//
// # The algorithm
//
// GCRA — the generic cell rate algorithm, the leaky bucket written as a
// deadline instead of a counter. One int64 of state per client, no background
// refill, no goroutine, and an operator can reconstruct any decision it made
// on paper from three numbers.
//
// Per client, keep TAT, the theoretical arrival time: the instant at which the
// client would next be exactly at its configured rate. With emission interval
// T = 1/rate and burst tolerance tau = (burst-1) * T, a query arriving at t is
// refused when TAT - tau > t, and otherwise accepted with
// TAT = max(TAT, t) + T.
//
// A client that has been quiet has TAT in the past, so max(TAT, t) restarts it
// from now and its burst allowance is whole again. A client at full rate walks
// TAT forward exactly T per query. A client above its rate pushes TAT into the
// future until it crosses the tolerance and starts being refused. Nothing
// decays, nothing is swept on a timer, and the arithmetic is the same three
// operations on every query.
package ratelimit

import (
	"hash/maphash"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// shards bounds mutex contention on the answer path. Every query takes
	// exactly one shard lock for the duration of three integer operations, so
	// the critical section is nanoseconds; the shards exist so that two
	// clients hashing differently do not queue behind each other at all.
	shards = 64

	// DefaultRate and DefaultBurst are deliberately generous. A client doing
	// something legitimate — a browser opening a page, a phone waking up, a
	// backup kicking off — does not come close. A client doing 500 queries a
	// second sustained is a fault or an attack, and 500/s is still a rate the
	// forwarding resolver serves out of cache without noticing.
	//
	// An operator running Daddybound Native should lower this: native
	// resolution is CPU-bound on signature verification and costs three orders
	// of magnitude more per query than a forwarded cache hit.
	DefaultRate  = 500
	DefaultBurst = 1000

	// DefaultMaxClients bounds the table. 65,536 keys of 32 bytes plus map
	// overhead is single-digit megabytes, and a network large enough to hold
	// that many distinct client prefixes is not one of this project's targets.
	DefaultMaxClients = 65536

	// DefaultIPv4PrefixLength and DefaultIPv6PrefixLength decide what "one
	// client" means. See Config.
	DefaultIPv4PrefixLength = 32
	DefaultIPv6PrefixLength = 64

	// evictionSample is how many entries are examined when a shard is full.
	// Go randomises map iteration order, so ranging and stopping after k gives
	// a random sample for free. Bounded work per query is the point: a sweep
	// of the whole shard would hand an attacker a way to make every query
	// expensive simply by keeping the table full.
	evictionSample = 8
)

// Decision is what the limiter concluded about one query.
type Decision struct {
	// Allowed is whether the query may proceed.
	Allowed bool
	// Key is the client prefix the decision was made against, which is the
	// client address masked to the configured prefix length. Present so a
	// caller can explain the decision; deliberately not used as a metric
	// label, because that is one series per client.
	Key netip.Prefix
	// Rate and Burst are the limits that applied, after overrides.
	Rate, Burst float64
	// RetryAfter is how long until this client would be admitted again, and is
	// zero when Allowed. It is derived from the same TAT the refusal was, so
	// it cannot disagree with it.
	RetryAfter time.Duration
}

// Override raises or lowers the limit for one range of client addresses.
//
// Longest matching prefix wins, so a /24 override beats a /8 override. A Rate
// of zero means this range is not limited at all, which is how an operator
// exempts something — a monitoring host, a downstream resolver, the loopback
// address if they want the box's own lookups outside the limit — without a
// special case in the code for any of them.
type Override struct {
	Prefix netip.Prefix
	Rate   float64
	Burst  float64
}

// Config describes the limiter. The zero value is not usable; use Defaults.
type Config struct {
	// Rate is sustained queries per second per client, and Burst is how far
	// above it a client may go momentarily before being refused.
	Rate  float64
	Burst float64

	// IPv4PrefixLength and IPv6PrefixLength decide what counts as one client.
	//
	// 32 for IPv4 is one address, which is one host on any network this
	// project is deployed on.
	//
	// 64 for IPv6 is a subnet, not a host, and that is a real trade-off rather
	// than an oversight. A host with privacy addressing (RFC 8981) holds
	// several addresses at once and rotates them on a timer, so limiting per
	// /128 would track one misbehaving host as a stream of new clients and
	// never accumulate enough state about any of them to refuse one. Limiting
	// per /64 groups a host's own addresses together. The cost is that on a
	// typical LAN — where every host shares one /64 — the IPv6 limit is
	// effectively per-LAN, which is why the default is generous enough for a
	// LAN. An operator who wants per-host IPv6 limiting sets this to 128 and
	// accepts the rotation caveat.
	IPv4PrefixLength int
	IPv6PrefixLength int

	// MaxClients bounds the tracking table across all shards.
	MaxClients int

	// Overrides are per-range limits, longest prefix first.
	Overrides []Override

	// now is injectable for tests. Nil means time.Now.
	now func() time.Time
}

// Defaults returns a usable configuration at the shipped limits.
func Defaults() Config {
	return Config{
		Rate:             DefaultRate,
		Burst:            DefaultBurst,
		IPv4PrefixLength: DefaultIPv4PrefixLength,
		IPv6PrefixLength: DefaultIPv6PrefixLength,
		MaxClients:       DefaultMaxClients,
	}
}

// Limiter enforces a Config. A nil *Limiter allows everything, so a caller
// that has the feature switched off holds nil rather than a special case.
type Limiter struct {
	cfg   Config
	seed  maphash.Seed
	parts [shards]shard

	// perShard is MaxClients divided across shards, at least one.
	perShard int

	limited atomic.Uint64
	evicted atomic.Uint64
}

type shard struct {
	mu sync.Mutex
	// tat maps a client prefix to its theoretical arrival time in Unix
	// nanoseconds. One map entry per client, one int64 of state.
	tat map[netip.Prefix]int64
}

// New builds a Limiter. Invalid or absent numbers fall back to the defaults
// rather than producing a limiter that refuses everything: a misconfigured
// rate limit must not be an outage.
func New(cfg Config) *Limiter {
	d := Defaults()
	if cfg.Rate <= 0 || math.IsNaN(cfg.Rate) || math.IsInf(cfg.Rate, 0) {
		cfg.Rate = d.Rate
	}
	if cfg.Burst < 1 || math.IsNaN(cfg.Burst) || math.IsInf(cfg.Burst, 0) {
		cfg.Burst = d.Burst
	}
	// Zero is "not set", not "/0". A prefix length of zero masks every client
	// to the default route, which would silently turn a per-client limit into
	// one shared allowance for the entire network — the exact opposite of what
	// this package is for, arrived at by leaving a key out of a YAML file. An
	// operator who genuinely wants one shared allowance expresses it as an
	// override on 0.0.0.0/0 and ::/0, where it is visible.
	if cfg.IPv4PrefixLength <= 0 || cfg.IPv4PrefixLength > 32 {
		cfg.IPv4PrefixLength = d.IPv4PrefixLength
	}
	if cfg.IPv6PrefixLength <= 0 || cfg.IPv6PrefixLength > 128 {
		cfg.IPv6PrefixLength = d.IPv6PrefixLength
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = d.MaxClients
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	// Longest prefix first, so the first match in Limiter.limitsFor is the
	// most specific one and the search stops there.
	cfg.Overrides = sortOverrides(cfg.Overrides)

	l := &Limiter{cfg: cfg, seed: maphash.MakeSeed()}
	l.perShard = cfg.MaxClients / shards
	if l.perShard < 1 {
		l.perShard = 1
	}
	for i := range l.parts {
		l.parts[i].tat = make(map[netip.Prefix]int64)
	}
	return l
}

func sortOverrides(in []Override) []Override {
	out := make([]Override, 0, len(in))
	for _, o := range in {
		if o.Prefix.IsValid() {
			out = append(out, o)
		}
	}
	// Insertion sort: this list is a handful of entries written by hand in a
	// configuration file, and it is sorted once at construction.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Prefix.Bits() > out[j-1].Prefix.Bits(); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Allow reports whether a query from addr may proceed, and records it against
// that client's allowance if so.
//
// An invalid address is allowed. That is not a fail-open: the client ACL
// refuses an address it cannot read before this is ever reached, so the only
// way to arrive here without one is a transport where a token identified the
// client instead. Refusing those would break roaming DoH and DoT clients to no
// end, since there is no key to accumulate state against either way.
func (l *Limiter) Allow(addr netip.Addr) Decision {
	if l == nil {
		return Decision{Allowed: true}
	}
	key, ok := l.key(addr)
	if !ok {
		return Decision{Allowed: true}
	}
	rate, burst := l.limitsFor(key)
	if rate <= 0 {
		// An explicit exemption. Not tracked, so an exempt range costs no
		// table space and cannot evict anybody else's state.
		return Decision{Allowed: true, Key: key, Rate: 0, Burst: burst}
	}

	now := l.cfg.now().UnixNano()
	interval := int64(float64(time.Second) / rate)
	if interval < 1 {
		interval = 1
	}
	tolerance := int64(float64(burst-1) * float64(interval))

	s := &l.parts[l.shardFor(key)]
	s.mu.Lock()
	tat, tracked := s.tat[key]
	if tat < now {
		// Quiet, or new. Either way the allowance starts from now.
		tat = now
	}
	if tat-tolerance > now {
		// Over the limit. TAT is left exactly where it is: a refused query
		// must not push the deadline further out, or a client hammering a
		// closed door would extend its own lockout without limit and a short
		// overshoot would become an indefinite one.
		wait := time.Duration(tat - tolerance - now)
		s.mu.Unlock()
		l.limited.Add(1)
		return Decision{Allowed: false, Key: key, Rate: rate, Burst: burst, RetryAfter: wait}
	}
	next := tat + interval
	if !tracked && len(s.tat) >= l.perShard {
		l.makeRoom(s, now)
	}
	s.tat[key] = next
	s.mu.Unlock()
	return Decision{Allowed: true, Key: key, Rate: rate, Burst: burst}
}

// makeRoom frees one slot in a full shard. Called with s.mu held.
//
// It prefers entries whose TAT has passed, because those carry no information:
// a client whose deadline is in the past is treated identically to one that
// was never seen, so deleting it changes no future decision. Only when the
// sample finds none does it evict the entry closest to expiring, which is the
// one whose loss matters least.
//
// The work is bounded by evictionSample regardless of table size. A client
// rotating source addresses to flush the table therefore cannot make each
// query cost more than a constant, and every entry it creates is itself the
// most attractive eviction candidate a moment later.
func (l *Limiter) makeRoom(s *shard, now int64) {
	var (
		victim  netip.Prefix
		lowest  int64
		checked int
		found   bool
	)
	for k, v := range s.tat {
		if v <= now {
			delete(s.tat, k)
			l.evicted.Add(1)
			return
		}
		if !found || v < lowest {
			victim, lowest, found = k, v, true
		}
		if checked++; checked >= evictionSample {
			break
		}
	}
	if found {
		delete(s.tat, victim)
		l.evicted.Add(1)
	}
}

// key masks addr to the configured prefix length. The bool is false when there
// is no address to key on.
func (l *Limiter) key(addr netip.Addr) (netip.Prefix, bool) {
	if !addr.IsValid() {
		return netip.Prefix{}, false
	}
	// An IPv4-mapped IPv6 address is the same client as the IPv4 address it
	// wraps; without this a dual-stack listener would give one host two
	// separate allowances.
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	addr = addr.WithZone("")
	bits := l.cfg.IPv6PrefixLength
	if addr.Is4() {
		bits = l.cfg.IPv4PrefixLength
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// limitsFor returns the rate and burst that apply to a client, after
// overrides. Overrides are sorted longest first, so the first containing
// prefix is the most specific one.
func (l *Limiter) limitsFor(key netip.Prefix) (rate, burst float64) {
	for _, o := range l.cfg.Overrides {
		if o.Prefix.Addr().Is4() != key.Addr().Is4() {
			continue
		}
		if o.Prefix.Bits() <= key.Bits() && o.Prefix.Contains(key.Addr()) {
			b := o.Burst
			if b < 1 {
				b = o.Rate
			}
			if b < 1 {
				b = 1
			}
			return o.Rate, b
		}
	}
	return l.cfg.Rate, l.cfg.Burst
}

// shardFor picks the shard a key lives in.
//
// Only the masked address is hashed, not the prefix length. Within one limiter
// the length is fixed per address family, so it adds nothing to distinguish
// keys; and a collision would in any case only put two keys in the same shard,
// never confuse them — the map key is the whole netip.Prefix, prefix length
// included.
func (l *Limiter) shardFor(key netip.Prefix) int {
	var h maphash.Hash
	h.SetSeed(l.seed)
	a := key.Addr().As16()
	_, _ = h.Write(a[:])
	return int(h.Sum64() % shards)
}

// Limited is how many queries have been refused for exceeding a limit.
func (l *Limiter) Limited() uint64 {
	if l == nil {
		return 0
	}
	return l.limited.Load()
}

// Evicted is how many clients have been dropped from the tracking table to
// make room. A number that climbs is either a network with more distinct
// clients than MaxClients or a client rotating source addresses; both are
// worth an operator's attention and neither is visible any other way.
func (l *Limiter) Evicted() uint64 {
	if l == nil {
		return 0
	}
	return l.evicted.Load()
}

// Tracked is how many clients currently hold state.
func (l *Limiter) Tracked() int {
	if l == nil {
		return 0
	}
	n := 0
	for i := range l.parts {
		l.parts[i].mu.Lock()
		n += len(l.parts[i].tat)
		l.parts[i].mu.Unlock()
	}
	return n
}

// Capacity is the configured ceiling on tracked clients, after rounding across
// shards. Reported next to Tracked so "how close am I" is answerable without
// the operator reconstructing the rounding.
func (l *Limiter) Capacity() int {
	if l == nil {
		return 0
	}
	return l.perShard * shards
}

// Config returns the limits in force, for diagnostics.
func (l *Limiter) Config() Config {
	if l == nil {
		return Config{}
	}
	return l.cfg
}
