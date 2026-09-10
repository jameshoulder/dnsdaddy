package recursive

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// The cache is deliberately three separate maps rather than one.
//
// Answers, delegations and nameserver addresses have different lifetimes,
// different sizes and — the reason that matters — different trust. An answer
// is what a server said about a name it is authoritative for. A delegation is
// what a parent said about where to ask next. Glue is a hint. Keeping them
// apart means a poisoned entry of one kind cannot be read back as another, and
// means the delegation map can be walked to find the deepest known zone cut
// without scanning every cached answer.
//
// Everything here is bounded. A cache that grows with traffic is a way to run
// a small box out of memory from the network, so each map has a hard entry
// limit and evicts when it is reached.

// CacheOptions configures a Cache.
type CacheOptions struct {
	// MaxAnswers, MaxDelegations and MaxAddrs bound each map.
	MaxAnswers     int
	MaxDelegations int
	MaxAddrs       int
	// MinTTL and MaxTTL clamp what a server can make us remember. A zero TTL
	// means "do not cache", and is honoured; a very large one is capped,
	// because a hostile authoritative server should not be able to pin an
	// entry in memory for a week.
	MinTTL time.Duration
	MaxTTL time.Duration
	Now    func() time.Time
}

func (o CacheOptions) withDefaults() CacheOptions {
	if o.MaxAnswers <= 0 {
		o.MaxAnswers = 4096
	}
	if o.MaxDelegations <= 0 {
		o.MaxDelegations = 2048
	}
	if o.MaxAddrs <= 0 {
		o.MaxAddrs = 2048
	}
	if o.MaxTTL <= 0 {
		o.MaxTTL = time.Hour
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// CacheStats are observable counters.
type CacheStats struct {
	Hits      uint64
	Misses    uint64
	Evictions uint64
	Expired   uint64
	Answers   int
	Dels      int
	Addrs     int
}

type answerEntry struct {
	msg     *dns.Msg
	expires time.Time
}

type delegationEntry struct {
	ns      []string
	glue    map[string][]netip.Addr
	expires time.Time
}

type addrEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

// Cache is a bounded, TTL-respecting recursive cache.
type Cache struct {
	opt CacheOptions

	mu      sync.Mutex
	answers map[string]answerEntry
	dels    map[string]delegationEntry
	addrs   map[string]addrEntry
	stats   CacheStats
}

// NewCache builds a Cache.
func NewCache(opt CacheOptions) *Cache {
	opt = opt.withDefaults()
	return &Cache{
		opt:     opt,
		answers: make(map[string]answerEntry),
		dels:    make(map[string]delegationEntry),
		addrs:   make(map[string]addrEntry),
	}
}

func answerKey(name string, rrtype uint16) string {
	return dns.CanonicalName(name) + "\x00" + dns.TypeToString[rrtype]
}

// GetMsg returns a cached answer whose TTL has not expired.
//
// The returned message is a copy with its TTLs decremented by the time it has
// been held, which is what makes a downstream cache behave. Handing out the
// stored message would let a caller mutate every future hit.
func (c *Cache) GetMsg(name string, rrtype uint16) (*dns.Msg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := answerKey(name, rrtype)
	e, ok := c.answers[key]
	if !ok {
		c.stats.Misses++
		return nil, false
	}
	now := c.opt.Now()
	if !now.Before(e.expires) {
		delete(c.answers, key)
		c.stats.Expired++
		c.stats.Misses++
		return nil, false
	}
	c.stats.Hits++
	out := e.msg.Copy()
	age := uint32(now.Sub(e.expires.Add(-c.ttlOf(e.msg))).Seconds())
	decrementTTL(out, age)
	return out, true
}

func (c *Cache) ttlOf(msg *dns.Msg) time.Duration {
	return time.Duration(msgTTL(msg)) * time.Second
}

// PutMsg caches an answer.
//
// Errors are never cached, and neither is anything with a zero TTL. A cached
// failure turns one bad moment into a persistent outage, and DNS already has a
// mechanism for "ask again later": the TTL.
func (c *Cache) PutMsg(name string, rrtype uint16, msg *dns.Msg) {
	if msg == nil {
		return
	}
	switch msg.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return
	}
	ttl := c.clamp(msgTTL(msg))
	if ttl <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictIfNeededLocked(len(c.answers), c.opt.MaxAnswers, func(k string) { delete(c.answers, k) }, c.answers)
	c.answers[answerKey(name, rrtype)] = answerEntry{
		msg:     msg.Copy(),
		expires: c.opt.Now().Add(ttl),
	}
}

// PutDelegation records a zone cut and the glue that came with it.
func (c *Cache) PutDelegation(zone string, ns []string, glue map[string][]netip.Addr) {
	if len(ns) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictIfNeededLocked(len(c.dels), c.opt.MaxDelegations, func(k string) { delete(c.dels, k) }, c.dels)
	c.dels[dns.CanonicalName(zone)] = delegationEntry{
		ns:      append([]string(nil), ns...),
		glue:    glue,
		expires: c.opt.Now().Add(c.clamp(600)),
	}
}

// BestDelegation returns the deepest cached zone cut at or above name, with
// usable addresses.
//
// Walking up label by label rather than scanning the map: the map is bounded
// but a name has at most 127 labels, so this is bounded by the name and not by
// how much has been cached.
func (c *Cache) BestDelegation(name string) (string, []netip.AddrPort, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.opt.Now()
	n := dns.CanonicalName(name)
	for {
		if e, ok := c.dels[n]; ok {
			if now.Before(e.expires) {
				var out []netip.AddrPort
				for _, ns := range e.ns {
					for _, a := range e.glue[ns] {
						out = append(out, netip.AddrPortFrom(a, 53))
					}
				}
				if len(out) > 0 {
					return n, out, true
				}
			} else {
				delete(c.dels, n)
				c.stats.Expired++
			}
		}
		if n == "." {
			return "", nil, false
		}
		i := strings.IndexByte(n, '.')
		if i < 0 || i+1 >= len(n) {
			return "", nil, false
		}
		n = n[i+1:]
	}
}

// KnownCuts returns the names at or above name that the cache holds a live
// delegation for, deepest first.
//
// This is what the cache knows about the shape of the tree, as distinct from
// what any one resolution happened to walk. The difference is the whole point.
// A resolution that starts from a cached delegation crosses no zone cuts and
// therefore observes none — and reading that silence as "there are no zone
// cuts here" is how a validator ends up authenticating a child zone's records
// against its parent's keys. See Source.ZoneCutsFor.
func (c *Cache) KnownCuts(name string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.opt.Now()
	var out []string
	for n := dns.CanonicalName(name); ; {
		if e, ok := c.dels[n]; ok {
			if now.Before(e.expires) {
				out = append(out, n)
			} else {
				delete(c.dels, n)
				c.stats.Expired++
			}
		}
		if n == "." {
			return out
		}
		i := strings.IndexByte(n, '.')
		if i < 0 || i+1 >= len(n) {
			return out
		}
		n = n[i+1:]
	}
}

// GetAddrs returns cached addresses for a nameserver name.
func (c *Cache) GetAddrs(name string) ([]netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := dns.CanonicalName(name)
	e, ok := c.addrs[n]
	if !ok {
		return nil, false
	}
	if !c.opt.Now().Before(e.expires) {
		delete(c.addrs, n)
		c.stats.Expired++
		return nil, false
	}
	return append([]netip.Addr(nil), e.addrs...), true
}

// PutAddrs caches nameserver addresses.
func (c *Cache) PutAddrs(name string, addrs []netip.Addr, ttl uint32) {
	if len(addrs) == 0 {
		return
	}
	d := c.clamp(ttl)
	if d <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictIfNeededLocked(len(c.addrs), c.opt.MaxAddrs, func(k string) { delete(c.addrs, k) }, c.addrs)
	c.addrs[dns.CanonicalName(name)] = addrEntry{
		addrs:   append([]netip.Addr(nil), addrs...),
		expires: c.opt.Now().Add(d),
	}
}

// evictIfNeededLocked keeps a map under its bound.
//
// Random eviction, which is not laziness: LRU needs an access-ordered
// structure whose bookkeeping an attacker can also drive, and the property
// that matters here is only that the map cannot grow without limit. Randomly
// chosen victims also deny an attacker control over *which* entry leaves,
// which a predictable policy would hand them.
func (c *Cache) evictIfNeededLocked(size, max int, del func(string), m any) {
	if size < max {
		return
	}
	drop := size - max + 1
	switch mm := m.(type) {
	case map[string]answerEntry:
		for k := range mm {
			del(k)
			c.stats.Evictions++
			if drop--; drop <= 0 {
				return
			}
		}
	case map[string]delegationEntry:
		for k := range mm {
			del(k)
			c.stats.Evictions++
			if drop--; drop <= 0 {
				return
			}
		}
	case map[string]addrEntry:
		for k := range mm {
			del(k)
			c.stats.Evictions++
			if drop--; drop <= 0 {
				return
			}
		}
	}
}

func (c *Cache) clamp(ttl uint32) time.Duration {
	d := time.Duration(ttl) * time.Second
	if d <= 0 {
		return 0
	}
	if d < c.opt.MinTTL {
		d = c.opt.MinTTL
	}
	if d > c.opt.MaxTTL {
		d = c.opt.MaxTTL
	}
	return d
}

// Flush empties the cache, for diagnostics and for the admin control.
func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.answers = make(map[string]answerEntry)
	c.dels = make(map[string]delegationEntry)
	c.addrs = make(map[string]addrEntry)
}

// Stats returns a snapshot.
func (c *Cache) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Answers, s.Dels, s.Addrs = len(c.answers), len(c.dels), len(c.addrs)
	return s
}

// msgTTL is the smallest TTL across the records that decide how long a message
// may be believed.
//
// The authority section counts because a negative answer's lifetime is set by
// the SOA there rather than by an answer record that does not exist.
func msgTTL(msg *dns.Msg) uint32 {
	min := ^uint32(0)
	seen := false
	for _, set := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range set {
			if _, isOPT := rr.(*dns.OPT); isOPT {
				continue
			}
			if soa, ok := rr.(*dns.SOA); ok {
				// RFC 2308: a negative answer lives for the lesser of the
				// SOA TTL and its MINIMUM field.
				if soa.Minttl < min {
					min = soa.Minttl
				}
			}
			if rr.Header().Ttl < min {
				min = rr.Header().Ttl
			}
			seen = true
		}
	}
	if !seen {
		return 0
	}
	return min
}

func decrementTTL(msg *dns.Msg, by uint32) {
	for _, set := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range set {
			h := rr.Header()
			if h.Ttl > by {
				h.Ttl -= by
			} else {
				h.Ttl = 1
			}
		}
	}
}

// strings_IndexByte finds the first label separator.
func strings_IndexByte(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}
