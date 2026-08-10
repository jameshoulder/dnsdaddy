package resolver

import (
	"hash/maphash"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Cache is a bounded, sharded, TTL-aware DNS answer cache.
//
// It is sharded to keep lock contention off the hot path and bounded by entry
// count rather than bytes, because on a 1 GB box the thing an operator needs to
// reason about is "how much RAM will this use" — 50,000 entries is roughly
// 25 MB and is the default.
//
// Entries carry the blocklist generation they were created under. When feeds
// refresh, the generation moves and every cached answer is treated as stale, so
// a newly blocked domain stops resolving immediately instead of lingering for
// up to its TTL.
type Cache struct {
	shards  [cacheShards]*shard
	maxTTL  uint32
	minTTL  uint32
	negTTL  uint32
	seed    maphash.Seed
	enabled bool

	hits   atomicCounter
	misses atomicCounter
}

const cacheShards = 16

type shard struct {
	mu      sync.Mutex
	entries map[string]*entry
	// order is an approximate LRU: eviction scans a bounded sample rather than
	// maintaining a linked list, which keeps insert cost to one map write.
	max int
}

type entry struct {
	msg        *dns.Msg
	expires    time.Time
	generation uint64
	lastUsed   time.Time
	origTTL    uint32
}

// CacheOptions configures a Cache.
type CacheOptions struct {
	Enabled     bool
	MaxEntries  int
	MinTTL      int
	MaxTTL      int
	NegativeTTL int
}

// NewCache builds a cache from options.
func NewCache(o CacheOptions) *Cache {
	max := o.MaxEntries
	if max <= 0 {
		max = 50000
	}
	// Each shard gets an equal share. The floor keeps a deliberately tiny cache
	// from degenerating into thrashing, at the cost of the effective minimum
	// size being cacheShards * minPerShard.
	const minPerShard = 4
	perShard := max / cacheShards
	if perShard < minPerShard {
		perShard = minPerShard
	}

	// minTTL is floored at zero rather than defaulted: 0 is a meaningful
	// setting ("honour whatever the upstream said"), not an unset one.
	c := &Cache{
		maxTTL:  ttlToUint32(orDefault(o.MaxTTL, 86400)),
		minTTL:  ttlToUint32(o.MinTTL),
		negTTL:  ttlToUint32(orDefault(o.NegativeTTL, 300)),
		seed:    maphash.MakeSeed(),
		enabled: o.Enabled,
	}
	for i := range c.shards {
		c.shards[i] = &shard{entries: make(map[string]*entry), max: perShard}
	}
	return c
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// maxDNSTTL is the largest TTL a DNS record may carry. RFC 2181 §8 reserves
// the top bit, so values above 2^31-1 must be treated as zero.
const maxDNSTTL = 1<<31 - 1

// ttlToUint32 clamps a configured TTL into the range a DNS record can hold.
//
// A plain uint32(n) conversion wraps: max_ttl: 4294967296 would silently
// become 0 (nothing cached) and a negative value would become enormous
// (everything cached forever). Clamping turns a typo into a bounded, obvious
// value instead of a silent inversion of the operator's intent.
// Flagged by gosec G115.
func ttlToUint32(n int) uint32 {
	if n < 0 {
		return 0
	}
	if n > maxDNSTTL {
		return maxDNSTTL
	}
	return uint32(n)
}

// Key builds the cache key for a question. DNSSEC-OK is folded in because an
// answer stripped of RRSIGs must not be served to a validating client.
func Key(q dns.Question, dnssecOK bool) string {
	suffix := ";0"
	if dnssecOK {
		suffix = ";1"
	}
	return q.Name + ";" + dns.TypeToString[q.Qtype] + ";" + dns.ClassToString[q.Qclass] + suffix
}

func (c *Cache) shardFor(key string) *shard {
	var h maphash.Hash
	h.SetSeed(c.seed)
	h.WriteString(key)
	return c.shards[h.Sum64()%cacheShards]
}

// Get returns a cached response with TTLs decremented by the time it has been
// held, or nil on a miss.
func (c *Cache) Get(key string, generation uint64) *dns.Msg {
	if !c.enabled {
		return nil
	}
	sh := c.shardFor(key)
	now := time.Now()

	sh.mu.Lock()
	e, ok := sh.entries[key]
	if ok && (now.After(e.expires) || e.generation != generation) {
		delete(sh.entries, key)
		ok = false
	}
	if ok {
		e.lastUsed = now
	}
	sh.mu.Unlock()

	if !ok {
		c.misses.inc()
		return nil
	}
	c.hits.inc()

	remaining := uint32(time.Until(e.expires).Seconds())
	if remaining < 1 {
		remaining = 1
	}
	out := e.msg.Copy()
	setTTL(out, remaining)
	return out
}

// Put stores a response, deriving its lifetime from the smallest TTL in the
// message (or the negative TTL for an empty or NXDOMAIN answer).
func (c *Cache) Put(key string, msg *dns.Msg, generation uint64) {
	if !c.enabled || msg == nil || msg.Truncated {
		return
	}
	switch msg.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		// Caching SERVFAIL would turn a transient upstream blip into a
		// multi-minute outage for that name.
		return
	}

	ttl := minTTL(msg)
	if ttl == 0 {
		ttl = c.negTTL
	}
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}

	now := time.Now()
	e := &entry{
		msg:        msg.Copy(),
		expires:    now.Add(time.Duration(ttl) * time.Second),
		generation: generation,
		lastUsed:   now,
		origTTL:    ttl,
	}

	sh := c.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if len(sh.entries) >= sh.max {
		sh.evictLocked(now)
	}
	sh.entries[key] = e
}

// evictLocked removes expired entries, falling back to dropping the least
// recently used of a bounded sample. Sampling keeps eviction O(1)-ish without
// the memory cost of intrusive list pointers on every entry.
func (sh *shard) evictLocked(now time.Time) {
	const sample = 24

	var (
		oldestKey string
		oldest    time.Time
		seen      int
	)
	for k, e := range sh.entries {
		if now.After(e.expires) {
			delete(sh.entries, k)
			if len(sh.entries) < sh.max {
				return
			}
			continue
		}
		if oldestKey == "" || e.lastUsed.Before(oldest) {
			oldestKey, oldest = k, e.lastUsed
		}
		seen++
		if seen >= sample {
			break
		}
	}
	if oldestKey != "" && len(sh.entries) >= sh.max {
		delete(sh.entries, oldestKey)
	}
}

// Purge empties the cache, used when configuration changes in a way that could
// affect answers.
func (c *Cache) Purge() {
	for _, sh := range c.shards {
		sh.mu.Lock()
		sh.entries = make(map[string]*entry)
		sh.mu.Unlock()
	}
}

// Stats reports cache size and hit ratio.
func (c *Cache) Stats() (size int, hits, misses uint64) {
	for _, sh := range c.shards {
		sh.mu.Lock()
		size += len(sh.entries)
		sh.mu.Unlock()
	}
	return size, c.hits.get(), c.misses.get()
}

func minTTL(msg *dns.Msg) uint32 {
	var out uint32
	first := true
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			ttl := rr.Header().Ttl
			if first || ttl < out {
				out, first = ttl, false
			}
		}
	}
	return out
}

func setTTL(msg *dns.Msg, ttl uint32) {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			rr.Header().Ttl = ttl
		}
	}
}
