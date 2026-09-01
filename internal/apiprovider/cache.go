package apiprovider

import (
	"hash/maphash"
	"sync"
	"time"
)

// CachedVerdict is what the in-memory layer holds.
type CachedVerdict struct {
	Verdict    Verdict
	ProviderID string
	ExpiresAt  time.Time
}

// MemoryCache is the layer the DNS hot path reads.
//
// Everything about it is chosen for that one caller. It is sharded, so N
// concurrent lookups do not queue on one mutex. It reads with a plain map
// lookup and no allocation on a hit. It never touches the database, never
// dials, and never blocks on anything a network call holds — a cache the
// resolution path can be made to wait on is not a cache, it is a dependency.
//
// Bounded by count rather than bytes, with the oldest-expiring entries dropped
// when it is full. An unbounded cache keyed on domain names grows at the rate
// the network resolves new names, which on a busy network is a slow leak that
// looks fine for a week.
type MemoryCache struct {
	shards []*cacheShard
	mask   uint64
	seed   maphash.Seed
	// perShard is the entry ceiling for one shard, so the total is
	// perShard × len(shards).
	perShard int
}

type cacheShard struct {
	mu      sync.RWMutex
	entries map[string]CachedVerdict
}

// NewMemoryCache returns a cache holding about maxEntries in total.
func NewMemoryCache(maxEntries int) *MemoryCache {
	const shardCount = 16 // power of two, so the mask works

	if maxEntries <= 0 {
		maxEntries = 4096
	}
	per := maxEntries / shardCount
	if per < 16 {
		per = 16
	}

	c := &MemoryCache{
		shards:   make([]*cacheShard, shardCount),
		mask:     shardCount - 1,
		seed:     maphash.MakeSeed(),
		perShard: per,
	}
	for i := range c.shards {
		c.shards[i] = &cacheShard{entries: make(map[string]CachedVerdict, per)}
	}
	return c
}

// cacheKey pairs a subject with the provider that answered about it. Two
// providers disagreeing about one domain is normal and both answers are worth
// keeping.
func cacheKey(subject, providerID string) string { return providerID + "\x00" + subject }

func (c *MemoryCache) shardFor(key string) *cacheShard {
	return c.shards[maphash.String(c.seed, key)&c.mask]
}

// Get returns a fresh verdict, or false.
//
// Expired entries are reported as absent rather than removed: this is called
// from the resolution path, and taking a write lock to evict would turn a read
// into a writer that every other lookup queues behind. The eviction in Put
// clears them.
func (c *MemoryCache) Get(subject, providerID string, now time.Time) (CachedVerdict, bool) {
	sh := c.shardFor(cacheKey(subject, providerID))
	sh.mu.RLock()
	v, ok := sh.entries[cacheKey(subject, providerID)]
	sh.mu.RUnlock()

	if !ok || !now.Before(v.ExpiresAt) {
		return CachedVerdict{}, false
	}
	return v, true
}

// Put stores a verdict, evicting if the shard is full.
func (c *MemoryCache) Put(subject string, v CachedVerdict) {
	key := cacheKey(subject, v.ProviderID)
	sh := c.shardFor(key)

	sh.mu.Lock()
	defer sh.mu.Unlock()

	if len(sh.entries) >= c.perShard {
		c.evictLocked(sh)
	}
	sh.entries[key] = v
}

// evictLocked makes room. The caller holds the write lock.
//
// Expired entries first, because they are free to lose. If that is not enough
// — a shard full of fresh entries — the soonest-expiring go, which is the
// closest thing to "least useful" available without tracking access times. A
// true LRU would need a second data structure updated on every read, and every
// read here is on the DNS path.
func (c *MemoryCache) evictLocked(sh *cacheShard) {
	now := time.Now()
	for k, v := range sh.entries {
		if !now.Before(v.ExpiresAt) {
			delete(sh.entries, k)
		}
	}
	if len(sh.entries) < c.perShard {
		return
	}

	// Still full. Drop the quarter that expires soonest. A quarter rather than
	// one, so a hot cache does not evict on every single insert.
	target := c.perShard - c.perShard/4
	for len(sh.entries) > target {
		var (
			oldestKey string
			oldest    time.Time
			found     bool
		)
		for k, v := range sh.entries {
			if !found || v.ExpiresAt.Before(oldest) {
				oldestKey, oldest, found = k, v.ExpiresAt, true
			}
		}
		if !found {
			return
		}
		delete(sh.entries, oldestKey)
	}
}

// Forget drops every entry for a provider.
//
// Called when a provider is deleted or its credential rotated. A cached
// verdict from a provider that no longer exists is an answer nobody can trace
// to a source, and after a rotation the old answers may have come from a
// credential that has since been revoked.
func (c *MemoryCache) Forget(providerID string) {
	prefix := providerID + "\x00"
	for _, sh := range c.shards {
		sh.mu.Lock()
		for k := range sh.entries {
			if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
				delete(sh.entries, k)
			}
		}
		sh.mu.Unlock()
	}
}

// Clear empties the cache.
func (c *MemoryCache) Clear() {
	for _, sh := range c.shards {
		sh.mu.Lock()
		sh.entries = make(map[string]CachedVerdict, c.perShard)
		sh.mu.Unlock()
	}
}

// Len reports how many entries are held, expired ones included.
func (c *MemoryCache) Len() int {
	n := 0
	for _, sh := range c.shards {
		sh.mu.RLock()
		n += len(sh.entries)
		sh.mu.RUnlock()
	}
	return n
}
