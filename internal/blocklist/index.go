// Package blocklist builds and serves the in-memory index of blocked domains.
//
// The index is a plain exact-match map from normalised domain to the category
// and feed that contributed it, consulted with a suffix walk so that blocking
// "evil.com" also blocks "login.evil.com".
//
// An exact map rather than a Bloom filter or hash-only set is a deliberate
// trade. Roughly 55 bytes per domain means a 500,000-domain index costs about
// 30 MB — comfortable on a 1 GB box — and in exchange there is no possibility
// of a hash collision silently blocking a legitimate domain. For NEO, one
// unexplained block of the MD's supplier costs more trust than 30 MB costs
// money.
package blocklist

import (
	"sync"
	"sync/atomic"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
)

// categoryRank is the canonical category ordering as a lookup, where a lower
// number is more severe. Built once: it is consulted for every domain claimed
// twice during a rebuild, which on a full feed set is hundreds of thousands of
// times.
var categoryRank = func() map[string]int {
	m := make(map[string]int, len(catalog.Categories))
	for i, c := range catalog.Categories {
		m[c.ID] = i
	}
	return m
}()

// rankOf returns a category's severity rank. Unknown categories sort last.
func rankOf(category string) int {
	if r, ok := categoryRank[category]; ok {
		return r
	}
	return len(categoryRank)
}

// Entry records why a domain is in the index.
type Entry struct {
	Category string
	FeedID   string
	FeedName string
}

// Index is an immutable snapshot of every enabled feed's domains.
type Index struct {
	domains map[string]Entry
	// counts per category, for the dashboard.
	byCategory map[string]int
	feeds      map[string]int
}

// NewIndex returns an empty index.
func NewIndex() *Index {
	return &Index{
		domains:    map[string]Entry{},
		byCategory: map[string]int{},
		feeds:      map[string]int{},
	}
}

// Lookup reports the closest matching blocklist entry for a domain, walking
// from the full name up through its parents. It performs no allocation.
func (ix *Index) Lookup(domain string) (Entry, bool) {
	if ix == nil || len(ix.domains) == 0 {
		return Entry{}, false
	}
	var (
		found Entry
		ok    bool
	)
	domainutil.Suffixes(domain, func(suffix string) bool {
		if e, hit := ix.domains[suffix]; hit {
			found, ok = e, true
			return true
		}
		return false
	})
	return found, ok
}

// Len returns the number of indexed domains.
func (ix *Index) Len() int {
	if ix == nil {
		return 0
	}
	return len(ix.domains)
}

// CountsByCategory returns per-category domain counts.
func (ix *Index) CountsByCategory() map[string]int {
	out := map[string]int{}
	if ix == nil {
		return out
	}
	for k, v := range ix.byCategory {
		out[k] = v
	}
	return out
}

// CountsByFeed returns per-feed domain counts, after de-duplication across feeds.
func (ix *Index) CountsByFeed() map[string]int {
	out := map[string]int{}
	if ix == nil {
		return out
	}
	for k, v := range ix.feeds {
		out[k] = v
	}
	return out
}

// Builder accumulates domains from feeds into a new Index.
//
// A domain claimed by more than one feed is filed under the most severe
// category claiming it, so a domain on both a malware list and an ad list is
// reported as malware. That is what makes the block reason in the query log
// trustworthy, and it is also what decides whether a policy blocks the domain
// at all: a policy enabling malware but not ads must not miss it because an ad
// feed happened to be read first.
//
// Feeds are still fed in category-priority order, which makes the common case
// a single map lookup. The rule is enforced here rather than left to that
// ordering because a feed's own category is no longer the whole story: the
// Observatory format carries a category per indicator, so one feed contributes
// domains at several severities and feed order alone cannot get this right.
type Builder struct {
	ix *Index
}

// NewBuilder returns a Builder with capacity hinted for n domains.
func NewBuilder(n int) *Builder {
	if n < 1024 {
		n = 1024
	}
	return &Builder{ix: &Index{
		domains:    make(map[string]Entry, n),
		byCategory: map[string]int{},
		feeds:      map[string]int{},
	}}
}

// Add inserts a normalised domain, reporting whether this entry now owns it —
// either because the domain was new, or because it displaced a less severe
// classification. A domain already held at the same or a higher severity keeps
// what it has, and Add returns false.
//
// The return value is what per-feed contribution counts are derived from, so
// "owns it" rather than "was new" keeps those counts equal to what the finished
// index actually attributes to each feed.
func (b *Builder) Add(domain string, e Entry) bool {
	if domain == "" {
		return false
	}
	if prev, exists := b.ix.domains[domain]; exists {
		if rankOf(e.Category) >= rankOf(prev.Category) {
			return false
		}
		// A more severe claim takes the domain over, and the previous holder
		// stops being credited with it.
		b.ix.byCategory[prev.Category]--
		b.ix.feeds[prev.FeedID]--
		b.ix.domains[domain] = e
		b.ix.byCategory[e.Category]++
		b.ix.feeds[e.FeedID]++
		return true
	}
	b.ix.domains[domain] = e
	b.ix.byCategory[e.Category]++
	b.ix.feeds[e.FeedID]++
	return true
}

// Build returns the finished index.
func (b *Builder) Build() *Index { return b.ix }

// Holder is a concurrency-safe slot for the current index. DNS queries read
// through it on the hot path, and a feed refresh swaps a freshly built index in
// atomically — readers never see a partially populated map, and there is no
// window where the resolver has no blocklist.
type Holder struct {
	v   atomic.Pointer[Index]
	mu  sync.Mutex // serialises rebuilds
	gen atomic.Uint64
}

// NewHolder returns a Holder containing an empty index.
func NewHolder() *Holder {
	h := &Holder{}
	h.v.Store(NewIndex())
	return h
}

// Load returns the current index.
func (h *Holder) Load() *Index { return h.v.Load() }

// Store swaps in a new index and bumps the generation counter.
func (h *Holder) Store(ix *Index) {
	h.v.Store(ix)
	h.gen.Add(1)
}

// Generation returns how many times the index has been replaced. The DNS cache
// keys on this so that a refreshed blocklist immediately invalidates cached
// answers rather than serving stale allows for up to a TTL.
func (h *Holder) Generation() uint64 { return h.gen.Load() }

// Lock serialises index rebuilds so two refreshes cannot interleave.
func (h *Holder) Lock() { h.mu.Lock() }

// Unlock releases the rebuild lock.
func (h *Holder) Unlock() { h.mu.Unlock() }
