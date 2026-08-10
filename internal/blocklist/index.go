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

	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
)

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
// A domain claimed by more than one feed keeps its first claim, and feeds are
// added in category priority order so that a domain on both a malware list and
// an ad list is reported as malware. That ordering is what makes the block
// reason in the query log trustworthy.
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

// Add inserts a normalised domain. It returns true if the domain was new.
func (b *Builder) Add(domain string, e Entry) bool {
	if domain == "" {
		return false
	}
	if _, exists := b.ix.domains[domain]; exists {
		return false
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
