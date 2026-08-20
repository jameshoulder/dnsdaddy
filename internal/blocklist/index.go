// Package blocklist builds and serves the in-memory index of blocked domains.
//
// The index is a plain exact-match map from normalised domain to the category
// and feed that contributed it, consulted with a suffix walk so that blocking
// "evil.com" also blocks "login.evil.com".
//
// An exact map rather than a Bloom filter or hash-only set is a deliberate
// trade: there is no possibility of a hash collision silently blocking a
// legitimate domain. For NEO, one unexplained block of the MD's supplier costs
// more trust than the memory costs money.
//
// The map stores a 4-byte index into a small table of distinct Entry values
// rather than the Entry itself. Category, feed ID and feed name are drawn from
// as many distinct values as there are feeds — around ten — so storing three
// string headers (48 bytes) against every one of millions of domains spent
// most of the index's memory restating the same handful of strings. Interning
// them cuts the per-domain cost by roughly a factor of four.
//
// That is not a micro-optimisation. A refresh builds the replacement index
// while the current one is still serving queries, so peak memory is both
// indexes at once; at the old cost, a default install exceeded the 640 MB
// container limit during refresh and was OOM-killed. See
// docs/baseline-validation.md.
package blocklist

import (
	"math"
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
	// domains maps a normalised name to its position in entries. A uint32
	// index rather than the Entry itself is what keeps the index affordable;
	// see the package comment.
	domains map[string]uint32
	// entries holds the distinct Entry values, one per feed in practice.
	entries []Entry
	// counts per category, for the dashboard.
	byCategory map[string]int
	feeds      map[string]int
}

// NewIndex returns an empty index.
func NewIndex() *Index {
	return &Index{
		domains:    map[string]uint32{},
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
		if idx, hit := ix.domains[suffix]; hit {
			found, ok = ix.entries[idx], true
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
	// intern maps a distinct Entry to its position in ix.entries. Entry is
	// comparable and there are only as many distinct values as feeds, so this
	// map stays tiny however many domains pass through.
	intern map[Entry]uint32
}

// NewBuilder returns a Builder with capacity hinted for n domains.
func NewBuilder(n int) *Builder {
	if n < 1024 {
		n = 1024
	}
	return &Builder{
		ix: &Index{
			domains:    make(map[string]uint32, n),
			byCategory: map[string]int{},
			feeds:      map[string]int{},
		},
		intern: map[Entry]uint32{},
	}
}

// Add inserts a normalised domain. It returns true if the domain was new.
func (b *Builder) Add(domain string, e Entry) bool {
	if domain == "" {
		return false
	}
	if _, exists := b.ix.domains[domain]; exists {
		return false
	}
	idx, seen := b.intern[e]
	if !seen {
		// Guarded rather than assumed: the index is addressed by uint32, and
		// silently wrapping would point domains at the wrong feed. In practice
		// there is one Entry per feed, so this is unreachable short of a bug.
		if len(b.ix.entries) >= math.MaxUint32 {
			return false
		}
		idx = uint32(len(b.ix.entries))
		b.ix.entries = append(b.ix.entries, e)
		b.intern[e] = idx
	}
	b.ix.domains[domain] = idx
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
