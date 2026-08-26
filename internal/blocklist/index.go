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
	"slices"
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
//
// A domain can be claimed under more than one category — the Observatory files
// a single indicator as both malware and C2, and two feeds routinely disagree
// about which category a domain belongs to. Every one of those claims decides
// whether some policy blocks the domain, so every one of them is kept.
//
// They are stored in two parts. domains holds the primary claim: the most
// severe category on that name, which is what the query log reports and what
// per-feed counts are attributed to. extra holds any further claims, and is
// empty for the overwhelming majority of domains, which are claimed once. That
// split is what keeps a multi-category index costing the same per domain as a
// single-category one, and keeps the blocked path to a single map lookup.
type Index struct {
	domains map[string]Entry
	extra   map[string][]Entry
	// counts per category, for the dashboard.
	byCategory map[string]int
	feeds      map[string]int
}

// NewIndex returns an empty index.
func NewIndex() *Index {
	return &Index{
		domains:    map[string]Entry{},
		extra:      map[string][]Entry{},
		byCategory: map[string]int{},
		feeds:      map[string]int{},
	}
}

// Lookup reports the primary claim on a domain — the most severe category any
// feed filed it under — walking from the full name up through its parents. It
// performs no allocation.
//
// This answers "is this domain listed, and as what". It is NOT the function to
// decide whether a policy blocks the domain: a domain listed as both malware
// and C2 reports malware here, and a C2-only policy still has to block it.
// Use LookupEnabled for that.
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

// LookupEnabled reports the claim that justifies blocking a domain under the
// given set of enabled categories, walking from the full name up through its
// parents. The returned entry names the category and feed to report, so the
// query log gives the reason the operator actually enabled.
//
// A domain claimed under several categories is blocked if a policy enables any
// one of them. That is the whole point of keeping every claim: a domain filed
// as both malware and C2 must be blocked by a malware-only policy and by a
// C2-only policy alike, and neither operator should have to know the other
// category exists.
//
// The walk stops at the most specific name carrying an enabled claim. A name
// listed only under categories this policy does not enable does not shadow a
// parent that is enabled — "blocking evil.com blocks login.evil.com" has to
// hold even when login.evil.com turns up on an ad list as well.
func (ix *Index) LookupEnabled(domain string, enabled map[string]bool) (Entry, bool) {
	if ix == nil || len(ix.domains) == 0 || len(enabled) == 0 {
		return Entry{}, false
	}
	var (
		found Entry
		ok    bool
	)
	domainutil.Suffixes(domain, func(suffix string) bool {
		e, hit := ix.domains[suffix]
		if !hit {
			return false
		}
		// The primary claim is the most severe on this name, so when the policy
		// enables it there is nothing better to find and no second map to
		// consult. This is the path every blocked query takes.
		if enabled[e.Category] {
			found, ok = e, true
			return true
		}
		// Otherwise fall back to the name's other claims, most severe first.
		for _, c := range ix.extra[suffix] {
			if !enabled[c.Category] {
				continue
			}
			if !ok || rankOf(c.Category) < rankOf(found.Category) {
				found, ok = c, true
			}
		}
		return ok
	})
	return found, ok
}

// Categories returns every category a domain is claimed under, most severe
// first, for the exact name only. It exists for diagnostics — "why is this
// blocked" — not for the hot path.
func (ix *Index) Categories(domain string) []string {
	if ix == nil {
		return nil
	}
	e, ok := ix.domains[domain]
	if !ok {
		return nil
	}
	out := []string{e.Category}
	for _, c := range ix.extra[domain] {
		out = append(out, c.Category)
	}
	// The primary is already the most severe; the rest are in the order they
	// were claimed, which is not the order a reader expects to see them in.
	slices.SortFunc(out[1:], func(a, b string) int { return rankOf(a) - rankOf(b) })
	return out
}

// Len returns the number of indexed domains.
func (ix *Index) Len() int {
	if ix == nil {
		return 0
	}
	return len(ix.domains)
}

// CountsByCategory returns, per category, how many domains enabling that
// category would block. A domain claimed under two categories counts once
// under each, so these totals can sum to more than Len() — that is the honest
// answer to "what does ticking this box cost me", which is the question the
// number is on screen to answer.
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

// CountsByFeed returns per-feed domain counts, after de-duplication across
// feeds: how many domains in the index this feed is the primary source for.
// A feed whose claim on a domain was superseded by a more severe one is not
// credited with it, even though its claim is still live and can still block.
// These totals sum to Len().
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
		domains: make(map[string]Entry, n),
		// Not sized from n: domains claimed under more than one category are a
		// small minority, and pre-allocating for all of them would waste more
		// memory than the claims themselves cost.
		extra:      map[string][]Entry{},
		byCategory: map[string]int{},
		feeds:      map[string]int{},
	}}
}

// Add records a claim on a normalised domain and reports whether this entry
// became its primary claim — because the domain was new, or because this claim
// is more severe than the one it held.
//
// No claim is ever discarded for being less severe. A claim under a category
// the domain is not already held at is kept alongside the primary one, so a
// policy enabling only that category still blocks the domain. What severity
// decides is which claim is reported in the query log and which feed is
// credited with the domain, not whether the other claims survive.
//
// A second claim under a category the domain already carries changes nothing:
// the first feed to list it keeps the attribution.
func (b *Builder) Add(domain string, e Entry) bool {
	if domain == "" {
		return false
	}

	prev, exists := b.ix.domains[domain]
	if !exists {
		b.ix.domains[domain] = e
		b.ix.byCategory[e.Category]++
		b.ix.feeds[e.FeedID]++
		return true
	}

	if e.Category == prev.Category || b.hasClaim(domain, e.Category) {
		return false
	}

	if rankOf(e.Category) < rankOf(prev.Category) {
		// A more severe claim takes over as primary. The one it displaces is
		// kept as a further claim — it can still be the reason some other
		// policy blocks this domain — but stops being credited with the domain.
		b.ix.feeds[prev.FeedID]--
		b.ix.feeds[e.FeedID]++
		b.ix.domains[domain] = e
		b.ix.extra[domain] = append(b.ix.extra[domain], prev)
		b.ix.byCategory[e.Category]++
		return true
	}

	b.ix.extra[domain] = append(b.ix.extra[domain], e)
	b.ix.byCategory[e.Category]++
	return false
}

// hasClaim reports whether a domain already carries a claim under a category,
// beyond its primary one.
func (b *Builder) hasClaim(domain, category string) bool {
	for _, c := range b.ix.extra[domain] {
		if c.Category == category {
			return true
		}
	}
	return false
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
