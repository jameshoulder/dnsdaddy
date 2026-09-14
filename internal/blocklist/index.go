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
	"time"

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
//
// # Why the times are int64 and not time.Time
//
// This struct is the single largest thing DNS Daddy holds in memory: one per
// listed domain, several hundred thousand of them on an ordinary install. The
// three strings already cost 48 bytes before a single character of anything,
// which is why TestIndexMemoryPerDomainStaysWithinBudget asserts the size.
//
// Three time.Time fields would have added 72 bytes — a 150% increase in the
// largest structure in the process, or about 18 MB at 250,000 domains, on a
// machine whose whole memory budget is 1 GB. Unix milliseconds cost 8 bytes
// each and say the same thing to the precision this is used at; the accessors
// below hand out time.Time so no caller has to know.
//
// LastSeen is deliberately absent. Every live indicator of a feed was last
// seen at that feed's most recent successful refresh — one time per feed, not
// one per domain — so it is held on the Index and read through LastSeenFor.
// Storing it here would have been another 8 bytes per domain to record the
// same value a few hundred thousand times.
type Entry struct {
	Category string
	FeedID   string
	FeedName string

	// FirstSeenUnixMs is when this feed first listed this domain, or 0 for
	// unknown.
	//
	// Zero means unknown and never 1970. An installation that upgraded into
	// this feature has no history for anything it was already blocking, and a
	// record claiming a domain was first listed on 1 January 1970 is worse
	// than one that says nothing: the first is a fact an operator may act on,
	// and it is false.
	FirstSeenUnixMs int64

	// ExpiresAtUnixMs is when the feed said this listing stops being current,
	// or 0 when it gave no expiry.
	//
	// Zero on every feed DNS Daddy ships with: hosts, domains and adblock are
	// bare domain lists, and the Observatory document does not carry one
	// either. The field exists so that a feed format which does carry one is
	// honoured rather than ignored, and so that nothing invents one.
	ExpiresAtUnixMs int64
}

// FirstSeen is when this feed first listed the domain, or the zero time when
// that is unknown.
func (e Entry) FirstSeen() time.Time { return fromUnixMs(e.FirstSeenUnixMs) }

// ExpiresAt is when this listing stops being current, or the zero time when
// the feed gave no expiry.
func (e Entry) ExpiresAt() time.Time { return fromUnixMs(e.ExpiresAtUnixMs) }

// Expired reports whether this listing has passed its expiry as of now.
//
// An entry with no expiry never expires, which is every entry from every feed
// shipped today. The zero check comes first so the common case is one integer
// comparison and no clock read at all.
func (e Entry) Expired(now time.Time) bool {
	return e.ExpiresAtUnixMs != 0 && now.UnixMilli() >= e.ExpiresAtUnixMs
}

// fromUnixMs turns a stored millisecond count into a time, mapping 0 to the
// zero time rather than to 1970.
func fromUnixMs(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
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

	// lastSeen is when each feed was last successfully refreshed, in Unix
	// milliseconds.
	//
	// One entry per feed rather than per domain, because that is genuinely the
	// shape of the fact: every indicator a feed currently lists was last seen
	// at the same moment — the refresh that built this index. A per-domain
	// copy would repeat one value a few hundred thousand times.
	lastSeen map[string]int64
}

// NewIndex returns an empty index.
func NewIndex() *Index {
	return &Index{
		domains:    map[string]Entry{},
		extra:      map[string][]Entry{},
		byCategory: map[string]int{},
		feeds:      map[string]int{},
		lastSeen:   map[string]int64{},
	}
}

// LastSeenFor is when a feed last confirmed everything it currently lists, or
// the zero time when that is unknown.
func (ix *Index) LastSeenFor(feedID string) time.Time {
	if ix == nil {
		return time.Time{}
	}
	return fromUnixMs(ix.lastSeen[feedID])
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
//
// An expired claim cannot block. A feed that publishes an expiry is saying the
// listing stops being current at that moment, and honouring the listing past
// it would be blocking on intelligence its own author has withdrawn. Expired
// claims are skipped exactly as if the policy did not enable them, so a parent
// name or a second claim can still block — what expires is one claim, not the
// name.
func (ix *Index) LookupEnabled(domain string, enabled map[string]bool) (Entry, bool) {
	return ix.lookupEnabledAt(domain, enabled, time.Now())
}

// lookupEnabledAt is LookupEnabled with the clock injected, so expiry can be
// tested without sleeping.
func (ix *Index) lookupEnabledAt(domain string, enabled map[string]bool, now time.Time) (Entry, bool) {
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
		//
		// The expiry check is one integer comparison against zero for every
		// entry from every feed shipped today, because none of them publish
		// one. Only a non-zero expiry reaches the clock.
		if enabled[e.Category] && !e.Expired(now) {
			found, ok = e, true
			return true
		}
		// Otherwise fall back to the name's other claims, most severe first.
		for _, c := range ix.extra[suffix] {
			if !enabled[c.Category] || c.Expired(now) {
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
		// One entry per feed, so a handful. Built here rather than lazily
		// because ApplyLifecycle writes to it on every rebuild, and a nil map
		// there panics the refresh goroutine.
		lastSeen: map[string]int64{},
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

// LifecycleTimes is what the lifecycle store knows about one feed's listing of
// one domain. Zero times mean unknown.
type LifecycleTimes struct {
	FirstSeenUnixMs int64
	ExpiresAtUnixMs int64
}

// ApplyLifecycle stamps stored listing times onto a freshly built index, and
// records when each feed was last confirmed.
//
// Called once per rebuild, in the refresh goroutine, before the index is
// published. It walks every entry — including the further claims held in
// `extra`, which are each a different feed's listing of the same domain and
// each have their own history.
//
// lookup returns the times for one (feed, domain) pair and reports whether any
// are known. An index built before the lifecycle table existed, or on an
// installation where it could not be read, simply gets zero times everywhere —
// which is the designed meaning of unknown, and leaves blocking untouched.
func (ix *Index) ApplyLifecycle(lastSeen map[string]int64, lookup func(feedID, domain string) (LifecycleTimes, bool)) {
	if ix == nil {
		return
	}
	if ix.lastSeen == nil {
		ix.lastSeen = make(map[string]int64, len(lastSeen))
	}
	for feedID, at := range lastSeen {
		ix.lastSeen[feedID] = at
	}
	if lookup == nil {
		return
	}
	for domain, e := range ix.domains {
		if t, ok := lookup(e.FeedID, domain); ok {
			e.FirstSeenUnixMs, e.ExpiresAtUnixMs = t.FirstSeenUnixMs, t.ExpiresAtUnixMs
			ix.domains[domain] = e
		}
	}
	for domain, claims := range ix.extra {
		for i, e := range claims {
			if t, ok := lookup(e.FeedID, domain); ok {
				claims[i].FirstSeenUnixMs, claims[i].ExpiresAtUnixMs = t.FirstSeenUnixMs, t.ExpiresAtUnixMs
			}
		}
	}
}

// Indicators reports, per feed, every domain that feed contributed to this
// index. It is what a refresh hands to the lifecycle store.
//
// Built from the finished index rather than tallied while loading, for the
// same reason the per-feed counts are: a later feed can take a domain off an
// earlier one by claiming it under a more severe category, and a set collected
// as that earlier feed was read would not know it. Every claim is included,
// primary and further alike, because each is that feed's own listing.
func (ix *Index) Indicators() map[string]map[string]time.Time {
	out := map[string]map[string]time.Time{}
	if ix == nil {
		return out
	}
	add := func(feedID, domain string, expires int64) {
		if feedID == "" {
			return
		}
		byFeed := out[feedID]
		if byFeed == nil {
			byFeed = map[string]time.Time{}
			out[feedID] = byFeed
		}
		byFeed[domain] = fromUnixMs(expires)
	}
	for domain, e := range ix.domains {
		add(e.FeedID, domain, e.ExpiresAtUnixMs)
	}
	for domain, claims := range ix.extra {
		for _, e := range claims {
			add(e.FeedID, domain, e.ExpiresAtUnixMs)
		}
	}
	return out
}
