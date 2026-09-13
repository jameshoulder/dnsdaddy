// Package firstseen records which registered domains this installation has
// ever seen a query for.
//
// "This domain has never been resolved on this network before" is one of the
// more useful signals in DNS security, and the query log is a poor place to
// get it from: at the seven-day default retention, almost every domain looks
// new. This index is kept independently of that window, one row per registered
// domain ever seen rather than one per query, so its size is bounded by how
// many domains a network touches rather than by how much it browses.
//
// # Observe only
//
// Nothing here can change an answer. There is no Enforce door to open: the
// output is a timestamp and a count, and a novelty signal is evidence for a
// human or an input to a detector, never a reason to refuse a name. A domain
// being new is not a domain being bad — every legitimate site was new once,
// and the first query after a cache flush looks identical to the first query
// ever.
//
// # The hot path
//
// Observe does a public-suffix lookup and a non-blocking channel send, and
// nothing else. If the buffer is full the observation is dropped and counted.
// Losing a novelty signal under extreme load is acceptable; adding
// milliseconds to every lookup on the network is not. Same discipline as
// internal/querylog, for the same reason.
//
// # Bounding
//
// An authorised client can ask for unique names forever. eTLD+1 cardinality is
// smaller than FQDN cardinality but still unbounded in practice — new gTLDs
// and algorithmically generated second-level names see to that — so the table
// is bounded three ways, all of them shipped rather than promised:
//
//	MaxRows          a hard ceiling, enforced by evicting the stalest rows
//	MaxNewPerMinute  a budget on how fast new rows may appear
//	the buffer       a bounded channel that drops rather than queues
//
// Repeats of domains already in the table never consume the new-row budget.
// That split is the point: an attacker minting fresh names is throttled while
// a network browsing the same few thousand domains never is.
package firstseen

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Status is what the index can say about a domain.
type Status string

const (
	// StatusNew means the index holds no row: this installation has not seen
	// the domain, as far as the index knows.
	StatusNew Status = "new"
	// StatusKnown means a row exists.
	StatusKnown Status = "known"
	// StatusUnknown means the index could not answer — it is switched off, or
	// the lookup failed. Callers must render this as "unknown" and never as
	// "new": a disabled index saying "never seen before" about every domain on
	// the network would be the loudest false signal this project could ship.
	StatusUnknown Status = "unknown"
)

// Drop reasons, used as a bounded metric label.
const (
	DropFull     = "full"     // the buffer was full
	DropBudget   = "budget"   // the new-row budget was spent
	DropInvalid  = "invalid"  // no registered domain could be derived
	DropDisabled = "disabled" // the index is off
)

// DropReasons is every reason, so metrics can be emitted at zero rather than
// appearing on first occurrence.
func DropReasons() []string {
	return []string{DropFull, DropBudget, DropInvalid, DropDisabled}
}

// Defaults.
const (
	// DefaultMaxRows caps the table.
	//
	// A row is a registered domain (~15 bytes), three integers, and SQLite's
	// per-row and index overhead: call it 120 bytes all in, so 100,000 rows is
	// roughly 12 MB on a box with 1 GB. A home or small-office network sees
	// somewhere between a few thousand and a few tens of thousands of distinct
	// registered domains over months, so this is years of headroom for a real
	// network and a firm ceiling against one that is being abused.
	DefaultMaxRows = 100_000

	// DefaultMaxNewPerMinute budgets new rows.
	//
	// A network discovering 200 previously unseen *registered domains* every
	// minute, sustained, is not browsing. Bursts go higher — a first boot, a
	// page with many third-party origins — which is why the budget is per
	// minute rather than per second: a burst is absorbed and a sustained flood
	// is not.
	DefaultMaxNewPerMinute = 200

	// DefaultBufferSize is the hot-path queue. Sized so a flush interval's
	// worth of a busy resolver fits without dropping.
	DefaultBufferSize = 4096

	// DefaultFlushInterval is how often a batch is written.
	DefaultFlushInterval = 2 * time.Second
)

// Config configures an Index.
type Config struct {
	MaxRows         int
	MaxNewPerMinute int
	BufferSize      int
	FlushInterval   time.Duration

	// now is injectable for tests.
	now func() time.Time
}

// Index is the first-seen engine. A nil *Index is a working switched-off
// index: Observe does nothing and Lookup returns StatusUnknown.
type Index struct {
	store *store.Store
	log   *slog.Logger
	cfg   Config

	ch   chan observation
	done chan struct{}

	// rows is the cached row count, refreshed after each flush so /metrics and
	// doctor do not run a COUNT(*) per scrape.
	rows atomic.Int64

	inserts   atomic.Uint64
	updates   atomic.Uint64
	evictions atomic.Uint64
	dropped   [4]atomic.Uint64

	lookupNew     atomic.Uint64
	lookupKnown   atomic.Uint64
	lookupUnknown atomic.Uint64
}

type observation struct {
	domain string
	at     time.Time
}

// New builds an Index. Run must be called to start draining.
func New(st *store.Store, cfg Config, log *slog.Logger) *Index {
	if cfg.MaxRows <= 0 {
		cfg.MaxRows = DefaultMaxRows
	}
	if cfg.MaxNewPerMinute <= 0 {
		cfg.MaxNewPerMinute = DefaultMaxNewPerMinute
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultBufferSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &Index{
		store: st,
		log:   log,
		cfg:   cfg,
		ch:    make(chan observation, cfg.BufferSize),
		done:  make(chan struct{}),
	}
}

// Observe records that a query was asked for name.
//
// name must already be normalised by domainutil — the handler has done that by
// the time this is reached, and normalising twice would be a second scheme to
// keep in step with the first.
//
// Never blocks, never returns an error, and does no database work. A name with
// no registered domain is counted as invalid and dropped rather than inserted
// under its raw form: "printer" and "wpad.corp.local" are not registrations,
// and indexing them would fill the table with a network's own search suffix.
func (i *Index) Observe(name string) {
	if i == nil {
		return
	}
	domain, _, ok := domainutil.RegisteredDomain(name)
	if !ok {
		i.drop(DropInvalid)
		return
	}
	select {
	case i.ch <- observation{domain: domain, at: i.cfg.now()}:
	default:
		i.drop(DropFull)
	}
}

// Lookup asks what the index knows about a name.
//
// Reads the database, so callers must not put it on the resolution path. It is
// for the API, hunts, and anything else a human is waiting on.
func (i *Index) Lookup(ctx context.Context, name string) (store.FirstSeen, Status) {
	if i == nil {
		return store.FirstSeen{}, StatusUnknown
	}
	domain, _, ok := domainutil.RegisteredDomain(name)
	if !ok {
		i.countLookup(StatusUnknown)
		return store.FirstSeen{}, StatusUnknown
	}
	rec, err := i.store.LookupFirstSeen(ctx, domain)
	switch {
	case err == nil:
		i.countLookup(StatusKnown)
		return rec, StatusKnown
	case err == store.ErrNotFound:
		i.countLookup(StatusNew)
		return store.FirstSeen{Domain: domain}, StatusNew
	default:
		i.countLookup(StatusUnknown)
		return store.FirstSeen{}, StatusUnknown
	}
}

// Run drains observations until ctx is cancelled, then flushes what is left.
func (i *Index) Run(ctx context.Context) {
	if i == nil {
		return
	}
	defer close(i.done)

	i.refreshRows(ctx)

	ticker := time.NewTicker(i.cfg.FlushInterval)
	defer ticker.Stop()

	// batch collapses repeats: a domain asked five hundred times between
	// flushes becomes one row update carrying five hundred, not five hundred
	// round trips. This is what keeps a busy network cheap.
	batch := map[string]*store.FirstSeenTouch{}

	// budget is refilled once a minute. Tracked here rather than per flush so
	// the limit means what its name says regardless of the flush interval.
	budget := i.cfg.MaxNewPerMinute
	budgetWindow := i.cfg.now()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		now := i.cfg.now()
		if now.Sub(budgetWindow) >= time.Minute {
			budget = i.cfg.MaxNewPerMinute
			budgetWindow = now
		}

		touches := make([]store.FirstSeenTouch, 0, len(batch))
		for _, t := range batch {
			touches = append(touches, *t)
		}
		clear(batch)

		// Detached context so a shutdown mid-flush still lands.
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()

		res, err := i.store.ApplyFirstSeen(wctx, touches, budget)
		if err != nil {
			// A failed write loses observations and nothing else. It must not
			// propagate: the answer that produced them went to the client
			// long ago, and there is nothing resolution could do with an
			// error from a statistics table.
			i.log.Error("write first-seen batch", "domains", len(touches), "error", err)
			return
		}
		i.inserts.Add(nonNegative(res.Inserted))
		i.updates.Add(nonNegative(res.Updated))
		for n := int64(0); n < res.Rejected; n++ {
			i.drop(DropBudget)
		}
		budget -= int(res.Inserted)
		if budget < 0 {
			budget = 0
		}

		if res.Inserted > 0 {
			if n, err := i.store.EvictFirstSeen(wctx, i.cfg.MaxRows); err != nil {
				i.log.Error("evict first-seen rows", "error", err)
			} else if n > 0 {
				i.evictions.Add(nonNegative(n))
			}
			i.refreshRows(wctx)
		}
	}

	for {
		select {
		case <-ctx.Done():
			// Drain what is already queued before the final write.
			for {
				select {
				case o := <-i.ch:
					i.collect(batch, o)
					continue
				default:
				}
				break
			}
			flush()
			return
		case o := <-i.ch:
			i.collect(batch, o)
		case <-ticker.C:
			flush()
		}
	}
}

// nonNegative converts a row count to a counter value.
//
// These counts come back from database/sql, where a row count is an int64 that
// a driver is permitted to report as -1 when it does not know. Converting that
// straight to uint64 would wrap to 18 quintillion and put a number on an
// operator's dashboard that is not merely wrong but unmistakably nonsense
// forever, since counters do not go down.
func nonNegative(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// collect folds one observation into the pending batch.
func (i *Index) collect(batch map[string]*store.FirstSeenTouch, o observation) {
	if t, ok := batch[o.domain]; ok {
		t.Count++
		if o.at.After(t.At) {
			t.At = o.at
		}
		return
	}
	batch[o.domain] = &store.FirstSeenTouch{Domain: o.domain, Count: 1, At: o.at}
}

func (i *Index) refreshRows(ctx context.Context) {
	n, err := i.store.CountFirstSeen(ctx)
	if err != nil {
		return
	}
	i.rows.Store(n)
}

// Wait blocks until Run has finished flushing.
func (i *Index) Wait() {
	if i == nil {
		return
	}
	<-i.done
}

func (i *Index) drop(reason string) {
	if i == nil {
		return
	}
	switch reason {
	case DropFull:
		i.dropped[0].Add(1)
	case DropBudget:
		i.dropped[1].Add(1)
	case DropInvalid:
		i.dropped[2].Add(1)
	case DropDisabled:
		i.dropped[3].Add(1)
	}
}

func (i *Index) countLookup(s Status) {
	if i == nil {
		return
	}
	switch s {
	case StatusNew:
		i.lookupNew.Add(1)
	case StatusKnown:
		i.lookupKnown.Add(1)
	default:
		i.lookupUnknown.Add(1)
	}
}

// Stats is a snapshot for /metrics and doctor.
type Stats struct {
	Rows      int64
	MaxRows   int
	Inserts   uint64
	Updates   uint64
	Evictions uint64
	Dropped   map[string]uint64
	Lookups   map[Status]uint64
}

// Stats returns the counters. Safe on a nil Index, which reports zeroes.
func (i *Index) Stats() Stats {
	s := Stats{
		Dropped: map[string]uint64{},
		Lookups: map[Status]uint64{StatusNew: 0, StatusKnown: 0, StatusUnknown: 0},
	}
	for _, r := range DropReasons() {
		s.Dropped[r] = 0
	}
	if i == nil {
		return s
	}
	s.Rows = i.rows.Load()
	s.MaxRows = i.cfg.MaxRows
	s.Inserts = i.inserts.Load()
	s.Updates = i.updates.Load()
	s.Evictions = i.evictions.Load()
	s.Dropped[DropFull] = i.dropped[0].Load()
	s.Dropped[DropBudget] = i.dropped[1].Load()
	s.Dropped[DropInvalid] = i.dropped[2].Load()
	s.Dropped[DropDisabled] = i.dropped[3].Load()
	s.Lookups[StatusNew] = i.lookupNew.Load()
	s.Lookups[StatusKnown] = i.lookupKnown.Load()
	s.Lookups[StatusUnknown] = i.lookupUnknown.Load()
	return s
}

// Config returns the limits in force, for diagnostics.
func (i *Index) Config() Config {
	if i == nil {
		return Config{}
	}
	return i.cfg
}
