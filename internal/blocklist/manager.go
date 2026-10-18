package blocklist

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/feedimport"
	"github.com/jameshoulder/dnsdaddy/internal/feedpolicy"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/jameshoulder/dnsdaddy/internal/version"
)

// Manager downloads threat-intelligence feeds, caches them on disk, and
// rebuilds the in-memory index.
//
// Every feed is cached to disk after a successful download. That means a
// restart rebuilds the index from local files in a second or two without
// touching the network — the resolver is protecting traffic before the first
// HTTP request goes out, and a provider being down never leaves a booting
// server with an empty blocklist.
type Manager struct {
	store           *store.Store
	holder          *Holder
	cfg             config.Feeds
	dir             string
	log             *slog.Logger
	client          *http.Client
	policy          *feedpolicy.Policy
	limits          feedimport.Limits
	maxBytes        int64
	localTimeout    time.Duration
	cacheRoot       cacheFilesystem
	localMu         sync.Mutex
	localRoot       *os.Root
	closed          bool
	localRecords    int
	lifecycle       sync.RWMutex
	closing         atomic.Bool
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	outcome     atomic.Pointer[FeedOutcome]
	refreshing  atomic.Bool
	lastRefresh atomic.Int64 // unix milli
	mu          sync.Mutex
	ingestMu    sync.Mutex // bounds validation/build overlap, including cache loads

	// loads is what the live index is actually made of, keyed by feed ID and
	// replaced wholesale on every rebuild. See FeedLoads.
	loads atomic.Pointer[map[string]FeedLoad]
}

// FeedOutcome is runtime evidence for the latest completed feed operation.
// It remains truthful when SQLite cannot persist refresh history.
type FeedOutcome struct {
	FeedID    string `json:"feedId"`
	Status    string `json:"status"`
	Committed bool   `json:"committed"`
	Error     string `json:"error,omitempty"`
}

func (m *Manager) LastFeedOutcome() *FeedOutcome {
	p := m.outcome.Load()
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// FeedLoad says whether a feed's cached copy made it into the index that is
// serving traffic right now.
//
// This is runtime state, not history, and the difference matters. A feed row
// records that a download succeeded; it cannot record that the file that
// download produced has since gone missing, been truncated by a full disk, or
// failed to parse on the way into the index at boot. In that situation the
// database says the feed is fine and the resolver is not blocking a single one
// of its domains. Anything that reports protection to an operator has to read
// this, not the timestamps.
type FeedLoad struct {
	// Loaded is true when this feed's cached copy was read into the current
	// index. It says nothing about how many domains survived de-duplication.
	Loaded bool
	// Error explains why not, in terms an operator can act on. Empty when
	// Loaded is true.
	Error string
}

// FeedLoads returns what the current index was built from, keyed by feed ID.
// Feeds that are disabled, or that have never been through a rebuild, are
// absent — which callers must read as "not loaded".
func (m *Manager) FeedLoads() map[string]FeedLoad {
	p := m.loads.Load()
	if p == nil {
		return map[string]FeedLoad{}
	}
	return *p
}

// describeLoadError turns a cache-load failure into something worth showing an
// operator. A missing file is by far the most common case and says nothing
// useful in its raw form — it is a path inside the server's data directory and
// an errno.
//
// The wording has to hold for both feeds that were never downloaded and feeds
// whose cached copy has since gone: "missing" is true of both, where "never
// downloaded" would contradict a refresh timestamp the operator can see.
func describeLoadError(err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return "its cached copy is missing"
	}
	// Parser and filesystem errors may contain publisher-controlled field names,
	// response text, or paths. Only emit application-controlled classifications.
	if errors.Is(err, os.ErrPermission) {
		return "its cached copy cannot be read (permission denied)"
	}
	return "its cached copy is unreadable or invalid"
}

// NewManager constructs a feed manager writing its cache under dataDir/feeds.
func NewManager(st *store.Store, holder *Holder, cfg config.Feeds, dataDir string, log *slog.Logger) (*Manager, error) {
	limits, maxBytes, localTimeout, err := cfg.ImportLimits.Normalize(cfg.MaxFeedBytes)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(dataDir, "feeds")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create feed cache dir: %w", err)
	}
	timeout := cfg.HTTPTimeout.D()
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	policy, err := feedpolicy.New(cfg.NetworkRules)
	if err != nil {
		return nil, err
	}
	cacheRoot, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errors.New("cannot open feed cache root")
	}
	info, err := cacheRoot.Stat(".")
	if err != nil || info.Mode().Perm()&0022 != 0 || !ownedByService(info) {
		cacheRoot.Close()
		return nil, errors.New("feed cache directory must be service-owned and not group/world writable")
	}
	st.SetFeedPolicy(policy)
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	return &Manager{store: st, holder: holder, cfg: cfg, dir: dir, log: log, policy: policy, client: policy.NewClient(timeout), limits: limits, maxBytes: maxBytes, localTimeout: localTimeout, cacheRoot: cacheRoot, lifecycleCtx: lifecycleCtx, lifecycleCancel: lifecycleCancel}, nil
}

// LoadFromCache rebuilds the index from disk without any network access.
// Feeds with no cached copy are skipped.
func (m *Manager) LoadFromCache(ctx context.Context) error {
	opCtx, done, err := m.beginOperation(ctx)
	if err != nil {
		return err
	}
	ctx = opCtx
	defer done()
	m.ingestMu.Lock()
	defer m.ingestMu.Unlock()
	return m.rebuild(ctx)
}

// Refresh downloads every enabled feed and rebuilds the index. Feeds that fail
// to download fall back to their cached copy, so a single unreachable provider
// degrades one category rather than the whole blocklist.
func (m *Manager) Refresh(ctx context.Context) error {
	opCtx, done, err := m.beginOperation(ctx)
	if err != nil {
		return err
	}
	ctx = opCtx
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	release, err := m.beginRefresh()
	if err != nil {
		return err
	}
	defer release()
	m.ingestMu.Lock()
	defer m.ingestMu.Unlock()
	m.localRecords = 0

	feeds, err := m.store.ListFeeds(ctx)
	if err != nil {
		return err
	}

	failures, committed := 0, 0
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		if ctx.Err() != nil {
			return fmt.Errorf("feed refresh interrupted (%d feeds committed): %w", committed, ctx.Err())
		}
		res := m.download(ctx, f)
		res = m.finishRefresh(ctx, f, res)
		if res.Committed {
			committed++
		}
		if res.Error != "" {
			failures++
			m.log.Warn("feed refresh outcome", "feed", f.ID, "committed", res.Committed, "error", res.Error)
		}
	}
	if failures != 0 {
		return fmt.Errorf("feed refresh incomplete: %d failed or warned; %d feeds committed; previous published protection retained for failures", failures, committed)
	}
	if committed == 0 {
		if err := m.rebuild(ctx); err != nil {
			return err
		}
	}
	m.lastRefresh.Store(time.Now().UnixMilli())
	return nil
}

// beginRefresh claims the single refresh slot, returning the function that
// gives it back. Refreshes are serialised because they all end in a full index
// rebuild, and two rebuilds racing would have one of them swap in an index
// built from a half-updated cache directory.
func (m *Manager) beginRefresh() (func(), error) {
	if !m.refreshing.CompareAndSwap(false, true) {
		return nil, errors.New("a feed refresh is already running")
	}
	return func() { m.refreshing.Store(false) }, nil
}

// RefreshFeed downloads one feed and rebuilds the index, leaving every other
// feed's cached copy exactly as it was.
//
// This is the same download, validation, caching and index-rebuild path
// Refresh uses — it just narrows what is fetched. It exists because a full
// refresh pulls a dozen third-party lists and takes minutes, which is the
// wrong thing to make an operator sit through when they have just switched one
// feed on and want to know whether it works.
func (m *Manager) RefreshFeed(ctx context.Context, feedID string) error {
	run, err := m.BeginRefreshFeed(feedID)
	if err != nil {
		return err
	}
	return run(ctx)
}

// BeginRefreshFeed claims the refresh slot for one feed and returns the
// function that performs the refresh and releases the slot again.
//
// Splitting the claim from the work lets a caller answer an HTTP request
// immediately and do the download in the background, while still guaranteeing
// that a status poll issued the moment that response lands already reports a
// refresh in progress. Refreshing() flipping true only once the goroutine got
// scheduled would let the dashboard read "idle" and paint a stale card.
//
// The returned function must be called exactly once, and the slot stays
// claimed until it returns.
func (m *Manager) BeginRefreshFeed(feedID string) (func(context.Context) error, error) {
	release, err := m.beginRefresh()
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) error {
		defer release()
		m.localRecords = 0
		return m.refreshOne(ctx, feedID)
	}, nil
}

// refreshOne downloads feedID and rebuilds the index. The caller holds the
// refresh slot.
func (m *Manager) refreshOne(ctx context.Context, feedID string) error {
	opCtx, done, err := m.beginOperation(ctx)
	if err != nil {
		return err
	}
	ctx = opCtx
	defer done()
	m.ingestMu.Lock()
	defer m.ingestMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	feeds, err := m.store.ListFeeds(ctx)
	if err != nil {
		return err
	}

	var target *store.Feed
	for i := range feeds {
		if feeds[i].ID == feedID {
			target = &feeds[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("unknown feed %q", feedID)
	}
	if !target.Enabled {
		return fmt.Errorf("feed %q is disabled", feedID)
	}

	res := m.finishRefresh(ctx, *target, m.download(ctx, *target))
	if res.Error != "" {
		m.log.Warn("feed refresh outcome", "feed", target.ID, "committed", res.Committed, "error", res.Error)
		return fmt.Errorf("refresh %s (committed=%t): %s", target.ID, res.Committed, res.Error)
	}
	return nil
}

// finishRefresh never rebuilds after a committed snapshot or over a live index
// following a failed download. A cold manager may load its previous cache.
// A 304 needs a complete cached candidate before it can be reported successful.
func (m *Manager) finishRefresh(ctx context.Context, f store.Feed, res store.FeedResult) store.FeedResult {
	defer func() {
		m.outcome.Store(&FeedOutcome{FeedID: f.ID, Status: res.Status, Committed: res.Committed, Error: res.Error})
	}()

	// A manager not yet initialized may recover existing cached protection even
	// when its first provider request fails. Never rebuild away a live index.
	if res.Error != "" && m.holder.Generation() == 0 {
		if err := m.rebuildRequired(ctx, f.ID); err != nil {
			m.log.Warn("initial cached fallback unavailable")
		}
	}

	if res.Status == "not-modified" {
		if err := m.rebuildRequired(ctx, f.ID); err != nil {
			res = failedImport(err)
		} else {
			res.Committed = true
		}
	}
	recordCtx := ctx
	if res.Committed {
		// Rename/publication is authoritative even if the caller cancels now.
		var cancel context.CancelFunc
		recordCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		counts := m.holder.Load().CountsByFeed()
		res.DomainCount = counts[f.ID]
		for id, load := range m.FeedLoads() {
			if load.Loaded {
				if err := m.store.SetFeedDomainCount(recordCtx, id, counts[id]); err != nil {
					res.Status = "committed-warning"
					res.Error = "feed cache/index committed; feed counts could not be recorded"
				}
			}
		}
	}
	if err := m.store.RecordFeedRefresh(recordCtx, f.ID, res); err != nil {
		if res.Committed {
			res.Status = "committed-warning"
			res.Error = "feed cache/index committed; refresh history could not be recorded"
		} else {
			res.Status = "error"
			res.Error = "feed not committed; refresh history could not be recorded"
		}
	}
	return res
}

// Refreshing reports whether a refresh is currently running.
func (m *Manager) Refreshing() bool { return m.refreshing.Load() }

// LastRefresh returns when the last refresh finished, or the zero time.
func (m *Manager) LastRefresh() time.Time {
	ms := m.lastRefresh.Load()
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// Run refreshes on a ticker until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	interval := m.cfg.RefreshInterval.D()
	if interval <= 0 {
		<-ctx.Done()
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Refresh(ctx); err != nil && ctx.Err() == nil {
				m.log.Error("scheduled feed refresh failed", "error", err)
			}
		}
	}
}

func (m *Manager) cachePath(feedID string) string {
	// Feed IDs are generated by us (hex or catalog slugs), but a filename is
	// worth being defensive about regardless.
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, feedID)
	return filepath.Join(m.dir, safe+".list")
}

// download fetches one feed into its cache file, using the stored ETag to skip
// unchanged content.
func (m *Manager) download(ctx context.Context, f store.Feed) store.FeedResult {
	if strings.HasPrefix(f.URL, "file://") {
		return m.copyLocal(ctx, f)
	}

	if err := m.policy.ValidateURL(f.URL); err != nil {
		return store.FeedResult{Status: "error", Error: feedpolicy.Failure(err)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return store.FeedResult{Status: "error", Error: "feed content or cache operation failed"}
	}
	req.Header.Set("User-Agent", "dnsdaddy/"+version.String()+" (+https://github.com/jameshoulder/dnsdaddy)")
	if Format(f.Format) == FormatObservatory {
		req.Header.Set("Accept", "application/json")
	} else {
		req.Header.Set("Accept", "text/plain, */*")
	}
	if f.ETag != "" {
		req.Header.Set("If-None-Match", f.ETag)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return store.FeedResult{Status: "error", Error: feedpolicy.Failure(err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return store.FeedResult{Status: "not-modified", ETag: f.ETag}
	}
	if resp.StatusCode != http.StatusOK {
		return store.FeedResult{
			Status: "error",
			Error:  fmt.Sprintf("feed server returned HTTP %d", resp.StatusCode),
		}
	}

	return m.snapshot(ctx, f, resp.Body, nil, resp.Header.Get("ETag"))
}

// rebuild publishes only a complete bounded candidate. Ordinary corrupt feeds
// contribute nothing; resource/cancellation failures retain the entire old index.
func (m *Manager) rebuild(ctx context.Context) error {
	return m.rebuildRequired(ctx, "")
}
func (m *Manager) rebuildRequired(ctx context.Context, required string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ix, loads, err := m.candidate(ctx, "", nil, required != "")
	if err != nil {
		return err
	}
	if required != "" && !loads[required].Loaded {
		return errors.New("feed has no usable cached content")
	}
	m.holder.Store(ix)
	m.loads.Store(&loads)
	byFeed := ix.CountsByFeed()
	for id, load := range loads {
		if !load.Loaded {
			continue
		}
		if err := m.store.SetFeedDomainCount(ctx, id, byFeed[id]); err != nil {
			m.log.Warn("record feed count failed", "feed", id)
		}
	}
	m.log.Info("blocklist index rebuilt", "domains", ix.Len(), "feeds", len(loads))
	return nil
}

// sortByCategoryPriority orders feeds so higher-severity categories claim a
// domain first. A domain on both a malware feed and an ad feed should be
// reported as malware in the query log.
//
// Builder.Add enforces that outcome regardless of order — it has to, since an
// Observatory feed contributes domains at several severities. This ordering
// makes the common case cheap: the more severe claim usually arrives first, so
// the later one costs a single map lookup and nothing is rewritten.
func sortByCategoryPriority(feeds []store.Feed) {
	priority := map[string]int{}
	for i, c := range catalog.Categories {
		priority[c.ID] = i
	}
	sort.SliceStable(feeds, func(i, j int) bool {
		pi, oki := priority[feeds[i].Category]
		pj, okj := priority[feeds[j].Category]
		if !oki {
			pi = len(priority)
		}
		if !okj {
			pj = len(priority)
		}
		if pi != pj {
			return pi < pj
		}
		return feeds[i].ID < feeds[j].ID
	})
}
