package blocklist

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	store  *store.Store
	holder *Holder
	cfg    config.Feeds
	dir    string
	log    *slog.Logger
	client *http.Client

	refreshing  atomic.Bool
	lastRefresh atomic.Int64 // unix milli
	mu          sync.Mutex

	// loads is what the live index is actually made of, keyed by feed ID and
	// replaced wholesale on every rebuild. See FeedLoads.
	loads atomic.Pointer[map[string]FeedLoad]
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
	return err.Error()
}

// NewManager constructs a feed manager writing its cache under dataDir/feeds.
func NewManager(st *store.Store, holder *Holder, cfg config.Feeds, dataDir string, log *slog.Logger) (*Manager, error) {
	dir := filepath.Join(dataDir, "feeds")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create feed cache dir: %w", err)
	}
	timeout := cfg.HTTPTimeout.D()
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	return &Manager{
		store:  st,
		holder: holder,
		cfg:    cfg,
		dir:    dir,
		log:    log,
		client: &http.Client{Timeout: timeout},
	}, nil
}

// LoadFromCache rebuilds the index from disk without any network access.
// Feeds with no cached copy are skipped.
func (m *Manager) LoadFromCache(ctx context.Context) error {
	return m.rebuild(ctx, nil)
}

// Refresh downloads every enabled feed and rebuilds the index. Feeds that fail
// to download fall back to their cached copy, so a single unreachable provider
// degrades one category rather than the whole blocklist.
func (m *Manager) Refresh(ctx context.Context) error {
	release, err := m.beginRefresh()
	if err != nil {
		return err
	}
	defer release()

	feeds, err := m.store.ListFeeds(ctx)
	if err != nil {
		return err
	}

	results := make(map[string]store.FeedResult, len(feeds))
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		res := m.download(ctx, f)
		results[f.ID] = res
		if err := m.store.RecordFeedRefresh(ctx, f.ID, res); err != nil {
			m.log.Warn("record feed refresh", "feed", f.ID, "error", err)
		}
		if res.Error != "" {
			m.log.Warn("feed download failed, using cached copy if present",
				"feed", f.ID, "url", f.URL, "error", res.Error)
		}
	}

	m.lastRefresh.Store(time.Now().UnixMilli())
	return m.rebuild(ctx, results)
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
		return m.refreshOne(ctx, feedID)
	}, nil
}

// refreshOne downloads feedID and rebuilds the index. The caller holds the
// refresh slot.
func (m *Manager) refreshOne(ctx context.Context, feedID string) error {
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

	res := m.download(ctx, *target)
	if err := m.store.RecordFeedRefresh(ctx, target.ID, res); err != nil {
		m.log.Warn("record feed refresh", "feed", target.ID, "error", err)
	}
	if res.Error != "" {
		m.log.Warn("feed download failed, using cached copy if present",
			"feed", target.ID, "url", target.URL, "error", res.Error)
	}

	// The rebuild reads every enabled feed's cached file, so the other feeds
	// keep contributing exactly what they contributed before. Only this feed's
	// cache changed, and only if the download succeeded.
	//
	// Deliberately not touching m.lastRefresh: that is "when were the feeds
	// refreshed", and one feed is not the feeds. Reporting a full refresh on
	// the dashboard because a single feed was fetched would be a lie of
	// exactly the kind the freshness figure exists to prevent.
	if err := m.rebuild(ctx, map[string]store.FeedResult{target.ID: res}); err != nil {
		return err
	}
	if res.Error != "" {
		return fmt.Errorf("refresh %s: %s", target.ID, res.Error)
	}
	return nil
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
		return m.copyLocal(f)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return store.FeedResult{Status: "error", Error: err.Error()}
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
		return store.FeedResult{Status: "error", Error: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return store.FeedResult{Status: "not-modified", ETag: f.ETag}
	}
	if resp.StatusCode != http.StatusOK {
		return store.FeedResult{
			Status: "error",
			Error:  fmt.Sprintf("HTTP %d from %s", resp.StatusCode, f.URL),
		}
	}

	maxBytes := m.cfg.MaxFeedBytes
	if maxBytes <= 0 {
		maxBytes = 128 << 20
	}

	// Write to a temp file and rename, so a download interrupted halfway
	// cannot leave a truncated cache file that we would happily parse.
	tmp, err := os.CreateTemp(m.dir, ".download-*")
	if err != nil {
		return store.FeedResult{Status: "error", Error: err.Error()}
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	written, err := io.Copy(tmp, io.LimitReader(resp.Body, maxBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return store.FeedResult{Status: "error", Error: err.Error()}
	}
	if written > maxBytes {
		return store.FeedResult{
			Status: "error",
			Error:  fmt.Sprintf("feed exceeds max_feed_bytes (%d)", maxBytes),
		}
	}
	if written == 0 {
		return store.FeedResult{Status: "error", Error: "feed returned an empty body"}
	}

	if err := m.verifyDownload(f, tmpName); err != nil {
		return store.FeedResult{Status: "error", Error: err.Error()}
	}

	if err := os.Rename(tmpName, m.cachePath(f.ID)); err != nil {
		return store.FeedResult{Status: "error", Error: err.Error()}
	}
	return store.FeedResult{Status: "ok", ETag: resp.Header.Get("ETag")}
}

// verifyDownload checks a freshly downloaded file before it is allowed to
// replace the cached copy.
//
// The rename is atomic, so the cache is never half-written — but atomic is not
// the same as correct. A response can arrive complete as far as HTTP is
// concerned and still be a truncated document or an HTML error page served
// with status 200, and renaming that over a good feed would silently unblock
// everything the old copy carried. Refusing it here leaves the previous copy
// in place and surfaces the error against that one feed, which is exactly what
// happens when a provider is unreachable.
//
// Only formats that can actually be checked are checked. There is no way to
// tell a truncated hosts file from a short one — every prefix of a hosts file
// is a valid hosts file — so those keep the behaviour they have always had.
func (m *Manager) verifyDownload(f store.Feed, path string) error {
	if Format(f.Format) != FormatObservatory {
		return nil
	}

	// #nosec G304 -- path is the temp file this manager just created inside its
	// own cache directory.
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := ValidateObservatory(file); err != nil {
		return fmt.Errorf("rejected download, keeping the previous copy: %w", err)
	}
	return nil
}

func (m *Manager) copyLocal(f store.Feed) store.FeedResult {
	// Re-checked here rather than trusting the row: the URL was validated when
	// the feed was created, but local_feed_dir may have been tightened since,
	// and a symlink inside the directory can be repointed at any time.
	path, err := store.LocalFeedPath(m.cfg.LocalFeedDir, f.URL)
	if err != nil {
		return store.FeedResult{Status: "error", Error: err.Error()}
	}

	// #nosec G304 -- LocalFeedPath confines path to feeds.local_feed_dir,
	// lexically and after symlink resolution.
	src, err := os.Open(path)
	if err != nil {
		return store.FeedResult{Status: "error", Error: err.Error()}
	}
	defer src.Close()

	dst, err := os.CreateTemp(m.dir, ".download-*")
	if err != nil {
		return store.FeedResult{Status: "error", Error: err.Error()}
	}
	tmpName := dst.Name()
	defer os.Remove(tmpName)

	_, err = io.Copy(dst, src)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return store.FeedResult{Status: "error", Error: err.Error()}
	}

	// The same gate as an HTTP download, for the same reason. A file:// feed
	// is not more trustworthy for being local: it can be half-written by
	// whatever produces it, truncated by a full disk, or repointed through a
	// symlink, and renaming any of those over a good cache would silently
	// unblock everything the old copy carried.
	if err := m.verifyDownload(f, tmpName); err != nil {
		return store.FeedResult{Status: "error", Error: err.Error()}
	}

	if err := os.Rename(tmpName, m.cachePath(f.ID)); err != nil {
		return store.FeedResult{Status: "error", Error: err.Error()}
	}
	return store.FeedResult{Status: "ok"}
}

// rebuild constructs a fresh index from the cached feed files and swaps it in.
//
// The feed list is read here, inside the lock, rather than taken from the
// caller. That is the whole point: a refresh reads the feed list, then spends
// minutes downloading, and the operator can disable a feed in the meantime.
// Rebuilding from the list the refresh started with would put that feed's
// domains back into the index after the database and the dashboard both said
// it was off — blocking traffic nobody could account for, and nothing would
// correct it until the next refresh. Rebuilds are serialised on m.mu, so
// whichever one runs last reads the current configuration and has the final
// say.
func (m *Manager) rebuild(ctx context.Context, results map[string]store.FeedResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	feeds, err := m.store.ListFeeds(ctx)
	if err != nil {
		return err
	}

	enabled := make([]store.Feed, 0, len(feeds))
	for _, f := range feeds {
		if f.Enabled {
			enabled = append(enabled, f)
		}
	}
	sortByCategoryPriority(enabled)

	// Size the map from the last known counts to avoid repeated rehashing of a
	// map that will hold hundreds of thousands of keys.
	var hint int
	for _, f := range enabled {
		hint += f.DomainCount
	}
	b := NewBuilder(hint)

	// What actually went into this index, feed by feed. A feed can be enabled,
	// have downloaded successfully last week, and still contribute nothing
	// today because its cached file went missing or was damaged on disk. The
	// database cannot tell that story — it only remembers the download — so it
	// is recorded here, by the rebuild that either used the file or could not.
	loads := make(map[string]FeedLoad, len(enabled))
	loaded := make([]string, 0, len(enabled))
	for _, f := range enabled {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := m.loadInto(b, f); err != nil {
			m.log.Warn("skipping feed with no usable cached copy", "feed", f.ID, "error", err)
			loads[f.ID] = FeedLoad{Error: describeLoadError(err)}
			continue
		}
		loads[f.ID] = FeedLoad{Loaded: true}
		loaded = append(loaded, f.ID)
	}

	ix := b.Build()
	m.holder.Store(ix)
	m.loads.Store(&loads)
	m.log.Info("blocklist index rebuilt",
		"domains", ix.Len(),
		"feeds", len(enabled),
		"categories", len(ix.CountsByCategory()))

	// Persist the deduplicated per-feed contribution so the dashboard shows
	// what each feed actually adds, not what it claims to contain.
	//
	// Read back off the finished index rather than tallied while loading: a
	// later feed can take a domain off an earlier one by claiming it under a
	// more severe category, and a count taken as that earlier feed was read
	// would not know it.
	byFeed := ix.CountsByFeed()
	for _, id := range loaded {
		if results != nil {
			if r, ok := results[id]; ok && r.Error != "" {
				continue // keep the previous count alongside the error
			}
		}
		if err := m.store.SetFeedDomainCount(ctx, id, byFeed[id]); err != nil {
			m.log.Warn("record feed count", "feed", id, "error", err)
		}
	}
	return nil
}

func (m *Manager) loadInto(b *Builder, f store.Feed) (int, error) {
	// #nosec G304 -- cachePath sanitises the feed ID to [A-Za-z0-9_-] and roots
	// the result under the managed feed cache directory.
	file, err := os.Open(m.cachePath(f.ID))
	if err != nil {
		return 0, err
	}
	defer file.Close()

	if Format(f.Format) == FormatObservatory {
		return m.loadObservatoryInto(b, f, file)
	}

	entry := Entry{Category: f.Category, FeedID: f.ID, FeedName: f.Name}
	added := 0
	accepted, skipped, err := Parse(file, Format(f.Format), func(domain string) {
		if b.Add(domain, entry) {
			added++
		}
	})
	if err != nil {
		return added, err
	}
	if skipped > 0 {
		m.log.Debug("feed had unparseable lines",
			"feed", f.ID, "accepted", accepted, "skipped", skipped)
	}
	return added, nil
}

// loadObservatoryInto indexes a Threat Observatory document.
//
// Unlike a line-based feed, every indicator carries its own categories, so a
// single Observatory feed contributes to malware, phishing, C2 and
// cryptomining at once — and one indicator tagged twice is filed under both,
// so a policy enabling either category blocks it. Indicators whose labels we
// do not recognise fall back to the feed's configured category: the
// Observatory lists a domain because it wants it blocked, and dropping one
// over an unfamiliar label would lose protection to a vocabulary mismatch.
//
// The document is validated before a single domain is indexed. A cached copy
// should already be complete — download refuses to replace the cache with
// anything else — so this is the second line of that same guarantee, covering
// a file damaged on disk. A partial document contributes nothing rather than
// silently indexing half a feed.
func (m *Manager) loadObservatoryInto(b *Builder, f store.Feed, r io.ReadSeeker) (int, error) {
	if err := ValidateObservatory(r); err != nil {
		return 0, err
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}

	fallback := f.Category
	if !catalog.ValidCategory(fallback) {
		fallback = "malware"
	}

	added := 0
	res, err := ParseObservatory(r, func(rec ObservatoryRecord) {
		categories := rec.Categories
		if len(categories) == 0 {
			categories = []string{fallback}
		}
		for _, category := range categories {
			if b.Add(rec.Domain, Entry{Category: category, FeedID: f.ID, FeedName: f.Name}) {
				added++
			}
		}
	})
	if err != nil {
		// Validation passed, so reaching here means the document changed under
		// us mid-read. Report it rather than keeping a partial index.
		return added, err
	}

	if res.Skipped > 0 {
		m.log.Debug("observatory feed had unusable indicators",
			"feed", f.ID, "accepted", res.Accepted, "skipped", res.Skipped)
	}
	m.log.Info("observatory feed indexed",
		"feed", f.ID,
		"indicators", res.Accepted,
		"domains", added,
		"generated_at", res.GeneratedAt,
		"source", res.Source)
	return added, nil
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
