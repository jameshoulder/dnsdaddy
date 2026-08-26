package blocklist

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func ptr[T any](v T) *T { return &v }

type managerHarness struct {
	mgr    *Manager
	store  *store.Store
	holder *Holder
	dir    string
}

func newManagerHarness(t *testing.T, opts ...func(*config.Feeds)) *managerHarness {
	t.Helper()

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	// Disable every seeded feed so tests only see what they add themselves and
	// never reach a third-party provider.
	feeds, err := st.ListFeeds(context.Background())
	if err != nil {
		t.Fatalf("ListFeeds: %v", err)
	}
	for _, f := range feeds {
		if _, err := st.UpdateFeed(context.Background(), f.ID, store.FeedInput{Enabled: ptr(false)}); err != nil {
			t.Fatalf("disable %s: %v", f.ID, err)
		}
	}

	cfg := config.Feeds{
		HTTPTimeout:  config.Duration(10 * time.Second),
		MaxFeedBytes: 1 << 20,
	}
	for _, o := range opts {
		o(&cfg)
	}
	st.SetLocalFeedDir(cfg.LocalFeedDir)

	holder := NewHolder()
	mgr, err := NewManager(st, holder, cfg, dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	return &managerHarness{mgr: mgr, store: st, holder: holder, dir: dir}
}

func (h *managerHarness) addFeed(t *testing.T, name, url, category, format string) store.Feed {
	t.Helper()
	f, err := h.store.CreateFeed(context.Background(), store.FeedInput{
		Name: &name, URL: &url, Category: &category, Format: &format, Enabled: ptr(true),
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	return f
}

func TestRefreshDownloadsAndIndexes(t *testing.T) {
	body := "0.0.0.0 evil.com\n0.0.0.0 phish.example\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	defer srv.Close()

	h := newManagerHarness(t)
	f := h.addFeed(t, "Test", srv.URL, "malware", "hosts")

	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	ix := h.holder.Load()
	if ix.Len() != 2 {
		t.Fatalf("indexed %d domains, want 2", ix.Len())
	}
	if _, ok := ix.Lookup("login.evil.com"); !ok {
		t.Error("a subdomain of an indexed domain does not match")
	}

	stored, err := h.store.GetFeed(context.Background(), f.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if stored.LastStatus != "ok" || stored.LastError != "" {
		t.Errorf("feed status = %q, error = %q", stored.LastStatus, stored.LastError)
	}
	if stored.LastRefresh == nil {
		t.Error("last refresh time was not recorded")
	}
	if stored.DomainCount != 2 {
		t.Errorf("DomainCount = %d, want 2", stored.DomainCount)
	}
}

func TestRefreshCachesToDiskForOfflineRestart(t *testing.T) {
	// The cache is what lets a restart protect traffic before the first HTTP
	// request goes out, and what stops a provider outage leaving a booting
	// server with an empty blocklist.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "0.0.0.0 evil.com\n")
	}))

	h := newManagerHarness(t)
	h.addFeed(t, "Test", srv.URL, "malware", "hosts")

	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("server hit %d times, want 1", hits.Load())
	}

	// The provider is now unreachable, as after a reboot during an outage.
	srv.Close()

	fresh := NewHolder()
	mgr2, err := NewManager(h.store, fresh, config.Feeds{
		HTTPTimeout:  config.Duration(2 * time.Second),
		MaxFeedBytes: 1 << 20,
	}, h.dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if err := mgr2.LoadFromCache(context.Background()); err != nil {
		t.Fatalf("LoadFromCache: %v", err)
	}
	if _, ok := fresh.Load().Lookup("evil.com"); !ok {
		t.Error("the cached feed was not reloaded; a restart would leave the network unprotected")
	}
	if hits.Load() != 1 {
		t.Error("LoadFromCache made a network request")
	}
}

func TestRefreshFallsBackToCacheOnFailure(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "upstream on fire", http.StatusInternalServerError)
			return
		}
		io.WriteString(w, "0.0.0.0 evil.com\n")
	}))
	defer srv.Close()

	h := newManagerHarness(t)
	f := h.addFeed(t, "Test", srv.URL, "malware", "hosts")

	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}

	fail.Store(true)
	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh should not fail outright when one feed is down: %v", err)
	}

	// One unreachable provider must degrade one category, not the whole index.
	if _, ok := h.holder.Load().Lookup("evil.com"); !ok {
		t.Error("a failed download dropped domains that were already cached")
	}

	stored, err := h.store.GetFeed(context.Background(), f.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if stored.LastError == "" {
		t.Error("the download failure was not surfaced against the feed")
	}
}

func TestRefreshHonoursETag(t *testing.T) {
	const etag = `"v1"`
	var fullSends atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fullSends.Add(1)
		w.Header().Set("ETag", etag)
		io.WriteString(w, "0.0.0.0 evil.com\n")
	}))
	defer srv.Close()

	h := newManagerHarness(t)
	h.addFeed(t, "Test", srv.URL, "malware", "hosts")

	for i := 0; i < 3; i++ {
		if err := h.mgr.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh %d: %v", i, err)
		}
	}

	if fullSends.Load() != 1 {
		t.Errorf("feed body was sent %d times, want 1 — the ETag is not being used", fullSends.Load())
	}
	if _, ok := h.holder.Load().Lookup("evil.com"); !ok {
		t.Error("a 304 response lost the cached content")
	}
}

func TestRefreshRejectsOversizedFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 5000; i++ {
			io.WriteString(w, "0.0.0.0 padding-padding-padding.example\n")
		}
	}))
	defer srv.Close()

	h := newManagerHarness(t)
	h.mgr.cfg.MaxFeedBytes = 1024
	f := h.addFeed(t, "Huge", srv.URL, "malware", "hosts")

	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	stored, err := h.store.GetFeed(context.Background(), f.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if stored.LastError == "" {
		t.Error("an oversized feed was accepted")
	}
	if h.holder.Load().Len() != 0 {
		t.Error("an oversized feed was partially indexed; a truncated list is a silently weaker one")
	}
}

func TestDisabledFeedIsNotIndexed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "0.0.0.0 evil.com\n")
	}))
	defer srv.Close()

	h := newManagerHarness(t)
	f := h.addFeed(t, "Test", srv.URL, "malware", "hosts")

	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if h.holder.Load().Len() != 1 {
		t.Fatal("precondition failed: the feed should be indexed")
	}

	if _, err := h.store.UpdateFeed(context.Background(), f.ID, store.FeedInput{Enabled: ptr(false)}); err != nil {
		t.Fatalf("UpdateFeed: %v", err)
	}
	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh after disable: %v", err)
	}

	if h.holder.Load().Len() != 0 {
		t.Error("a disabled feed is still contributing domains")
	}
}

func TestCategoryPriorityDecidesTheReason(t *testing.T) {
	// A domain on both a malware feed and an ad feed must be reported as
	// malware, so the reason in the query log is the one that matters.
	adSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "0.0.0.0 shared.example\n")
	}))
	defer adSrv.Close()
	malwareSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "0.0.0.0 shared.example\n")
	}))
	defer malwareSrv.Close()

	h := newManagerHarness(t)
	h.addFeed(t, "Ads", adSrv.URL, "ads", "hosts")
	h.addFeed(t, "Malware", malwareSrv.URL, "malware", "hosts")

	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	entry, ok := h.holder.Load().Lookup("shared.example")
	if !ok {
		t.Fatal("the shared domain was not indexed")
	}
	if entry.Category != "malware" {
		t.Errorf("category = %q, want malware (higher severity claims the domain first)", entry.Category)
	}
}

func TestRefreshBumpsGeneration(t *testing.T) {
	// The generation is what invalidates cached answers, so a newly listed
	// domain stops resolving immediately instead of lingering for a TTL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "0.0.0.0 evil.com\n")
	}))
	defer srv.Close()

	h := newManagerHarness(t)
	h.addFeed(t, "Test", srv.URL, "malware", "hosts")

	before := h.holder.Generation()
	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if h.holder.Generation() == before {
		t.Error("the generation did not advance after a refresh")
	}
}

func TestFileURLFeedInsideLocalFeedDir(t *testing.T) {
	feedDir := t.TempDir()
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = feedDir })

	path := filepath.Join(feedDir, "local.txt")
	if err := os.WriteFile(path, []byte("internal-bad.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.addFeed(t, "Local", "file://"+path, "malware", "domains")

	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, ok := h.holder.Load().Lookup("internal-bad.example"); !ok {
		t.Error("a file:// feed was not indexed")
	}
}

// A feed URL arrives over the management API, so an unconfined file:// feed is
// an arbitrary-file-read primitive for anyone holding a session or a token.
func TestFileURLFeedIsConfinedToLocalFeedDir(t *testing.T) {
	feedDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("stolen.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("disabled by default", func(t *testing.T) {
		h := newManagerHarness(t)
		_, err := h.store.CreateFeed(context.Background(), store.FeedInput{
			Name: ptr("Local"), URL: ptr("file://" + outside),
			Category: ptr("malware"), Format: ptr("domains"),
		})
		if err == nil {
			t.Fatal("a file:// feed was accepted with no local_feed_dir configured")
		}
	})

	t.Run("outside the directory", func(t *testing.T) {
		h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = feedDir })
		_, err := h.store.CreateFeed(context.Background(), store.FeedInput{
			Name: ptr("Local"), URL: ptr("file://" + outside),
			Category: ptr("malware"), Format: ptr("domains"),
		})
		if err == nil {
			t.Fatal("a file:// feed outside local_feed_dir was accepted")
		}
	})

	t.Run("traversal out of the directory", func(t *testing.T) {
		h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = feedDir })
		_, err := h.store.CreateFeed(context.Background(), store.FeedInput{
			Name: ptr("Local"), URL: ptr("file://" + filepath.Join(feedDir, "..", filepath.Base(filepath.Dir(outside)), "secret.txt")),
			Category: ptr("malware"), Format: ptr("domains"),
		})
		if err == nil {
			t.Fatal("a file:// feed using .. to escape local_feed_dir was accepted")
		}
	})

	t.Run("symlink out of the directory", func(t *testing.T) {
		h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = feedDir })
		link := filepath.Join(feedDir, "escape.txt")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		defer os.Remove(link)

		// The link passes the lexical check — only resolving it catches this.
		_, err := h.store.CreateFeed(context.Background(), store.FeedInput{
			Name: ptr("Local"), URL: ptr("file://" + link),
			Category: ptr("malware"), Format: ptr("domains"),
		})
		if err == nil {
			t.Fatal("a symlink escaping local_feed_dir was accepted")
		}
	})
}

func TestConcurrentRefreshIsRejected(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		io.WriteString(w, "0.0.0.0 evil.com\n")
	}))
	defer srv.Close()

	h := newManagerHarness(t)
	h.addFeed(t, "Slow", srv.URL, "malware", "hosts")

	done := make(chan error, 1)
	go func() { done <- h.mgr.Refresh(context.Background()) }()

	// Wait until the first refresh has actually started.
	deadline := time.Now().Add(3 * time.Second)
	for !h.mgr.Refreshing() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !h.mgr.Refreshing() {
		t.Fatal("the first refresh never started")
	}

	if err := h.mgr.Refresh(context.Background()); err == nil {
		t.Error("a second concurrent refresh was allowed")
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
}

func TestRefreshIndexesObservatoryPerIndicatorCategories(t *testing.T) {
	// The point of the Observatory format: one feed row contributes to several
	// categories at once, so a policy that enables phishing but not cryptomining
	// blocks the phishing indicators and nothing else.
	body := `{
	  "generated_at": "2026-08-26T09:15:00Z",
	  "source": "dnsdaddy-threat-observatory",
	  "indicators": [
	    {"value": "c2.example", "type": "domain", "severity": "critical", "categories": ["c2"]},
	    {"value": "phish.example", "type": "domain", "severity": "high", "categories": ["phishing"]},
	    {"value": "miner.example", "type": "domain", "severity": "medium", "categories": ["cryptojacking"]},
	    {"value": "odd.example", "type": "domain", "severity": "low", "categories": ["never-heard-of-it"]},
	    {"value": "multi.example", "type": "domain", "severity": "critical", "categories": ["c2", "ransomware"]}
	  ]
	}`
	var accept atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept.Store(r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	defer srv.Close()

	h := newManagerHarness(t)
	f := h.addFeed(t, "Observatory", srv.URL, "malware", "observatory")

	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if got, _ := accept.Load().(string); got != "application/json" {
		t.Errorf("Accept header = %q, want application/json", got)
	}

	ix := h.holder.Load()
	want := map[string]string{
		"c2.example":    "c2",
		"phish.example": "phishing",
		"miner.example": "cryptomining",
		// An unrecognised label falls back to the feed's own category rather
		// than losing the block to a vocabulary mismatch.
		"odd.example": "malware",
	}
	for domain, category := range want {
		entry, ok := ix.Lookup(domain)
		if !ok {
			t.Errorf("%s was not indexed", domain)
			continue
		}
		if entry.Category != category {
			t.Errorf("%s category = %q, want %q", domain, entry.Category, category)
		}
		if entry.FeedName != "Observatory" {
			t.Errorf("%s feed name = %q, want Observatory", domain, entry.FeedName)
		}
		// Each domain is reachable by the one category it carries, and by no
		// other — the feed row's category does not leak onto every indicator.
		if _, ok := ix.LookupEnabled(domain, map[string]bool{category: true}); !ok {
			t.Errorf("%s is not blocked by a %s-only policy", domain, category)
		}
	}

	// The multi-label indicator is filed under both of its categories, so a
	// policy enabling either one blocks it.
	if got := ix.Categories("multi.example"); !slices.Equal(got, []string{"malware", "c2"}) {
		t.Errorf("multi.example categories = %v, want [malware c2]", got)
	}
	for _, only := range []string{"malware", "c2"} {
		if _, ok := ix.LookupEnabled("multi.example", map[string]bool{only: true}); !ok {
			t.Errorf("multi.example is not blocked by a %s-only policy", only)
		}
	}
	if _, ok := ix.LookupEnabled("multi.example", map[string]bool{"ads": true}); ok {
		t.Error("multi.example was blocked by a policy enabling neither of its categories")
	}

	// Subdomains match, as for any other feed.
	if _, ok := ix.Lookup("login.phish.example"); !ok {
		t.Error("a subdomain of an Observatory indicator does not match")
	}

	stored, err := h.store.GetFeed(context.Background(), f.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if stored.LastStatus != "ok" || stored.LastError != "" {
		t.Errorf("feed status = %q, error = %q", stored.LastStatus, stored.LastError)
	}
	// Five distinct domains, though six claims were made across them.
	if stored.DomainCount != 5 {
		t.Errorf("DomainCount = %d, want 5", stored.DomainCount)
	}
}

func TestTruncatedObservatoryNeverReplacesLastKnownGood(t *testing.T) {
	// The regression this exists to prevent: a feed that downloads cleanly, then
	// comes back truncated on the next refresh, must not take the intelligence
	// from the first download with it. A partial feed is not a smaller feed —
	// it is thousands of malicious domains quietly becoming resolvable again.
	good := `{"generated_at": "2026-08-26T09:15:00Z", "indicators": [
	  {"value": "first.example", "type": "domain", "categories": ["c2"]},
	  {"value": "second.example", "type": "domain", "categories": ["phishing"]},
	  {"value": "third.example", "type": "domain", "categories": ["malware"]}
	]}`
	truncated := `{"generated_at": "2026-08-26T21:15:00Z", "indicators": [
	  {"value": "first.example", "type": "domain", "categ`

	var serveTruncated atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveTruncated.Load() {
			io.WriteString(w, truncated)
			return
		}
		io.WriteString(w, good)
	}))
	defer srv.Close()

	h := newManagerHarness(t)
	f := h.addFeed(t, "Observatory", srv.URL, "malware", "observatory")
	ctx := context.Background()

	if err := h.mgr.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := h.holder.Load().Len(); got != 3 {
		t.Fatalf("indexed %d domains after the good download, want 3", got)
	}
	cached, err := os.ReadFile(h.mgr.cachePath(f.ID))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}

	// The provider now serves a truncated body with a perfectly good HTTP 200.
	serveTruncated.Store(true)
	if err := h.mgr.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Every domain from the last known good dataset is still blocking.
	ix := h.holder.Load()
	if ix.Len() != 3 {
		t.Errorf("indexed %d domains after the truncated download, want all 3 retained", ix.Len())
	}
	for _, d := range []string{"first.example", "second.example", "third.example"} {
		if _, ok := ix.Lookup(d); !ok {
			t.Errorf("%s stopped being blocked after a truncated refresh", d)
		}
	}

	// The cache on disk was not replaced, so a restart still recovers it.
	after, err := os.ReadFile(h.mgr.cachePath(f.ID))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if string(after) != string(cached) {
		t.Error("the truncated download overwrote the cached copy")
	}

	// And the failure is reported against that feed rather than passing as ok.
	stored, err := h.store.GetFeed(ctx, f.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if stored.LastStatus != "error" {
		t.Errorf("feed status = %q, want error", stored.LastStatus)
	}
	if stored.LastError == "" {
		t.Error("a truncated download recorded no error for the operator to see")
	}
}

func TestObservatoryRejectsNonFeedBodyServedAs200(t *testing.T) {
	// A proxy or a captive portal answering with an HTML page and status 200 is
	// a complete document that is not a feed. It must not replace the cache
	// either — the failure mode is identical.
	var serveHTML atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveHTML.Load() {
			io.WriteString(w, "<!DOCTYPE html><html><body>Sign in to continue</body></html>")
			return
		}
		io.WriteString(w, `{"indicators": [{"value": "evil.example", "type": "domain", "categories": ["c2"]}]}`)
	}))
	defer srv.Close()

	h := newManagerHarness(t)
	f := h.addFeed(t, "Observatory", srv.URL, "malware", "observatory")
	ctx := context.Background()

	if err := h.mgr.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	serveHTML.Store(true)
	if err := h.mgr.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if _, ok := h.holder.Load().Lookup("evil.example"); !ok {
		t.Error("an HTML error page served as 200 wiped the blocklist")
	}
	stored, _ := h.store.GetFeed(ctx, f.ID)
	if stored.LastStatus != "error" {
		t.Errorf("feed status = %q, want error", stored.LastStatus)
	}
}

func TestObservatoryFeedIsSeededDisabled(t *testing.T) {
	// Every source a default install blocks from is one an operator can fetch
	// themselves. Ours is opt-in, and a refactor must not quietly flip that.
	h := newManagerHarness(t)

	found := false
	for _, f := range catalog.DefaultFeeds {
		if f.ID != catalog.ObservatoryFeedID {
			continue
		}
		found = true
		if f.Enabled {
			t.Error("the Threat Observatory feed is seeded enabled; it must be opt-in")
		}
		if f.Format != string(FormatObservatory) {
			t.Errorf("Observatory feed format = %q, want %q", f.Format, FormatObservatory)
		}
		if f.URL != catalog.ObservatoryFeedURL {
			t.Errorf("Observatory feed URL = %q, want %q", f.URL, catalog.ObservatoryFeedURL)
		}
	}
	if !found {
		t.Fatal("the Threat Observatory feed is not in the shipped catalog")
	}

	// It is seeded into the database too, so it appears in the dashboard for an
	// operator to turn on.
	feeds, err := h.store.ListFeeds(context.Background())
	if err != nil {
		t.Fatalf("ListFeeds: %v", err)
	}
	for _, f := range feeds {
		if f.ID == catalog.ObservatoryFeedID {
			if !f.Builtin {
				t.Error("the Observatory feed should be marked built-in")
			}
			return
		}
	}
	t.Error("the Observatory feed was not seeded into the store")
}

func TestObservatoryDoesNotDowngradeAnotherFeedsClaim(t *testing.T) {
	// The Observatory sorts among the malware feeds, so it is read first. Its
	// indicators carry their own categories, though, so it can claim a domain
	// as cryptomining that a later malware feed also lists. The malware claim
	// has to win — otherwise enabling the Observatory would stop a policy that
	// blocks malware but not cryptomining from blocking that domain at all.
	observatory := `{"indicators": [
	  {"value": "shared.example", "type": "domain", "severity": "high", "categories": ["cryptojacking"]},
	  {"value": "onlyhere.example", "type": "domain", "severity": "high", "categories": ["c2"]}
	]}`
	obsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, observatory)
	}))
	defer obsSrv.Close()

	malSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "0.0.0.0 shared.example\n")
	}))
	defer malSrv.Close()

	h := newManagerHarness(t)
	obs := h.addFeed(t, "Observatory", obsSrv.URL, "malware", "observatory")
	mal := h.addFeed(t, "URLhaus-alike", malSrv.URL, "malware", "hosts")

	if err := h.mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	ix := h.holder.Load()
	entry, ok := ix.Lookup("shared.example")
	if !ok {
		t.Fatal("shared.example was not indexed")
	}
	if entry.Category != "malware" {
		t.Errorf("shared.example category = %q, want malware", entry.Category)
	}

	// The Observatory keeps what only it lists.
	if e, ok := ix.Lookup("onlyhere.example"); !ok || e.Category != "c2" {
		t.Errorf("onlyhere.example = %+v, %v; want a c2 entry", e, ok)
	}

	// The stored per-feed counts reflect what each feed actually holds in the
	// finished index, including the domain the Observatory lost.
	ctx := context.Background()
	obsStored, err := h.store.GetFeed(ctx, obs.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if obsStored.DomainCount != 1 {
		t.Errorf("Observatory DomainCount = %d, want 1 (it lost shared.example)", obsStored.DomainCount)
	}
	malStored, err := h.store.GetFeed(ctx, mal.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if malStored.DomainCount != 1 {
		t.Errorf("malware feed DomainCount = %d, want 1", malStored.DomainCount)
	}
}
