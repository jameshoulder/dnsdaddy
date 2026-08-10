package blocklist

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

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
