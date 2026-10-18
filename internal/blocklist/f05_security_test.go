package blocklist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/feedimport"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestF05RootedDescriptorPolicy(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if e := os.WriteFile(sentinel, []byte("outside.example\n"), 0600); e != nil {
		t.Fatal(e)
	}
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root })
	if e := os.WriteFile(filepath.Join(root, "good"), []byte("inside.example\n"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name, target string
		ok           bool
	}{{"relative", "good", true}, {"outside", sentinel, false}, {"absolute-inside", filepath.Join(root, "good"), false}, {"loop", "loop", false}} {
		if e := os.Symlink(tc.target, filepath.Join(root, tc.name)); e != nil {
			t.Fatal(e)
		}
		f, e := h.mgr.openLocal("file://" + filepath.Join(root, tc.name))
		if e == nil {
			data, _ := io.ReadAll(f)
			f.Close()
			if !tc.ok || string(data) != "inside.example\n" {
				t.Fatalf("unsafe read %s", tc.name)
			}
		} else if tc.ok {
			t.Fatal(e)
		}
	}
	if e := os.Link(sentinel, filepath.Join(root, "hard")); e != nil {
		t.Fatal(e)
	}
	if e := syscall.Mkfifo(filepath.Join(root, "fifo"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"hard", "fifo", "."} {
		start := time.Now()
		f, e := h.mgr.openLocal("file://" + filepath.Join(root, name))
		if f != nil {
			f.Close()
		}
		if e == nil {
			t.Errorf("accepted %s", name)
		}
		if time.Since(start) > time.Second {
			t.Errorf("nonregular open blocked %s", name)
		}
	}
	// Root remains pinned after rename/replacement, rather than following a new
	// attacker-controlled directory at the old configured pathname.
	var e error
	moved := root + "-moved"
	if e = os.Rename(root, moved); e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(moved)
	if e = os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "good"), []byte("replacement.example\n"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := h.mgr.openLocal("file://" + filepath.Join(root, "good"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	data, _ := io.ReadAll(f)
	if string(data) != "inside.example\n" {
		t.Fatal("root was re-resolved")
	}
}

func TestF05SwappedSymlinkAndAtomicProducer(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(root, "safe"), []byte("inside.example\n"), 0600)
	os.WriteFile(filepath.Join(outside, "secret"), []byte("outside.example\n"), 0600)
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root })
	// Deterministic replacement after admission, before descriptor opening.
	p := filepath.Join(root, "new")
	if _, e := store.LocalFeedPath(root, "file://"+p); e != nil {
		t.Fatal(e)
	}
	os.Symlink(filepath.Join(outside, "secret"), p)
	if f, e := h.mgr.openLocal("file://" + p); e == nil {
		f.Close()
		t.Fatal("post-admission escape")
	}
	// A pinned descriptor remains on the old version after producer atomic rename.
	f, e := h.mgr.openLocal("file://" + filepath.Join(root, "safe"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	os.WriteFile(filepath.Join(root, "next"), []byte("new.example\n"), 0600)
	if e = os.Rename(filepath.Join(root, "next"), filepath.Join(root, "safe")); e != nil {
		t.Fatal(e)
	}
	data, _ := io.ReadAll(f)
	if string(data) != "inside.example\n" {
		t.Fatal("opened descriptor changed")
	}
	// Supplemental exchange stress: each success must read only the in-root file.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			os.Remove(filepath.Join(root, "swap-next"))
			target := "safe"
			if i%2 == 0 {
				target = filepath.Join(outside, "secret")
			}
			os.Symlink(target, filepath.Join(root, "swap-next"))
			os.Rename(filepath.Join(root, "swap-next"), filepath.Join(root, "swap"))
		}
		close(done)
	}()
	for i := 0; i < 200; i++ {
		g, e := h.mgr.openLocal("file://" + filepath.Join(root, "swap"))
		if e == nil {
			b, _ := io.ReadAll(g)
			g.Close()
			if bytes.Contains(b, []byte("outside")) {
				t.Fatal("symlink escape")
			}
		}
	}
	<-done
	wg.Wait()
}

func TestF05ParserBounds(t *testing.T) {
	for _, body := range []string{`{"indicators":[{"value":"good.example"}],"source":"` + strings.Repeat("x", maxJSONValue) + `"}`, `{"indicators":[],"unknown":` + strings.Repeat("[", 65) + `0` + strings.Repeat("]", 65) + `}`, `[{"value":"good.example"},`, `{"indicators":[]} trailing`, `{"indicators":[],"indicators":[]}`} {
		if _, e := parseObservatoryLimited(context.Background(), strings.NewReader(body), 10, nil); e == nil {
			t.Fatal("invalid/over-limit JSON accepted")
		}
	}
	for _, body := range []string{"junk\njunk\njunk\n", "#comment\n\n#comment\n", "same.example\nsame.example\nsame.example\n"} {
		if _, _, e := parseLines(context.Background(), strings.NewReader(body), FormatDomains, 2, func(string) error { return nil }); !errors.Is(e, feedimport.ErrLimit) {
			t.Fatal(e)
		}
	}
	if _, e := parseObservatoryLimited(context.Background(), strings.NewReader(`[null,null,null]`), 2, nil); !errors.Is(e, feedimport.ErrLimit) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, _, e := parseLines(ctx, strings.NewReader("one.example\ntwo.example\n"), FormatDomains, 10, func(string) error { calls++; cancel(); return nil })
	if !errors.Is(e, context.Canceled) || calls != 1 {
		t.Fatal(calls, e)
	}
}

type cancelReader struct {
	cancel context.CancelFunc
	calls  int
}

func (r *cancelReader) Read(b []byte) (int, error) {
	r.calls++
	copy(b, "synthetic.example\n")
	r.cancel()
	return len("synthetic.example\n"), nil
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestF05BoundedCopy(t *testing.T) {
	for _, n := range []int{31, 32, 33} {
		var out bytes.Buffer
		written, e := copyBounded(context.Background(), &out, strings.NewReader(strings.Repeat("x", n)), 32)
		if n <= 32 {
			if e != nil || written != int64(n) {
				t.Fatal(n, written, e)
			}
		} else if !errors.Is(e, feedimport.ErrLimit) || out.Len() > 32 {
			t.Fatal(written, e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &cancelReader{cancel: cancel}
	var out bytes.Buffer
	if _, e := copyBounded(ctx, &out, r, 1024); !errors.Is(e, context.Canceled) || r.calls != 1 {
		t.Fatal(r.calls, e)
	}
	if _, e := copyBounded(context.Background(), shortWriter{}, strings.NewReader("abc"), 10); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal(e)
	}
}

func TestF05RejectedSnapshotsAndCleanup(t *testing.T) {
	for _, tc := range []struct{ name, format, bad string }{{"late-line", "domains", "bad.example\n" + strings.Repeat("x", (1<<20)+1)}, {"truncated", "observatory", `{"indicators":[{"value":"bad.example"},`}, {"records", "domains", "a.example\na.example\na.example\n"}, {"empty", "domains", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, "feed")
			good := "good.example\n"
			if tc.format == "observatory" {
				good = `{"indicators":[{"value":"good.example"}]}`
			}
			os.WriteFile(p, []byte(good), 0600)
			h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root; c.MaxFeedBytes = 2 << 20; c.ImportLimits.Records = 2 })
			f := h.addFeed(t, "local", "file://"+p, "malware", tc.format)
			if e := h.mgr.RefreshFeed(context.Background(), f.ID); e != nil {
				t.Fatal(e)
			}
			before, _ := os.ReadFile(h.mgr.cachePath(f.ID))
			state, _ := h.store.GetFeed(context.Background(), f.ID)
			os.WriteFile(p, []byte(tc.bad), 0600)
			if e := h.mgr.RefreshFeed(context.Background(), f.ID); e == nil {
				t.Fatal("bad snapshot accepted")
			}
			after, _ := os.ReadFile(h.mgr.cachePath(f.ID))
			if !bytes.Equal(before, after) {
				t.Fatal("cache overwritten")
			}
			if _, ok := h.holder.Load().Lookup("good.example"); !ok {
				t.Fatal("good index lost")
			}
			if _, ok := h.holder.Load().Lookup("bad.example"); ok {
				t.Fatal("partial index")
			}
			now, _ := h.store.GetFeed(context.Background(), f.ID)
			if now.LastSuccess == nil || state.LastSuccess == nil || !now.LastSuccess.Equal(*state.LastSuccess) {
				t.Fatal("false success")
			}
			assertNoStaging(t, h.mgr)
		})
	}
}
func assertNoStaging(t *testing.T, m *Manager) {
	t.Helper()
	entries, e := os.ReadDir(m.dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".download-") {
			t.Fatal("temporary file leak", entry.Name())
		}
	}
}

func TestF05AggregateBudgetBeforePromotion(t *testing.T) {
	root := t.TempDir()
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root; c.ImportLimits.Domains = 2 })
	for i := 0; i < 2; i++ {
		p := filepath.Join(root, fmt.Sprint(i))
		os.WriteFile(p, []byte(fmt.Sprintf("d%d.example\n", i)), 0600)
		f := h.addFeed(t, "local", "file://"+p, "malware", "domains")
		if e := h.mgr.RefreshFeed(context.Background(), f.ID); e != nil {
			t.Fatal(e)
		}
	}
	p := filepath.Join(root, "over")
	os.WriteFile(p, []byte("third.example\n"), 0600)
	f := h.addFeed(t, "local", "file://"+p, "malware", "domains")
	if e := h.mgr.RefreshFeed(context.Background(), f.ID); e == nil {
		t.Fatal("aggregate budget bypass")
	}
	if _, e := os.Stat(h.mgr.cachePath(f.ID)); !os.IsNotExist(e) {
		t.Fatal("over-budget snapshot promoted")
	}
	if h.holder.Load().Len() != 2 {
		t.Fatal("old holder lost")
	}
	assertNoStaging(t, h.mgr)
}

func TestF05TemporaryQuotaAndCancellation(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "feed")
	os.WriteFile(p, []byte("good.example\n"), 0600)
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root; c.ImportLimits.TempBytes = 32 })
	f := h.addFeed(t, "local", "file://"+p, "malware", "domains")
	orphan := filepath.Join(h.mgr.dir, ".download-orphan")
	os.WriteFile(orphan, make([]byte, 30), 0600)
	if e := h.mgr.RefreshFeed(context.Background(), f.ID); e == nil {
		t.Fatal("orphan quota ignored")
	}
	if _, e := os.Stat(orphan); e != nil {
		t.Fatal("orphan deleted")
	}
	os.Remove(orphan)
	assertNoStaging(t, h.mgr)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := h.mgr.RefreshFeed(ctx, f.ID); e == nil {
		t.Fatal("cancellation ignored")
	}
	if h.mgr.Refreshing() {
		t.Fatal("refresh slot leaked")
	}
	assertNoStaging(t, h.mgr)
	if e := h.mgr.RefreshFeed(context.Background(), f.ID); e != nil {
		t.Fatal(e)
	}
}

func TestF05CacheLimitsRetainHolder(t *testing.T) {
	h := newManagerHarness(t, func(c *config.Feeds) { c.ImportLimits.Records = 2 })
	f := h.addFeed(t, "cache", "https://fixture.example/feed", "malware", "domains")
	os.WriteFile(h.mgr.cachePath(f.ID), []byte("good.example\n"), 0600)
	if e := h.mgr.LoadFromCache(context.Background()); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(h.mgr.cachePath(f.ID), []byte("bad.example\nbad.example\nbad.example\n"), 0600)
	if e := h.mgr.LoadFromCache(context.Background()); !errors.Is(e, feedimport.ErrLimit) {
		t.Fatal(e)
	}
	if _, ok := h.holder.Load().Lookup("good.example"); !ok {
		t.Fatal("active index lost on resource error")
	}
}

func TestF05SyntheticCapacity(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "feed")
	file, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(file, "capacity-%d.example\n", i)
	}
	file.Close()
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root })
	f := h.addFeed(t, "capacity", "file://"+p, "malware", "domains")
	if e := h.mgr.RefreshFeed(context.Background(), f.ID); e != nil {
		t.Fatal(e)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	peak.Store(before.HeapAlloc)
	done := make(chan struct{})
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				var sample runtime.MemStats
				runtime.ReadMemStats(&sample)
				if sample.HeapAlloc > peak.Load() {
					peak.Store(sample.HeapAlloc)
				}
			}
		}
	}()
	defer func() { close(done); <-joined }()
	start := time.Now()
	if e := h.mgr.RefreshFeed(context.Background(), f.ID); e != nil {
		t.Fatal(e)
	}
	runtime.ReadMemStats(&after)
	if h.holder.Load().Len() != 20000 {
		t.Fatal("capacity content lost")
	}
	if after.HeapAlloc > peak.Load() {
		peak.Store(after.HeapAlloc)
	}
	if peak.Load()-before.HeapAlloc > uint64(h.mgr.limits.MemoryBytes) {
		t.Fatal("synthetic heap growth exceeded accounting budget")
	}
	t.Logf("synthetic records=20000 replacement elapsed=%s heap-before=%d heap-after=%d sampled-peak=%d allocated=%d index-accounting=%d budget=%d (1ms samples; not strict peak/RSS/quota)", time.Since(start), before.HeapAlloc, after.HeapAlloc, peak.Load(), after.TotalAlloc-before.TotalAlloc, indexCharge(h.holder.Load()), h.mgr.limits.MemoryBytes)
}

func FuzzF05JSONFraming(f *testing.F) {
	for _, s := range []string{`{null :0,"indicators":[]}`, `{"indicators":[]}`, `[{"value":"good.example"}]`, `{"source":"\\\"","indicators":[null]}`, `{"unknown":[{}],"indicators":[]}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 2<<20 {
			t.Skip()
		}
		_, err := parseObservatoryLimited(context.Background(), strings.NewReader(s), 20, nil)
		if err == nil && !json.Valid([]byte(s)) {
			t.Fatal("framer accepted syntactically invalid JSON")
		}
	})
}

func TestF05IntermediateDirectoryReplacement(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, "sub"), 0700); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(root, "sub", "feed")
	os.WriteFile(p, []byte("safe.example\n"), 0600)
	os.WriteFile(filepath.Join(outside, "feed"), []byte("outside.example\n"), 0600)
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root })
	if _, e := store.LocalFeedPath(root, "file://"+p); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(filepath.Join(root, "sub"), filepath.Join(root, "old")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(root, "sub")); e != nil {
		t.Fatal(e)
	}
	if f, e := h.mgr.openLocal("file://" + p); e == nil {
		f.Close()
		t.Fatal("intermediate escape accepted")
	}
}
func TestF05SparseAndTimeout(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "sparse")
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(1025); e != nil {
		t.Fatal(e)
	}
	f.Close()
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root; c.MaxFeedBytes = 1024 })
	if f, e = h.mgr.openLocal("file://" + p); e == nil {
		f.Close()
		t.Fatal("oversized sparse file accepted")
	}
	h2 := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root; c.ImportLimits.Timeout = "1ns" })
	feed := h2.addFeed(t, "timeout", "file://"+p, "malware", "domains")
	if e = h2.mgr.RefreshFeed(context.Background(), feed.ID); e == nil {
		t.Fatal("local timeout ignored")
	}
	if h2.mgr.Refreshing() {
		t.Fatal("timeout leaked slot")
	}
	assertNoStaging(t, h2.mgr)
}
func TestF05ClaimAndMemoryAccounting(t *testing.T) {
	h := newManagerHarness(t, func(c *config.Feeds) { c.ImportLimits.Claims = 1 })
	b := NewBuilder(1024)
	budget := h.mgr.newBudget()
	e := Entry{Category: "malware", FeedID: "synthetic"}
	if err := h.mgr.addBounded(b, budget, "one.example", e); err != nil {
		t.Fatal(err)
	}
	e.Category = "phishing"
	if err := h.mgr.addBounded(b, budget, "one.example", e); !errors.Is(err, feedimport.ErrLimit) {
		t.Fatal(err)
	}
	if len(b.ix.extra["one.example"]) != 0 {
		t.Fatal("claim mutated before limit check")
	}
	b = NewBuilder(1024)
	budget = &importBudget{used: 1023, limit: 1024}
	if err := h.mgr.addBounded(b, budget, "two.example", e); !errors.Is(err, feedimport.ErrLimit) {
		t.Fatal(err)
	}
	if b.ix.Len() != 0 {
		t.Fatal("memory limit mutated candidate")
	}
	b = NewBuilder(int(^uint(0) >> 1))
	if b.ix.Len() != 0 {
		t.Fatal("invalid hint")
	}
}

type faultCache struct {
	cacheFilesystem
	renameErr    bool
	syncDirErr   bool
	opens        int
	beforeRename func()
	onStageStat  func()
}

func (f *faultCache) Lstat(n string) (os.FileInfo, error) {
	info, e := f.cacheFilesystem.Lstat(n)
	if strings.HasPrefix(n, ".download-") && f.onStageStat != nil {
		f.onStageStat()
	}
	return info, e
}

func (f *faultCache) Rename(a, b string) error {
	if f.beforeRename != nil {
		f.beforeRename()
	}
	if f.renameErr {
		return errors.New("synthetic rename failure")
	}
	return f.cacheFilesystem.Rename(a, b)
}
func (f *faultCache) Open(n string) (*os.File, error) {
	f.opens++
	if f.syncDirErr && f.opens == 2 {
		return nil, errors.New("synthetic directory durability failure")
	}
	return f.cacheFilesystem.Open(n)
}
func TestF05CommitFailures(t *testing.T) {
	for _, post := range []bool{false, true} {
		t.Run(fmt.Sprint(post), func(t *testing.T) {
			h := newManagerHarness(t)
			f := h.addFeed(t, "cache", "https://fixture.example/feed", "malware", "domains")
			if e := os.WriteFile(h.mgr.cachePath(f.ID), []byte("old.example\n"), 0600); e != nil {
				t.Fatal(e)
			}
			if e := h.mgr.LoadFromCache(context.Background()); e != nil {
				t.Fatal(e)
			}
			h.mgr.cacheRoot = &faultCache{cacheFilesystem: h.mgr.cacheRoot, renameErr: !post, syncDirErr: post}
			res := h.mgr.snapshot(context.Background(), f, strings.NewReader("new.example\n"), nil, "")
			if res.Error == "" {
				t.Fatal("failure hidden")
			}
			cache, e := os.ReadFile(h.mgr.cachePath(f.ID))
			if e != nil {
				t.Fatal(e)
			}
			want := "old.example"
			if post {
				want = "new.example"
				if !strings.Contains(res.Error, "committed") {
					t.Fatal("post-commit error claims rollback")
				}
			}
			if !strings.Contains(string(cache), want) {
				t.Fatal("wrong committed state")
			}
			if _, ok := h.holder.Load().Lookup(want); !ok {
				t.Fatal("holder does not match committed state")
			}
			assertNoStaging(t, h.mgr)
		})
	}
}

type mutatingReader struct {
	r      io.Reader
	once   sync.Once
	mutate func()
}

func (r *mutatingReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	r.once.Do(r.mutate)
	return n, e
}
func TestF05DetectsSourceMutation(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "feed")
	os.WriteFile(p, []byte("old.example\n"), 0600)
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root })
	f := h.addFeed(t, "local", "file://"+p, "malware", "domains")
	src, e := h.mgr.openLocal(f.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer src.Close()
	r := &mutatingReader{r: src, mutate: func() {
		if e := os.WriteFile(p, []byte("different-length.example\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}}
	res := h.mgr.snapshot(context.Background(), f, r, src, "")
	if res.Error == "" {
		t.Fatal("mutation accepted")
	}
	if _, e := os.Stat(h.mgr.cachePath(f.ID)); !os.IsNotExist(e) {
		t.Fatal("changed source committed")
	}
	assertNoStaging(t, h.mgr)
}
func TestF05ConcurrentImportsAndCacheRebuilds(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "feed")
	os.WriteFile(p, []byte("good.example\n"), 0600)
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root })
	f := h.addFeed(t, "local", "file://"+p, "malware", "domains")
	run, e := h.mgr.BeginRefreshFeed(f.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.mgr.BeginRefreshFeed(f.ID); e == nil {
		t.Fatal("concurrent import slot admitted")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if e := h.mgr.LoadFromCache(context.Background()); e != nil {
				t.Error(e)
			}
		}
	}()
	if e = run(context.Background()); e != nil {
		t.Fatal(e)
	}
	wg.Wait()
	if _, ok := h.holder.Load().Lookup("good.example"); !ok {
		t.Fatal("concurrent publication lost feed")
	}
	assertNoStaging(t, h.mgr)
}

func TestF05CancellationAtCommitBoundary(t *testing.T) {
	for _, afterCheck := range []bool{false, true} {
		t.Run(fmt.Sprint(afterCheck), func(t *testing.T) {
			h := newManagerHarness(t)
			f := h.addFeed(t, "cache", "https://fixture.example/feed", "malware", "domains")
			os.WriteFile(h.mgr.cachePath(f.ID), []byte("old.example\n"), 0600)
			if e := h.mgr.LoadFromCache(context.Background()); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fault := &faultCache{cacheFilesystem: h.mgr.cacheRoot}
			if afterCheck {
				fault.beforeRename = cancel
			} else {
				fault.onStageStat = cancel
			}
			h.mgr.cacheRoot = fault
			res := h.mgr.snapshot(ctx, f, strings.NewReader("new.example\n"), nil, "")
			want := "old.example"
			if afterCheck {
				want = "new.example"
				if res.Error != "" {
					t.Fatal("committed snapshot falsely rejected", res)
				}
			} else if res.Error == "" {
				t.Fatal("pre-commit cancellation ignored")
			}
			b, e := os.ReadFile(h.mgr.cachePath(f.ID))
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(string(b), want) {
				t.Fatal("cache not at commit boundary")
			}
			if _, ok := h.holder.Load().Lookup(want); !ok {
				t.Fatal("holder/cache disagreement")
			}
			assertNoStaging(t, h.mgr)
		})
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("synthetic read failure") }
func TestF05ReadFailureAndFailedRecordAccounting(t *testing.T) {
	root := t.TempDir()
	h := newManagerHarness(t, func(c *config.Feeds) {
		c.LocalFeedDir = root
		c.ImportLimits.Records = 2
		c.ImportLimits.LocalRecords = 3
	})
	p := filepath.Join(root, "feed")
	os.WriteFile(p, []byte("#one\n#two\n#three\n"), 0600)
	f := h.addFeed(t, "local", "file://"+p, "malware", "domains")
	res := h.mgr.snapshot(context.Background(), f, io.MultiReader(strings.NewReader("partial.example\n"), failedReader{}), nil, "")
	if res.Error == "" {
		t.Fatal("read failure accepted")
	}
	assertNoStaging(t, h.mgr)
	if res = h.mgr.copyLocal(context.Background(), f); res.Error == "" {
		t.Fatal("excess records accepted")
	}
	if h.mgr.localRecords != 3 {
		t.Fatal("failed parse escaped accounting", h.mgr.localRecords)
	}
	os.WriteFile(p, []byte("now-valid.example\n"), 0600)
	if res = h.mgr.copyLocal(context.Background(), f); res.Error == "" {
		t.Fatal("failed records did not exhaust refresh budget")
	}
	assertNoStaging(t, h.mgr)
}

type canceledBody struct {
	ctx     context.Context
	started chan struct{}
	once    sync.Once
}

func (b *canceledBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (b *canceledBody) Close() error { return nil }
func TestF05CloseCancelsAndJoinsCleanup(t *testing.T) {
	h := newManagerHarness(t)
	f := h.addFeed(t, "shutdown", "https://fixture.example/feed", "malware", "domains")
	started := make(chan struct{})
	h.mgr.client.Transport = stage1RoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &canceledBody{ctx: r.Context(), started: started}, Request: r}, nil
	})
	done := make(chan error, 1)
	go func() { done <- h.mgr.RefreshFeed(context.Background(), f.ID) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("controlled reader did not start")
	}
	if e := h.mgr.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("shutdown import reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("manager operation not joined")
	}
	assertNoStaging(t, h.mgr)
	if h.mgr.Refreshing() {
		t.Fatal("refresh slot leaked on close")
	}
	if e := h.mgr.LoadFromCache(context.Background()); e == nil {
		t.Fatal("closed manager admitted work")
	}
}

// No socket/device nodes are opened. The offline sandbox does not permit a
// Unix-domain fixture socket; classify synthetic descriptor metadata instead.
type modeInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (i modeInfo) Mode() os.FileMode { return i.mode }
func TestF05SpecialDescriptorClassification(t *testing.T) {
	p := filepath.Join(t.TempDir(), "regular")
	if e := os.WriteFile(p, []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []os.FileMode{os.ModeSocket, os.ModeDevice, os.ModeDevice | os.ModeCharDevice, os.ModeNamedPipe, os.ModeDir} {
		if _, e := validateFeedInfo(modeInfo{info, mode}, 1024); e == nil {
			t.Fatal("special descriptor accepted", mode)
		}
	}
}
