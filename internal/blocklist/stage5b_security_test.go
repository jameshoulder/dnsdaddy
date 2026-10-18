package blocklist

import (
	"context"
	"errors"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStage5BFailedUpdatePreservesPublication(t *testing.T) {
	for _, failure := range []string{"malformed", "records", "rename", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "feed")
			ctx := context.Background()
			h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root; c.ImportLimits.Records = 2 })
			f := h.addFeed(t, "synthetic", "file://"+source, "malware", "observatory")
			good := `{"indicators":[{"value":"old.example","type":"domain","categories":["malware"]}]}`
			if e := os.WriteFile(source, []byte(good), 0600); e != nil {
				t.Fatal(e)
			}
			if e := h.mgr.RefreshFeed(ctx, f.ID); e != nil {
				t.Fatal(e)
			}
			before := h.holder.Load()
			gen := h.holder.Generation()
			cache, e := os.ReadFile(h.mgr.cachePath(f.ID))
			if e != nil {
				t.Fatal(e)
			}
			state, e := h.store.GetFeed(ctx, f.ID)
			if e != nil {
				t.Fatal(e)
			}
			data := `{"indicators":[{"value":"new.example","type":"domain","categories":["malware"]}]}`
			switch failure {
			case "malformed":
				data = `{"indicators":[{"value":"new.example","type":"domain"},`
			case "records":
				data = `{"indicators":[{"value":"one.example","type":"domain"},{"value":"two.example","type":"domain"},{"value":"three.example","type":"domain"}]}`
			case "rename":
				h.mgr.cacheRoot = &faultCache{cacheFilesystem: h.mgr.cacheRoot, renameErr: true}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if e = os.WriteFile(source, []byte(data), 0600); e != nil {
				t.Fatal(e)
			}
			if e = h.mgr.RefreshFeed(ctx, f.ID); e == nil {
				t.Fatal("failure hidden")
			}
			after, e := os.ReadFile(h.mgr.cachePath(f.ID))
			if e != nil || string(cache) != string(after) {
				t.Fatal("failed update changed cache")
			}
			if h.holder.Load() != before || h.holder.Generation() != gen {
				t.Fatal("failed update changed published index")
			}
			if _, ok := h.holder.Load().Lookup("old.example"); !ok {
				t.Fatal("DNS blocking data lost")
			}
			final, e := h.store.GetFeed(context.Background(), f.ID)
			if e != nil || final.LastSuccess == nil || !final.LastSuccess.Equal(*state.LastSuccess) {
				t.Fatal("failed refresh changed success timestamp")
			}
			if failure != "cancel" {
				out := h.mgr.LastFeedOutcome()
				if out == nil || out.Committed || out.Error == "" {
					t.Fatal("failure outcome inaccurate")
				}
			}
			assertNoStaging(t, h.mgr)
		})
	}
}

func TestStage5BHistoryFailureReportsCommitted(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "feed")
	ctx := context.Background()
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root })
	f := h.addFeed(t, "synthetic", "file://"+source, "malware", "domains")
	if e := os.WriteFile(source, []byte("committed.example\n"), 0600); e != nil {
		t.Fatal(e)
	}
	// Simulate a metadata write failure after the filesystem commit point.
	if _, e := h.store.DB().Exec(`CREATE TRIGGER fail_refresh_history BEFORE UPDATE OF last_refreshed_at ON feeds BEGIN SELECT RAISE(ABORT,'synthetic failure'); END`); e != nil {
		t.Fatal(e)
	}
	e := h.mgr.RefreshFeed(ctx, f.ID)
	if e == nil || !strings.Contains(e.Error(), "committed=true") {
		t.Fatal("committed result not explicit", e)
	}
	if _, ok := h.holder.Load().Lookup("committed.example"); !ok {
		t.Fatal("committed content missing")
	}
	out := h.mgr.LastFeedOutcome()
	if out == nil || !out.Committed || out.Status != "committed-warning" || out.Error == "" {
		t.Fatal("runtime warning lost when history unavailable")
	}
	if _, e = h.store.DB().Exec("DROP TRIGGER fail_refresh_history"); e != nil {
		t.Fatal(e)
	}
	if e = h.mgr.RefreshFeed(ctx, f.ID); e != nil {
		t.Fatal("repeat committed refresh", e)
	}
}

func TestStage5BCorruptOtherFeedCannotDropPublishedClaims(t *testing.T) {
	root := t.TempDir()
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root })
	ctx := context.Background()
	ids := []string{}
	for i, name := range []string{"one", "two"} {
		source := filepath.Join(root, name)
		if e := os.WriteFile(source, []byte(name+".example\n"), 0600); e != nil {
			t.Fatal(e)
		}
		f := h.addFeed(t, name, "file://"+source, "malware", "domains")
		ids = append(ids, f.ID)
		if e := h.mgr.RefreshFeed(ctx, ids[i]); e != nil {
			t.Fatal(e)
		}
	}
	before := h.holder.Load()
	gen := h.holder.Generation()
	if e := os.Remove(h.mgr.cachePath(ids[0])); e != nil {
		t.Fatal(e)
	}
	if e := h.mgr.RefreshFeed(ctx, ids[1]); e == nil {
		t.Fatal("refresh dropped missing published feed")
	}
	if h.holder.Load() != before || h.holder.Generation() != gen || h.holder.Load().Len() != 2 {
		t.Fatal("previous protection not retained")
	}
}

type cancelGenerationCache struct {
	cacheFilesystem
	cancel context.CancelFunc
}

func (c *cancelGenerationCache) OpenFile(n string, flag int, mode os.FileMode) (*os.File, error) {
	f, e := c.cacheFilesystem.OpenFile(n, flag, mode)
	if !strings.HasPrefix(n, ".download-") {
		c.cancel()
	}
	return f, e
}
func TestStage5BCancellationDuringCandidate(t *testing.T) {
	h := newManagerHarness(t)
	ctx := context.Background()
	f := h.addFeed(t, "cached", "https://fixture.example/feed", "malware", "domains")
	if e := os.WriteFile(h.mgr.cachePath(f.ID), []byte("old.example\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := h.mgr.LoadFromCache(ctx); e != nil {
		t.Fatal(e)
	}
	before := h.holder.Load()
	gen := h.holder.Generation()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	h.mgr.cacheRoot = &cancelGenerationCache{cacheFilesystem: h.mgr.cacheRoot, cancel: cancel}
	if e := h.mgr.LoadFromCache(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal("generation cancellation hidden", e)
	}
	if h.holder.Load() != before || h.holder.Generation() != gen {
		t.Fatal("canceled candidate published")
	}
}

func TestStage5BCloseJoinsQueuedLoadsAndRefresh(t *testing.T) {
	for n := 0; n < 10; n++ {
		h := newManagerHarness(t)
		f := h.addFeed(t, "cached", "https://fixture.example/feed", "malware", "domains")
		// Hold ingestion so cache loading, refresh and Close contend. All methods
		// must acquire lifecycle protection before the ingestion lock, never invert it.
		h.mgr.ingestMu.Lock()
		started := make(chan struct{}, 2)
		done := make(chan error, 3)
		go func() { started <- struct{}{}; done <- h.mgr.LoadFromCache(context.Background()) }()
		go func() { started <- struct{}{}; done <- h.mgr.RefreshFeed(context.Background(), f.ID) }()
		<-started
		<-started
		go func() { done <- h.mgr.Close() }()
		deadline := time.Now().Add(time.Second)
		for !h.mgr.closing.Load() {
			if time.Now().After(deadline) {
				h.mgr.ingestMu.Unlock()
				t.Fatal("Close did not begin")
			}
			runtime.Gosched()
		}
		h.mgr.ingestMu.Unlock()
		timer := time.NewTimer(3 * time.Second)
		for i := 0; i < 3; i++ {
			select {
			case <-done:
			case <-timer.C:
				t.Fatal("Close/ingestion lock ordering blocked")
			}
		}
		timer.Stop()
	}
}

func TestStage5BNotModifiedWarningKeepsActualCount(t *testing.T) {
	h := newManagerHarness(t)
	ctx := context.Background()
	f := h.addFeed(t, "cached", "https://fixture.example/feed", "malware", "domains")
	if e := os.WriteFile(h.mgr.cachePath(f.ID), []byte("one.example\ntwo.example\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := h.mgr.LoadFromCache(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := h.store.DB().Exec(`CREATE TRIGGER fail_count BEFORE UPDATE OF domain_count ON feeds WHEN NEW.last_status=OLD.last_status BEGIN SELECT RAISE(ABORT,'synthetic count failure'); END`); e != nil {
		t.Fatal(e)
	}
	result := h.mgr.finishRefresh(ctx, f, store.FeedResult{Status: "not-modified", ETag: "synthetic-v1"})
	if !result.Committed || result.Error == "" || result.DomainCount != 2 {
		t.Fatal("304 warning lost actual contribution")
	}
	after, e := h.store.GetFeed(ctx, f.ID)
	if e != nil || after.DomainCount != 2 || after.LastSuccess == nil || after.LastStatus != "committed-warning" {
		t.Fatal("304 warning corrupted persisted count")
	}
}
