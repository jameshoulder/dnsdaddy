package blocklist

import (
	"context"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestF05OversizedLocalPreservesCache(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "feed")
	if err := os.WriteFile(p, []byte("good.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h := newManagerHarness(t, func(c *config.Feeds) { c.LocalFeedDir = root; c.MaxFeedBytes = 64 })
	f := h.addFeed(t, "local", "file://"+p, "malware", "domains")
	if err := h.mgr.RefreshFeed(context.Background(), f.ID); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(h.mgr.cachePath(f.ID))
	if err := os.WriteFile(p, []byte(strings.Repeat("bad.example\n", 20)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.mgr.RefreshFeed(context.Background(), f.ID); err == nil {
		t.Error("oversized local accepted")
	}
	after, _ := os.ReadFile(h.mgr.cachePath(f.ID))
	if string(before) != string(after) {
		t.Error("rejected source replaced cache")
	}
}

func TestF05LateParseFailureDoesNotPublish(t *testing.T) {
	h := newManagerHarness(t, func(c *config.Feeds) { c.MaxFeedBytes = 2 << 20 })
	f := h.addFeed(t, "cache", "https://fixture.example/feed", "malware", "domains")
	if err := os.WriteFile(h.mgr.cachePath(f.ID), []byte("partial.example\n"+strings.Repeat("x", (1<<20)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	_ = h.mgr.LoadFromCache(context.Background())
	if h.holder.Load().Len() != 0 {
		t.Fatal("failed feed partially published")
	}
}
