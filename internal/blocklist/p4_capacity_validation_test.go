package blocklist

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/feedimport"
	"os"
	"path/filepath"
	"testing"
)

// Stage5B replaces the preserved Phase4 characterization with desired behavior.
func TestStage5BCapacityConsistency(t *testing.T) {
	for _, memory := range []int64{64 << 20, 256 << 20} {
		for _, fits := range []bool{true, false} {
			for _, cached := range []bool{true, false} {
				t.Run(fmt.Sprintf("memory-%d/fits-%t/startup-%t", memory, fits, cached), func(t *testing.T) {
					root := t.TempDir()
					source := filepath.Join(root, "feed")
					h := newManagerHarness(t, func(c *config.Feeds) {
						c.LocalFeedDir = root
						c.MaxFeedBytes = 16 << 20
						c.ImportLimits.MemoryBytes = memory
					})
					f := h.addFeed(t, "capacity", "file://"+source, "malware", "domains")
					charge := claimCharge("d000000.example", Entry{Category: f.Category, FeedID: f.ID, FeedName: f.Name})
					records := int(h.mgr.indexCapacity() / charge)
					if !fits {
						records++
					}
					var data bytes.Buffer
					for i := 0; i < records; i++ {
						fmt.Fprintf(&data, "d%06d.example\n", i)
					}
					if e := os.WriteFile(source, data.Bytes(), 0600); e != nil {
						t.Fatal(e)
					}
					if cached {
						if e := os.WriteFile(h.mgr.cachePath(f.ID), data.Bytes(), 0600); e != nil {
							t.Fatal(e)
						}
					}
					before := h.holder.Load()
					gen := h.holder.Generation()
					ctx := context.Background()
					if cached {
						e := h.mgr.LoadFromCache(ctx)
						if fits && e != nil {
							t.Fatal(e)
						}
						if !fits && !errors.Is(e, feedimport.ErrLimit) {
							t.Fatal("startup limit mismatch", e)
						}
					}
					for n := 0; n < 3; n++ {
						e := h.mgr.RefreshFeed(ctx, f.ID)
						if fits {
							if e != nil {
								t.Fatal("identical refresh rejected", e)
							}
							if h.holder.Load().Len() != records {
								t.Fatal("incomplete index")
							}
							state, e := h.store.GetFeed(ctx, f.ID)
							if e != nil || state.LastSuccess == nil || state.LastError != "" || state.DomainCount != records {
								t.Fatal("success/history mismatch")
							}
						} else {
							if e == nil {
								t.Fatal("oversized refresh accepted")
							}
							if h.holder.Load() != before || h.holder.Generation() != gen {
								t.Fatal("failed refresh changed protection")
							}
							if !cached {
								if _, e := os.Stat(h.mgr.cachePath(f.ID)); !os.IsNotExist(e) {
									t.Fatal("oversized first import committed")
								}
							}
							state, e := h.store.GetFeed(ctx, f.ID)
							if e != nil || state.LastSuccess != nil || state.LastError == "" {
								t.Fatal("failure/history mismatch")
							}
						}
						assertNoStaging(t, h.mgr)
					}
					t.Logf("budget=%d capacity=%d records=%d fits=%t startup=%t", memory, h.mgr.indexCapacity(), records, fits, cached)
				})
			}
		}
	}
}

// Replay the exact sizing formula and feed bytes from the Phase4 reproduction.
func TestStage5BOriginalP4CorpusRejectedConsistently(t *testing.T) {
	for _, memory := range []int64{64 << 20, 256 << 20} {
		t.Run(fmt.Sprint(memory), func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "feed")
			h := newManagerHarness(t, func(c *config.Feeds) {
				c.LocalFeedDir = root
				c.MaxFeedBytes = 16 << 20
				c.ImportLimits.MemoryBytes = memory
			})
			f := h.addFeed(t, "capacity", "file://"+source, "malware", "domains")
			charge := claimCharge("d000000.example", Entry{Category: f.Category, FeedID: f.ID, FeedName: f.Name})
			records := int(((memory - (32 << 20)) * 2 / 5) / charge)
			var data bytes.Buffer
			for i := 0; i < records; i++ {
				fmt.Fprintf(&data, "d%06d.example\n", i)
			}
			for _, path := range []string{source, h.mgr.cachePath(f.ID)} {
				if e := os.WriteFile(path, data.Bytes(), 0600); e != nil {
					t.Fatal(e)
				}
			}
			ctx := context.Background()
			before := h.holder.Load()
			gen := h.holder.Generation()
			if e := h.mgr.LoadFromCache(ctx); !errors.Is(e, feedimport.ErrLimit) {
				t.Fatal("startup decision differs", e)
			}
			if e := h.mgr.RefreshFeed(ctx, f.ID); e == nil {
				t.Fatal("oversized refresh accepted")
			}
			if e := os.Remove(h.mgr.cachePath(f.ID)); e != nil {
				t.Fatal(e)
			}
			if e := h.mgr.RefreshFeed(ctx, f.ID); e == nil {
				t.Fatal("oversized first import accepted")
			}
			if _, e := os.Stat(h.mgr.cachePath(f.ID)); !os.IsNotExist(e) {
				t.Fatal("failed first import committed cache")
			}
			if h.holder.Load() != before || h.holder.Generation() != gen {
				t.Fatal("oversized candidate published")
			}
			state, e := h.store.GetFeed(ctx, f.ID)
			if e != nil || state.LastSuccess != nil || state.LastError == "" {
				t.Fatal("oversized candidate recorded success")
			}
			assertNoStaging(t, h.mgr)
			t.Logf("original P4 corpus records=%d charge=%d budget=%d: startup/refresh/first-import reject consistently without commit", records, charge, memory)
		})
	}
}
