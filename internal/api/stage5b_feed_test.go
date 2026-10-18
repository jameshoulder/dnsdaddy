package api

import (
	"context"
	"encoding/json"
	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestStage5BFeedOutcomeSurvivesHistoryFailure(t *testing.T) {
	h := newHarness(t)
	h.login()
	ctx := context.Background()
	if _, e := h.store.DB().Exec("UPDATE feeds SET enabled=0"); e != nil {
		t.Fatal(e)
	}
	cfg := config.Default().Feeds
	cfg.LocalFeedDir = h.dir
	manager, e := blocklist.NewManager(h.store, h.lists, cfg, h.dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	defer manager.Close()
	h.api.Feeds = manager
	h.store.SetLocalFeedDir(h.dir)
	source := filepath.Join(h.dir, "synthetic-feed")
	if e = os.WriteFile(source, []byte("committed.example\n"), 0600); e != nil {
		t.Fatal(e)
	}
	name, url, category, format := "synthetic", "file://"+source, "malware", "domains"
	f, e := h.store.CreateFeed(ctx, store.FeedInput{Name: &name, URL: &url, Category: &category, Format: &format})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.store.DB().Exec(`CREATE TRIGGER fail_stage5b_history BEFORE UPDATE OF last_refreshed_at ON feeds BEGIN SELECT RAISE(ABORT,'synthetic'); END`); e != nil {
		t.Fatal(e)
	}
	if e = manager.RefreshFeed(ctx, f.ID); e == nil {
		t.Fatal("history failure hidden")
	}
	response, b := h.do("GET", "/api/v1/feeds", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
	var result struct {
		Last *blocklist.FeedOutcome `json:"lastFeedOutcome"`
	}
	if e = json.Unmarshal(b, &result); e != nil {
		t.Fatal(e)
	}
	if result.Last == nil || result.Last.FeedID != f.ID || !result.Last.Committed || result.Last.Status != "committed-warning" || result.Last.Error == "" {
		t.Fatal("API concealed committed publication warning")
	}
	if _, ok := h.lists.Load().Lookup("committed.example"); !ok {
		t.Fatal("published protection absent")
	}
}
