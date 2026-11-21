package blocklist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/feedimport"
)

func TestFeedChecksumEvidenceAndLastGoodRetention(t *testing.T) {
	h := newManagerHarness(t)
	ctx := context.Background()
	body := []byte("evil.example\nother.example\n")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	f := h.addFeed(t, "checksum-feed", srv.URL+"/list.txt", "malware", "domains")
	if err := h.mgr.RefreshFeed(ctx, f.ID); err != nil {
		t.Fatalf("RefreshFeed: %v", err)
	}
	got, err := h.store.GetFeed(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ContentSHA256 != digest || got.LastGoodSHA256 != digest {
		t.Fatalf("checksum evidence: got content=%q lastGood=%q want %q", got.ContentSHA256, got.LastGoodSHA256, digest)
	}
	if got.ParserAccepted < 1 {
		t.Fatalf("expected parser accepts, got %d", got.ParserAccepted)
	}
	if got.RefreshSourceURL == "" {
		t.Fatal("refresh source URL missing")
	}

	if err := os.WriteFile(h.mgr.cachePath(f.ID), []byte("tampered.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.mgr.rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	load := h.mgr.FeedLoads()[f.ID]
	if load.Loaded {
		t.Fatal("tampered cache was loaded despite checksum mismatch")
	}
	if load.Error == "" {
		t.Fatal("expected load error for checksum mismatch")
	}
	after, err := h.store.GetFeed(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastGoodSHA256 != digest {
		t.Fatalf("last good checksum changed after tamper: %q", after.LastGoodSHA256)
	}
}

func TestVerifyCachedChecksumRejectsOversizedBeforeHash(t *testing.T) {
	h := newManagerHarness(t, func(cfg *config.Feeds) {
		cfg.MaxFeedBytes = 64
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	path := h.mgr.cachePath("oversized")
	if err := os.WriteFile(path, make([]byte, 128), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = verifyCachedChecksum(ctx, f, "deadbeef", h.mgr.maxBytes)
	if err == nil {
		t.Fatal("accepted oversized cache for hashing")
	}
	if errors.Is(err, errChecksumMismatch) {
		t.Fatal("hashed oversized cache instead of rejecting on size")
	}
	if !errors.Is(err, feedimport.ErrLimit) {
		t.Fatalf("want feed byte limit, got %v", err)
	}
}
