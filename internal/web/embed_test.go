package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

func TestDashboardFingerprintsFollowEmbeddedAssets(t *testing.T) {
	input := fstest.MapFS{
		"index.html": {Data: []byte(`<link href="/app.css"><script src="/app.js"></script>`)},
		"app.js":     {Data: []byte("old script")}, "app.css": {Data: []byte("body{}")},
	}
	before, etags, err := dashboardIndex(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(before, []byte("/app.js?v=")) || !bytes.Contains(before, []byte("/app.css?v=")) || etags["app.js"] == "" {
		t.Fatalf("missing fingerprints: %s", before)
	}
	input["app.js"].Data = []byte("new script")
	after, later, err := dashboardIndex(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) || etags["app.js"] == later["app.js"] {
		t.Fatal("a different binary's script reused the old cache key")
	}
	if etags["app.css"] != later["app.css"] {
		t.Fatal("unchanged CSS should retain its content hash")
	}
}

func TestDashboardServesRevalidatableAssetsAndActual404s(t *testing.T) {
	h := Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("index response: %d %v", w.Code, w.Header())
	}
	match := regexp.MustCompile(`src="(/app.js\?v=[0-9a-f]{16})"`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("served HTML does not select its own embedded script")
	}
	asset := httptest.NewRecorder()
	h.ServeHTTP(asset, httptest.NewRequest("GET", match[1], nil))
	if asset.Code != 200 || asset.Header().Get("ETag") == "" || !strings.Contains(asset.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("script response: %d %v", asset.Code, asset.Header())
	}
	r := httptest.NewRequest("GET", match[1], nil)
	r.Header.Set("If-None-Match", asset.Header().Get("ETag"))
	cached := httptest.NewRecorder()
	h.ServeHTTP(cached, r)
	if cached.Code != http.StatusNotModified || cached.Body.Len() != 0 {
		t.Fatalf("ETag was not honoured: %d", cached.Code)
	}
	for _, path := range []string{"/missing.js", "/missing.css", "/api/missing"} {
		out := httptest.NewRecorder()
		h.ServeHTTP(out, httptest.NewRequest("GET", path, nil))
		if out.Code != http.StatusNotFound {
			t.Errorf("%s returned SPA success: %d", path, out.Code)
		}
	}
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-inline") {
		t.Fatal("cache repair relaxed CSP")
	}
}
