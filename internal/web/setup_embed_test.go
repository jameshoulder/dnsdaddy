package web

import (
	"bytes"
	"net/http/httptest"
	"os/exec"
	"testing"
	"testing/fstest"
)

func TestSetupExtensionIsIncludedInTheServedScript(t *testing.T) {
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, httptest.NewRequest("GET", "/app.js", nil))
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("function mountGuide")) || !bytes.Contains(w.Body.Bytes(), []byte("async function boot")) {
		t.Fatal("the production dashboard did not contain both bootstrap and guided setup")
	}
	if w.Header().Get("ETag") == "" {
		t.Fatal("assembled script has no cache identity")
	}
}

func TestSetupChangesInvalidateTheDashboardFingerprint(t *testing.T) {
	fixture := fstest.MapFS{
		"index.html": {Data: []byte(`<script src="/app.js"></script><link href="/app.css">`)},
		"app.js":     {Data: []byte("main();")},
		"app.css":    {Data: []byte("body{}")},
		"setup.js":   {Data: []byte("first();")},
	}
	before, first, err := dashboardIndex(fixture)
	if err != nil {
		t.Fatal(err)
	}
	fixture["setup.js"].Data = []byte("second();")
	after, second, err := dashboardIndex(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) || first["app.js"] == second["app.js"] {
		t.Fatal("setup changes reused stale dashboard bytes")
	}
	if first["app.css"] != second["app.css"] {
		t.Fatal("setup changed an unrelated asset hash")
	}
}

// CI's Go test step runs before its explicit dashboard test command. Exercise
// this extension when Node is available without making Node a runtime dependency.
func TestGuidedSetupJavaScript(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node is unavailable; run node --test internal/web/setup.test.js in the dashboard test environment")
	}
	out, err := exec.Command("node", "--test", "setup.test.js").CombinedOutput()
	if err != nil {
		t.Fatalf("guided setup JavaScript: %v\n%s", err, out)
	}
}
