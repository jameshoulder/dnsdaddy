package web

import (
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

func TestPhase1DisclosuresAreInTheServedDashboardBundle(t *testing.T) {
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, httptest.NewRequest("GET", "/app.js", nil))
	for _, text := range []string{"Fresh installations without an explicit resolver-mode override start in Forward (off)", "Safe Search is not enforced.", "installProductClaims"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Errorf("served bundle lacks %q", text)
		}
	}
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-inline") {
		t.Fatal("read-only disclosures must not weaken the CSP")
	}
}

func TestPhase1RenderedProductClaims(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node unavailable; run node --test internal/web/product_claims.test.js")
	}
	out, err := exec.Command("node", "--test", "product_claims.test.js").CombinedOutput()
	if err != nil {
		t.Fatalf("rendered product claims: %v\n%s", err, out)
	}
}
