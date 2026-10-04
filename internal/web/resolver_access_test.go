package web

import (
	"os/exec"
	"testing"
)

func TestResolverAccessJavaScript(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node unavailable; run node --test internal/web/resolver_access.test.js")
	}
	out, err := exec.Command("node", "--test", "resolver_access.test.js").CombinedOutput()
	if err != nil {
		t.Fatalf("resolver access JavaScript: %v\n%s", err, out)
	}
}
