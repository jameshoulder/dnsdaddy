package config

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// repoFile reads a file from the repository root.
func repoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// splitCIDRs parses a comma-separated DNSDADDY_ALLOWED_CLIENT_CIDRS value.
func splitCIDRs(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// The Compose file substitutes a default when the operator has not set
// DNSDADDY_ALLOWED_CLIENT_CIDRS. That default must be the binary's own,
// because anything narrower means a Docker install silently serves fewer
// clients than a native one for no reason the operator can see — the
// resolver stays healthy and its clients get REFUSED.
func TestComposeClientACLDefaultMatchesBuiltIn(t *testing.T) {
	compose := repoFile(t, "docker-compose.yml")

	re := regexp.MustCompile(`DNSDADDY_ALLOWED_CLIENT_CIDRS:\s*"\$\{DNSDADDY_ALLOWED_CLIENT_CIDRS:-([^}]*)\}"`)
	m := re.FindStringSubmatch(compose)
	if m == nil {
		t.Fatal("docker-compose.yml no longer substitutes a default for DNSDADDY_ALLOWED_CLIENT_CIDRS; " +
			"if that is deliberate, update this test to describe the new contract")
	}

	got := splitCIDRs(m[1])
	want := DefaultAllowedClientCIDRs

	if !slices.Equal(got, want) {
		t.Errorf("docker-compose.yml default client ACL has drifted from config.DefaultAllowedClientCIDRs\n"+
			" compose: %v\n built-in: %v\n"+
			"A Docker deployment must not serve a different set of clients from a native one.", got, want)
	}
}

// .env.example is copied to .env by the documented install path, so every
// uncommented assignment in it is applied to a stock deployment.
//
// It must not ship an active DNSDADDY_ALLOWED_CLIENT_CIDRS. It used to set
// "127.0.0.0/8,172.16.0.0/12" under a heading that read "REQUIRED on a public
// VPS", which a LAN operator reasonably skips — while the line beneath it was
// live and narrowed their ACL to loopback and the Docker bridge. Every LAN
// client was then REFUSED by a resolver that reported itself healthy.
func TestEnvExampleDoesNotNarrowTheClientACL(t *testing.T) {
	sc := bufio.NewScanner(strings.NewReader(repoFile(t, ".env.example")))
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(text, "DNSDADDY_ALLOWED_CLIENT_CIDRS=") {
			continue
		}
		value := strings.TrimPrefix(text, "DNSDADDY_ALLOWED_CLIENT_CIDRS=")
		t.Errorf(".env.example:%d ships an active client ACL (%q).\n"+
			"The documented install copies this file to .env, so it overrides the built-in\n"+
			"default and decides who may resolve. Leave it commented out: a LAN install\n"+
			"needs no value, and a VPS operator has to choose their own.", line, value)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan .env.example: %v", err)
	}
}
