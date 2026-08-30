package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The management interface is the one that can repoint a network's DNS, read
// every query it has answered, and rotate the credentials devices use. Where
// it binds is a security property of the program, and these tests are what
// stop it drifting back to a wildcard the next time somebody finds ":8080"
// convenient.

func TestDefaultManagementBindIsLoopback(t *testing.T) {
	cfg := Default()
	if got := ClassifyManagementBind(cfg.HTTP.Listen); got != BindLoopback {
		t.Fatalf("default http.listen %q classifies as %v, want loopback", cfg.HTTP.Listen, got)
	}
	// Named explicitly rather than only classified: a future edit to
	// ClassifyManagementBind must not be able to make a wildcard "loopback"
	// and take this assertion with it.
	if cfg.HTTP.Listen != "127.0.0.1:8080" {
		t.Fatalf("default http.listen = %q, want 127.0.0.1:8080", cfg.HTTP.Listen)
	}
	if cfg.HTTP.AllowPublicBind {
		t.Fatal("http.allow_public_bind defaults to true; it must be opt-in")
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("the default configuration must be valid: %v", err)
	}
}

func TestClassifyManagementBind(t *testing.T) {
	tests := []struct {
		listen string
		want   ManagementBindKind
	}{
		// Loopback, in every spelling a person actually writes.
		{"127.0.0.1:8080", BindLoopback},
		{"127.0.0.53:8080", BindLoopback},
		{"[::1]:8080", BindLoopback},
		{"::1", BindLoopback},
		{"localhost:8080", BindLoopback},
		{"LocalHost:8080", BindLoopback},

		// Every interface. All four of these are the same thing, and the
		// first two are the ones that look innocent.
		{":8080", BindWildcard},
		{"", BindWildcard},
		{"0.0.0.0:8080", BindWildcard},
		{"[::]:8080", BindWildcard},

		// A named LAN address: the home deployment.
		{"192.168.1.50:8080", BindPrivate},
		{"10.4.0.9:8080", BindPrivate},
		{"172.16.0.1:8080", BindPrivate},
		{"100.64.0.7:8080", BindPrivate}, // RFC 6598 CGNAT / Tailscale
		{"169.254.10.1:8080", BindPrivate},
		{"[fd00::1]:8080", BindPrivate},
		{"[fe80::1%eth0]:8080", BindPrivate},

		// Globally routable.
		{"203.0.113.9:8080", BindPublic},
		{"[2001:db8::1]:8080", BindPublic},
		// An IPv4-mapped IPv6 literal must be judged on the v4 address it
		// carries, not treated as an exotic v6 one.
		{"[::ffff:203.0.113.9]:8080", BindPublic},
		{"[::ffff:127.0.0.1]:8080", BindLoopback},

		{"dns.example.com:8080", BindUnknown},
	}
	for _, tc := range tests {
		if got := ClassifyManagementBind(tc.listen); got != tc.want {
			t.Errorf("ClassifyManagementBind(%q) = %v, want %v", tc.listen, got, tc.want)
		}
	}
}

func TestWildcardAndPublicBindsAreRefusedWithoutAcknowledgement(t *testing.T) {
	for _, listen := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "203.0.113.9:8080", "[2001:db8::1]:8080"} {
		cfg := Default()
		cfg.HTTP.Listen = listen
		err := cfg.validate()
		if err == nil {
			t.Errorf("http.listen %q was accepted; it publishes the management API", listen)
			continue
		}
		if !strings.Contains(err.Error(), "allow_public_bind") {
			t.Errorf("http.listen %q: error does not say how to proceed deliberately: %v", listen, err)
		}
	}
}

func TestLoopbackAndPrivateBindsNeedNoAcknowledgement(t *testing.T) {
	// The LAN deployment must not need an escape hatch. Someone who types
	// their own 192.168 address has already said what they mean, and making
	// them set a second flag would only teach them to set it everywhere.
	for _, listen := range []string{"127.0.0.1:8080", "[::1]:8080", "192.168.1.50:8080", "10.0.0.4:8080", "[fd00::1]:8080"} {
		cfg := Default()
		cfg.HTTP.Listen = listen
		if err := cfg.validate(); err != nil {
			t.Errorf("http.listen %q was refused: %v", listen, err)
		}
	}
}

func TestPublicBindIsPermittedOnceAcknowledged(t *testing.T) {
	cfg := Default()
	cfg.HTTP.Listen = ":8080"
	cfg.HTTP.AllowPublicBind = true
	if err := cfg.validate(); err != nil {
		t.Fatalf("an acknowledged public bind must be allowed: %v", err)
	}
}

func TestAllowPublicBindIsReachableFromTheEnvironment(t *testing.T) {
	// The container image sets this variable, so it has to be wired up. If it
	// silently did nothing, every Docker deployment would fail to start.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("http:\n  listen: \":8080\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("a wildcard bind loaded without the acknowledgement")
	}

	t.Setenv("DNSDADDY_ALLOW_PUBLIC_BIND", "true")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("DNSDADDY_ALLOW_PUBLIC_BIND=true did not take effect: %v", err)
	}
	if !cfg.HTTP.AllowPublicBind {
		t.Fatal("DNSDADDY_ALLOW_PUBLIC_BIND=true did not reach the config")
	}
}

func TestDockerImageDeclaresItsOwnBoundary(t *testing.T) {
	// The image sets a wildcard listener, which the binary refuses by default.
	// It is allowed to, because the container's network namespace is the
	// boundary and Compose publishes to loopback — but only if it says so.
	// If someone removes DNSDADDY_ALLOW_PUBLIC_BIND from the Dockerfile, every
	// container stops booting, and this test says why before that ships.
	b, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Skipf("Dockerfile not readable from here: %v", err)
	}
	df := string(b)
	if !strings.Contains(df, "DNSDADDY_HTTP_LISTEN=:8080") {
		t.Skip("the image no longer sets a wildcard listener; nothing to acknowledge")
	}
	if !strings.Contains(df, "DNSDADDY_ALLOW_PUBLIC_BIND=true") {
		t.Error("the image sets a wildcard HTTP listener but does not set " +
			"DNSDADDY_ALLOW_PUBLIC_BIND, so the container will refuse to start")
	}
}

func TestComposePublishesTheDashboardToLoopbackByDefault(t *testing.T) {
	// The one variable that decides whether the management API is on the
	// internet. Its default has to be loopback, and the substitution has to
	// keep it there when .env says nothing.
	b, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Skipf("docker-compose.yml not readable from here: %v", err)
	}
	if !strings.Contains(string(b), `"${DNSDADDY_DASHBOARD_BIND:-127.0.0.1}:8080:8080"`) {
		t.Error("docker-compose.yml no longer publishes the dashboard to 127.0.0.1 by default")
	}
}
