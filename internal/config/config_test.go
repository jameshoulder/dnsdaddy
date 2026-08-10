package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultsAreValid(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("the built-in defaults do not validate: %v", err)
	}
	if len(cfg.DNS.Upstreams) == 0 {
		t.Error("no default upstreams")
	}
	// Shipping plaintext upstreams by default would expose every lookup DNS
	// Daddy forwards to the operator's ISP.
	for _, u := range cfg.DNS.Upstreams {
		if len(u) < 6 || u[:6] != "tls://" {
			t.Errorf("default upstream %q is not encrypted", u)
		}
	}
}

func TestMissingFileIsNotAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err != nil {
		t.Errorf("a missing config file should fall back to defaults, got %v", err)
	}
}

func TestUnreadableFileIsAnError(t *testing.T) {
	// A directory where a file is expected: silently falling back to defaults
	// would start a resolver with settings the operator did not choose.
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("Load accepted a directory as a config file")
	}
}

func TestMalformedYAMLIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("dns:\n  upstreams: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load accepted malformed YAML")
	}
}

func TestFileOverridesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `
data_dir: /srv/dnsdaddy
dns:
  listen_udp: "127.0.0.1:5353"
  upstreams:
    - "tls://9.9.9.9:853#dns.quad9.net"
  upstream_mode: race
log:
  retention_days: 30
feeds:
  refresh_interval: 6h
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DataDir != "/srv/dnsdaddy" {
		t.Errorf("DataDir = %q", cfg.DataDir)
	}
	if cfg.DNS.ListenUDP != "127.0.0.1:5353" {
		t.Errorf("ListenUDP = %q", cfg.DNS.ListenUDP)
	}
	if cfg.DNS.UpstreamMode != "race" {
		t.Errorf("UpstreamMode = %q", cfg.DNS.UpstreamMode)
	}
	if cfg.Log.RetentionDays != 30 {
		t.Errorf("RetentionDays = %d", cfg.Log.RetentionDays)
	}
	if cfg.Feeds.RefreshInterval.D() != 6*time.Hour {
		t.Errorf("RefreshInterval = %v, want 6h", cfg.Feeds.RefreshInterval)
	}
	// Unset keys must keep their defaults rather than becoming zero values.
	if cfg.DNS.ListenTCP != ":53" {
		t.Errorf("ListenTCP = %q, want the default to survive a partial file", cfg.DNS.ListenTCP)
	}
}

func TestUnknownTopLevelYAMLKeyIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// A plausible typo of "data_dir" — must not be silently ignored.
	if err := os.WriteFile(path, []byte("data_directory: /srv/dnsdaddy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load accepted an unknown top-level key")
	}
}

func TestUnknownNestedYAMLKeyIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// A plausible typo of "retention_days" — silently ignoring this means the
	// operator believes their retention setting applied when it did not.
	if err := os.WriteFile(path, []byte("log:\n  retension_days: 30\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load accepted an unknown nested key")
	}
}

func TestMultipleYAMLDocumentsAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "data_dir: /srv/one\n---\ndata_dir: /srv/two\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load accepted a config file with more than one YAML document")
	}
}

func TestEmptyYAMLFileIsValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DataDir != Default().DataDir {
		t.Errorf("DataDir = %q, want the default to survive an empty file", cfg.DataDir)
	}
}

func TestShippedExampleConfigDecodesCleanly(t *testing.T) {
	// dnsdaddy.example.yaml is what every operator copies as a starting
	// point. If strict decoding ever rejects it, every fresh install breaks
	// on the exact config file the README tells people to use.
	path := filepath.Join("..", "..", "dnsdaddy.example.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("example config not found at %s: %v", path, err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("dnsdaddy.example.yaml did not decode: %v", err)
	}
}

func TestInvalidEnvironmentValuesAreErrors(t *testing.T) {
	tests := []struct {
		name, key, value string
	}{
		{"bad bool", "DNSDADDY_QUERY_LOG", "fasle"},
		{"bad int", "DNSDADDY_RETENTION_DAYS", "not-a-number"},
		{"bad duration", "DNSDADDY_FEED_REFRESH_INTERVAL", "soon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.key, tt.value)
			if _, err := Load(""); err == nil {
				t.Errorf("Load accepted %s=%q instead of failing to start", tt.key, tt.value)
			}
		})
	}
}

func TestEnvironmentOverridesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: /from/file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("DNSDADDY_DATA_DIR", "/from/env")
	t.Setenv("DNSDADDY_UPSTREAMS", "tls://1.1.1.1:853#cloudflare-dns.com, udp://8.8.8.8:53")
	t.Setenv("DNSDADDY_RETENTION_DAYS", "14")
	t.Setenv("DNSDADDY_QUERY_LOG", "false")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DataDir != "/from/env" {
		t.Errorf("DataDir = %q, want the environment to win", cfg.DataDir)
	}
	if len(cfg.DNS.Upstreams) != 2 {
		t.Fatalf("Upstreams = %v, want 2 parsed from the comma-separated list", cfg.DNS.Upstreams)
	}
	if cfg.DNS.Upstreams[1] != "udp://8.8.8.8:53" {
		t.Errorf("Upstreams[1] = %q, want whitespace trimmed", cfg.DNS.Upstreams[1])
	}
	if cfg.Log.RetentionDays != 14 {
		t.Errorf("RetentionDays = %d", cfg.Log.RetentionDays)
	}
	if cfg.Log.QueryLog {
		t.Error("DNSDADDY_QUERY_LOG=false did not disable query logging")
	}
}

func TestValidationRejectsBadConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no data dir", func(c *Config) { c.DataDir = "" }},
		{"no upstreams", func(c *Config) { c.DNS.Upstreams = nil }},
		{"bad upstream mode", func(c *Config) { c.DNS.UpstreamMode = "roundrobin" }},
		{"no listeners", func(c *Config) { c.DNS.ListenUDP, c.DNS.ListenTCP, c.DNS.ListenDoT = "", "", "" }},
		{"negative retention", func(c *Config) { c.Log.RetentionDays = -1 }},
		{"inverted TTL bounds", func(c *Config) { c.Cache.MinTTL, c.Cache.MaxTTL = 100, 10 }},
		{"refresh interval too short", func(c *Config) { c.Feeds.RefreshInterval = Duration(time.Second) }},
		{"DoT without a key", func(c *Config) {
			c.DNS.ListenDoT = ":853"
			c.DNS.TLSCertFile = "/etc/cert.pem"
			c.DNS.TLSKeyFile = ""
		}},
		{"open resolver", func(c *Config) { c.DNS.AllowedClientCIDRs = nil }},
		{"bad client CIDR", func(c *Config) { c.DNS.AllowedClientCIDRs = []string{"192.168.0.0/64"} }},
		{"bad trusted proxy CIDR", func(c *Config) { c.HTTP.TrustedProxyCIDRs = []string{"not-an-address"} }},
		{"bad secure_cookies mode", func(c *Config) { c.HTTP.SecureCookies = "sometimes" }},
		{"TTL over the 32-bit DNS limit", func(c *Config) { c.Cache.MaxTTL = 1 << 32 }},
		{"negative TTL", func(c *Config) { c.Cache.MinTTL = -1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.mutate(&cfg)
			if err := cfg.validate(); err == nil {
				t.Error("validate() accepted an invalid configuration")
			}
		})
	}
}

func TestDurationRoundTrip(t *testing.T) {
	var d Duration
	if err := d.UnmarshalText([]byte("90m")); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if d.D() != 90*time.Minute {
		t.Errorf("parsed %v, want 90m", d.D())
	}
	if d.String() != "1h30m0s" {
		t.Errorf("String() = %q", d.String())
	}
	if err := d.UnmarshalText([]byte("not-a-duration")); err == nil {
		t.Error("UnmarshalText accepted junk")
	}
}

func TestDerivedPaths(t *testing.T) {
	cfg := Default()
	cfg.DataDir = "/srv/dnsdaddy"
	if got := cfg.DBPath(); got != "/srv/dnsdaddy/dnsdaddy.db" {
		t.Errorf("DBPath() = %q", got)
	}
	if got := cfg.SecretPath(); got != "/srv/dnsdaddy/session.key" {
		t.Errorf("SecretPath() = %q", got)
	}
}

// An open resolver is discovered and conscripted into amplification attacks
// within days. Refusing to start is a far smaller cost than that, so the
// error must fire on exactly the dangerous combination and nothing else.
func TestOpenResolverGuard(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name:    "shipped defaults are closed",
			mutate:  func(*Config) {},
			wantErr: false,
		},
		{
			name:    "public listener with no ACL",
			mutate:  func(c *Config) { c.DNS.AllowedClientCIDRs = nil },
			wantErr: true,
		},
		{
			name: "public listener with explicit opt-in",
			mutate: func(c *Config) {
				c.DNS.AllowedClientCIDRs = nil
				c.DNS.AllowPublicResolver = true
			},
			wantErr: false,
		},
		{
			name: "loopback-only listener needs no ACL",
			mutate: func(c *Config) {
				c.DNS.AllowedClientCIDRs = nil
				c.DNS.ListenUDP = "127.0.0.1:53"
				c.DNS.ListenTCP = "127.0.0.1:53"
			},
			wantErr: false,
		},
		{
			name: "IPv6 loopback listener needs no ACL",
			mutate: func(c *Config) {
				c.DNS.AllowedClientCIDRs = nil
				c.DNS.ListenUDP = "[::1]:53"
				c.DNS.ListenTCP = "[::1]:53"
			},
			wantErr: false,
		},
		{
			name: "localhost by name needs no ACL",
			mutate: func(c *Config) {
				c.DNS.AllowedClientCIDRs = nil
				c.DNS.ListenUDP = "localhost:53"
				c.DNS.ListenTCP = "localhost:53"
			},
			wantErr: false,
		},
		{
			// One loopback listener does not excuse a second public one.
			name: "mixed loopback and public listeners",
			mutate: func(c *Config) {
				c.DNS.AllowedClientCIDRs = nil
				c.DNS.ListenUDP = "127.0.0.1:53"
				c.DNS.ListenTCP = "0.0.0.0:53"
			},
			wantErr: true,
		},
		{
			name: "public DoT listener with no ACL",
			mutate: func(c *Config) {
				c.DNS.AllowedClientCIDRs = nil
				c.DNS.ListenUDP = "127.0.0.1:53"
				c.DNS.ListenTCP = "127.0.0.1:53"
				c.DNS.ListenDoT = ":853"
				c.DNS.TLSCertFile = "/etc/cert.pem"
				c.DNS.TLSKeyFile = "/etc/key.pem"
			},
			wantErr: true,
		},
		{
			name: "a bound public address is still public",
			mutate: func(c *Config) {
				c.DNS.AllowedClientCIDRs = nil
				c.DNS.ListenUDP = "203.0.113.9:53"
				c.DNS.ListenTCP = "203.0.113.9:53"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.mutate(&cfg)
			err := cfg.validate()
			if tt.wantErr && err == nil {
				t.Error("validate() accepted a configuration that would be an open resolver")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validate() rejected a safe configuration: %v", err)
			}
		})
	}
}

// The shipped ACL must actually cover the private address space and nothing
// routable, or the default is either useless or dangerous.
func TestDefaultAllowedClientCIDRs(t *testing.T) {
	cfg := Default()
	prefixes := cfg.AllowedClientPrefixes()
	if len(prefixes) != len(DefaultAllowedClientCIDRs) {
		t.Fatalf("parsed %d prefixes from %d defaults", len(prefixes), len(DefaultAllowedClientCIDRs))
	}

	contains := func(s string) bool {
		addr := netip.MustParseAddr(s)
		for _, p := range prefixes {
			if p.Addr().Is4() == addr.Is4() && p.Contains(addr) {
				return true
			}
		}
		return false
	}

	for _, in := range []string{"127.0.0.1", "10.1.2.3", "172.16.9.9", "192.168.1.50", "100.64.0.7", "::1", "fd00::1"} {
		if !contains(in) {
			t.Errorf("the default ACL does not cover %s, which is a normal LAN client", in)
		}
	}
	for _, out := range []string{"8.8.8.8", "203.0.113.9", "172.32.0.1", "2001:db8::1"} {
		if contains(out) {
			t.Errorf("the default ACL covers %s, which is routable on the public internet", out)
		}
	}
}

// A TTL is a uint32 on the wire and RFC 2181 §8 reserves the top bit, so
// anything outside 0..2^31-1 cannot be represented and must be rejected at
// load time rather than silently wrapping.
func TestCacheTTLBounds(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"defaults", func(*Config) {}, false},
		{"max at the RFC 2181 limit", func(c *Config) { c.Cache.MaxTTL = 1<<31 - 1 }, false},
		{"max one past the limit", func(c *Config) { c.Cache.MaxTTL = 1 << 31 }, true},
		{"max past uint32", func(c *Config) { c.Cache.MaxTTL = 1 << 32 }, true},
		{"negative min", func(c *Config) { c.Cache.MinTTL = -1 }, true},
		{"negative negative_ttl", func(c *Config) { c.Cache.NegativeTTL = -1 }, true},
		{"zero min honours upstream", func(c *Config) { c.Cache.MinTTL = 0 }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.mutate(&cfg)
			err := cfg.validate()
			if tt.wantErr && err == nil {
				t.Error("validate() accepted an unrepresentable TTL")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validate() rejected a valid TTL: %v", err)
			}
		})
	}
}

func TestLocalFeedDirDefaultsToDisabled(t *testing.T) {
	if Default().Feeds.LocalFeedDir != "" {
		t.Error("file:// feeds are enabled by default; they must be opt-in")
	}
}
