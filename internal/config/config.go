// Package config loads DNS Daddy's runtime configuration.
//
// Configuration comes from three places, in increasing order of precedence:
// built-in defaults, a YAML file, then DNSDADDY_* environment variables.
// The defaults are tuned for a 1 GB / 1 vCPU VPS (a $5 Linode Nanode or
// equivalent), which is the reference deployment target.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	DataDir string  `yaml:"data_dir"`
	DNS     DNS     `yaml:"dns"`
	HTTP    HTTP    `yaml:"http"`
	Log     Logging `yaml:"log"`
	Cache   Cache   `yaml:"cache"`
	Feeds   Feeds   `yaml:"feeds"`
}

// DNS holds the resolver-side settings: what we listen on and where we forward.
type DNS struct {
	ListenUDP    string   `yaml:"listen_udp"`
	ListenTCP    string   `yaml:"listen_tcp"`
	ListenDoT    string   `yaml:"listen_dot"`
	TLSCertFile  string   `yaml:"tls_cert_file"`
	TLSKeyFile   string   `yaml:"tls_key_file"`
	Upstreams    []string `yaml:"upstreams"`
	UpstreamMode string   `yaml:"upstream_mode"` // "failover" or "race"
	Timeout      Duration `yaml:"timeout"`
	MaxInflight  int      `yaml:"max_inflight"`

	// AllowedClientCIDRs restricts which source addresses may resolve.
	// Queries from anywhere else are REFUSED before any upstream work.
	//
	// This duplicates what a host firewall should already do, deliberately.
	// An open resolver on the public internet gets found and abused for
	// amplification within days, and "the operator was told to firewall it"
	// is not a control. Empty means no restriction — permitted only when the
	// listeners are loopback-only or AllowPublicResolver is set.
	AllowedClientCIDRs []string `yaml:"allowed_client_cidrs"`

	// AllowPublicResolver is the explicit acknowledgement required to run
	// with a non-loopback listener and no client ACL. Without it, that
	// combination is a startup error rather than a silently open resolver.
	AllowPublicResolver bool `yaml:"allow_public_resolver"`

	// RefuseANY answers ANY queries per RFC 8482 instead of forwarding them.
	// ANY responses are large and are a standard DNS amplification lever.
	RefuseANY bool `yaml:"refuse_any"`
}

// HTTP holds the management API and dashboard settings.
type HTTP struct {
	Listen        string `yaml:"listen"`
	AdminPassword string `yaml:"admin_password"`
	BaseURL       string `yaml:"base_url"`

	// TrustedProxyCIDRs lists the peers whose X-Forwarded-For,
	// X-Real-IP, and X-Forwarded-Proto headers are believed. Empty means no
	// forwarding header is ever trusted, which is correct when the HTTP port
	// is reachable directly: otherwise any client could assert any source
	// address and pick up another network's filtering policy.
	TrustedProxyCIDRs []string `yaml:"trusted_proxy_cidrs"`

	// SecureCookies controls the session cookie's Secure flag:
	//
	//	auto   — set it when the request arrived over TLS (default)
	//	always — set it unconditionally; correct once TLS is in front, and
	//	         the right choice for anything internet-facing
	//	never  — never set it; for a plain-HTTP LAN deployment where "always"
	//	         would make login impossible
	//
	// "auto" exists because this is self-hosted software that legitimately
	// runs on plain HTTP inside a LAN, where an unconditional Secure flag
	// means the browser never sends the cookie back and nobody can log in.
	SecureCookies string `yaml:"secure_cookies"`

	// AllowUntokenizedDoH permits /dns-query without a per-network token.
	// Off by default: behind a public reverse proxy that path would other-
	// wise be an open DoH resolver for anyone who finds it.
	AllowUntokenizedDoH bool `yaml:"allow_untokenized_doh"`
}

// Logging controls query logging and retention.
type Logging struct {
	QueryLog        bool `yaml:"query_log"`
	LogClientIP     bool `yaml:"log_client_ip"`
	RetentionDays   int  `yaml:"retention_days"`
	RollupDays      int  `yaml:"rollup_days"`
	BufferSize      int  `yaml:"buffer_size"`
	FlushIntervalMS int  `yaml:"flush_interval_ms"`
}

// Cache controls the answer cache.
type Cache struct {
	Enabled     bool `yaml:"enabled"`
	MaxEntries  int  `yaml:"max_entries"`
	MinTTL      int  `yaml:"min_ttl"`
	MaxTTL      int  `yaml:"max_ttl"`
	NegativeTTL int  `yaml:"negative_ttl"`
}

// Feeds controls threat-intelligence feed refreshes.
type Feeds struct {
	RefreshInterval Duration `yaml:"refresh_interval"`
	RefreshOnStart  bool     `yaml:"refresh_on_start"`
	HTTPTimeout     Duration `yaml:"http_timeout"`
	MaxFeedBytes    int64    `yaml:"max_feed_bytes"`

	// LocalFeedDir is the only directory a file:// feed may read from. Empty
	// (the default) rejects file:// feeds outright.
	//
	// Feeds are added through the management API, so without this an operator
	// session — or a leaked API token — could point a "feed" at any file the
	// process can read and pull it back out through the dashboard.
	LocalFeedDir string `yaml:"local_feed_dir"`
}

// Duration is a time.Duration that unmarshals from a string like "24h".
type Duration time.Duration

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// String implements fmt.Stringer.
func (d Duration) String() string { return time.Duration(d).String() }

// DefaultAllowedClientCIDRs is the shipped DNS client ACL: loopback, the RFC
// 1918 private ranges, carrier-grade NAT (which is what Tailscale hands out),
// link-local, and IPv6 unique-local. Between them these cover every network a
// self-hosted resolver is normally asked to serve, and none of them are
// routable from the public internet.
var DefaultAllowedClientCIDRs = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

// Default returns the built-in configuration.
func Default() Config {
	return Config{
		DataDir: "/var/lib/dnsdaddy",
		DNS: DNS{
			ListenUDP: ":53",
			ListenTCP: ":53",
			ListenDoT: "",
			// Quad9 and Cloudflare over DNS-over-TLS. Both are widely peered in
			// the UK and EU, which is where the reference deployment lives.
			Upstreams:    []string{"tls://9.9.9.9:853#dns.quad9.net", "tls://1.1.1.1:853#cloudflare-dns.com"},
			UpstreamMode: "failover",
			Timeout:      Duration(4 * time.Second),
			MaxInflight:  2048,
			// Serve the private address space out of the box. This is the
			// deployment nearly everyone actually has — a resolver on a VPS or
			// a home box answering its own networks — and it means the default
			// configuration is both usable and closed to the public internet.
			// Opening it up is a deliberate edit, not the fallback.
			AllowedClientCIDRs: append([]string(nil), DefaultAllowedClientCIDRs...),
			RefuseANY:          true,
		},
		HTTP: HTTP{
			Listen:        ":8080",
			SecureCookies: "auto",
		},
		Log: Logging{
			QueryLog:        true,
			LogClientIP:     true,
			RetentionDays:   7,
			RollupDays:      90,
			BufferSize:      8192,
			FlushIntervalMS: 500,
		},
		Cache: Cache{
			Enabled:     true,
			MaxEntries:  50000,
			MinTTL:      30,
			MaxTTL:      86400,
			NegativeTTL: 300,
		},
		Feeds: Feeds{
			RefreshInterval: Duration(12 * time.Hour),
			RefreshOnStart:  true,
			HTTPTimeout:     Duration(90 * time.Second),
			MaxFeedBytes:    128 << 20,
		},
	}
}

// Load builds a Config from defaults, an optional YAML file, and the
// environment. A missing config file is not an error; an unreadable or
// malformed one is.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		// #nosec G304 -- the config file path comes from -config or DNSDADDY_CONFIG,
		// both operator-supplied at startup.
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := unmarshalYAML(b, &cfg); err != nil {
				return cfg, fmt.Errorf("parse %s: %w", path, err)
			}
		case os.IsNotExist(err):
			// Fall through to defaults + environment.
		default:
			return cfg, fmt.Errorf("read %s: %w", path, err)
		}
	}

	if err := applyEnv(&cfg); err != nil {
		return cfg, fmt.Errorf("environment: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// applyEnv overlays DNSDADDY_* environment variables onto cfg. A malformed
// value (DNSDADDY_QUERY_LOG=fasle, say) is a startup error rather than a
// silently ignored typo: for a security setting, "the operator's config was
// ignored" is worse than "the process refused to start."
func applyEnv(cfg *Config) error {
	envStr("DNSDADDY_DATA_DIR", &cfg.DataDir)
	envStr("DNSDADDY_DNS_LISTEN_UDP", &cfg.DNS.ListenUDP)
	envStr("DNSDADDY_DNS_LISTEN_TCP", &cfg.DNS.ListenTCP)
	envStr("DNSDADDY_DNS_LISTEN_DOT", &cfg.DNS.ListenDoT)
	envStr("DNSDADDY_TLS_CERT_FILE", &cfg.DNS.TLSCertFile)
	envStr("DNSDADDY_TLS_KEY_FILE", &cfg.DNS.TLSKeyFile)
	envStr("DNSDADDY_UPSTREAM_MODE", &cfg.DNS.UpstreamMode)
	envStr("DNSDADDY_HTTP_LISTEN", &cfg.HTTP.Listen)
	envStr("DNSDADDY_ADMIN_PASSWORD", &cfg.HTTP.AdminPassword)
	envStr("DNSDADDY_BASE_URL", &cfg.HTTP.BaseURL)
	envStr("DNSDADDY_SECURE_COOKIES", &cfg.HTTP.SecureCookies)
	envStr("DNSDADDY_LOCAL_FEED_DIR", &cfg.Feeds.LocalFeedDir)
	envList("DNSDADDY_TRUSTED_PROXY_CIDRS", &cfg.HTTP.TrustedProxyCIDRs)
	envList("DNSDADDY_ALLOWED_CLIENT_CIDRS", &cfg.DNS.AllowedClientCIDRs)

	if v := os.Getenv("DNSDADDY_UPSTREAMS"); v != "" {
		var ups []string
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				ups = append(ups, p)
			}
		}
		if len(ups) > 0 {
			cfg.DNS.Upstreams = ups
		}
	}

	for _, step := range []func() error{
		func() error { return envBool("DNSDADDY_ALLOW_PUBLIC_RESOLVER", &cfg.DNS.AllowPublicResolver) },
		func() error { return envBool("DNSDADDY_REFUSE_ANY", &cfg.DNS.RefuseANY) },
		func() error { return envBool("DNSDADDY_ALLOW_UNTOKENIZED_DOH", &cfg.HTTP.AllowUntokenizedDoH) },
		func() error { return envBool("DNSDADDY_QUERY_LOG", &cfg.Log.QueryLog) },
		func() error { return envBool("DNSDADDY_LOG_CLIENT_IP", &cfg.Log.LogClientIP) },
		func() error { return envInt("DNSDADDY_RETENTION_DAYS", &cfg.Log.RetentionDays) },
		func() error { return envInt("DNSDADDY_ROLLUP_DAYS", &cfg.Log.RollupDays) },
		func() error { return envBool("DNSDADDY_CACHE_ENABLED", &cfg.Cache.Enabled) },
		func() error { return envInt("DNSDADDY_CACHE_MAX_ENTRIES", &cfg.Cache.MaxEntries) },
		func() error { return envDur("DNSDADDY_FEED_REFRESH_INTERVAL", &cfg.Feeds.RefreshInterval) },
		func() error { return envBool("DNSDADDY_FEED_REFRESH_ON_START", &cfg.Feeds.RefreshOnStart) },
	} {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func envStr(key string, dst *string) {
	if v, ok := os.LookupEnv(key); ok {
		*dst = v
	}
}

// envList parses a comma-separated environment variable into a string slice.
func envList(key string, dst *[]string) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	*dst = out
}

func envBool(key string, dst *bool) error {
	v, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s=%q is not a valid boolean: %w", key, v, err)
	}
	*dst = b
	return nil
}

func envInt(key string, dst *int) error {
	v, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s=%q is not a valid integer: %w", key, v, err)
	}
	*dst = n
	return nil
}

func envDur(key string, dst *Duration) error {
	v, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s=%q is not a valid duration: %w", key, v, err)
	}
	*dst = Duration(d)
	return nil
}

func (c *Config) validate() error {
	if c.DataDir == "" {
		return fmt.Errorf("data_dir must not be empty")
	}
	if len(c.DNS.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream resolver is required")
	}
	switch c.DNS.UpstreamMode {
	case "failover", "race":
	default:
		return fmt.Errorf("upstream_mode must be %q or %q, got %q", "failover", "race", c.DNS.UpstreamMode)
	}
	if c.DNS.ListenUDP == "" && c.DNS.ListenTCP == "" && c.DNS.ListenDoT == "" {
		return fmt.Errorf("no DNS listener configured")
	}
	if c.DNS.ListenDoT != "" && (c.DNS.TLSCertFile == "") != (c.DNS.TLSKeyFile == "") {
		return fmt.Errorf("tls_cert_file and tls_key_file must be set together")
	}
	if c.Log.RetentionDays < 0 {
		return fmt.Errorf("retention_days must not be negative")
	}
	if c.Cache.MinTTL < 0 || c.Cache.MaxTTL < c.Cache.MinTTL {
		return fmt.Errorf("invalid cache TTL bounds: min=%d max=%d", c.Cache.MinTTL, c.Cache.MaxTTL)
	}
	// RFC 2181 §8 reserves the top bit of a TTL, so 2^31-1 is the largest a
	// record can carry. Rejecting anything larger at startup is clearer than
	// silently clamping a value the operator plainly meant.
	const maxTTL = 1<<31 - 1
	for name, v := range map[string]int{
		"min_ttl":      c.Cache.MinTTL,
		"max_ttl":      c.Cache.MaxTTL,
		"negative_ttl": c.Cache.NegativeTTL,
	} {
		if v < 0 || v > maxTTL {
			return fmt.Errorf("cache.%s must be between 0 and %d, got %d", name, maxTTL, v)
		}
	}
	if c.Feeds.RefreshInterval.D() > 0 && c.Feeds.RefreshInterval.D() < time.Minute {
		return fmt.Errorf("feed refresh_interval must be at least 1m")
	}

	switch c.HTTP.SecureCookies {
	case "", "auto", "always", "never":
	default:
		return fmt.Errorf("http.secure_cookies must be auto, always, or never, got %q", c.HTTP.SecureCookies)
	}
	if _, err := parsePrefixes(c.HTTP.TrustedProxyCIDRs); err != nil {
		return fmt.Errorf("http.trusted_proxy_cidrs: %w", err)
	}
	if _, err := parsePrefixes(c.DNS.AllowedClientCIDRs); err != nil {
		return fmt.Errorf("dns.allowed_client_cidrs: %w", err)
	}

	return c.validateNotAnOpenResolver()
}

// validateNotAnOpenResolver refuses to start a resolver that is reachable from
// anywhere with no client ACL.
//
// Failing closed here is the whole point: an open resolver is discovered and
// conscripted into amplification attacks within days, and by then it is the
// operator's IP address in the abuse report. Making them write one explicit
// line to opt in is a far smaller cost than that.
func (c *Config) validateNotAnOpenResolver() error {
	if len(c.DNS.AllowedClientCIDRs) > 0 || c.DNS.AllowPublicResolver {
		return nil
	}

	for _, listen := range []string{c.DNS.ListenUDP, c.DNS.ListenTCP, c.DNS.ListenDoT} {
		if listen == "" {
			continue
		}
		if listenIsLoopback(listen) {
			continue
		}
		return fmt.Errorf(
			"dns listener %q accepts queries from any address but dns.allowed_client_cidrs is empty, "+
				"which would make this an open resolver. Set dns.allowed_client_cidrs to the networks "+
				"you serve (e.g. [\"10.0.0.0/8\", \"192.168.0.0/16\"]), or set dns.allow_public_resolver: true "+
				"if you genuinely intend to run a public resolver", listen)
	}
	return nil
}

// listenIsLoopback reports whether a listen address is bound to loopback only,
// in which case no external client can reach it and an ACL adds nothing.
func listenIsLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		// No port separator: treat the whole string as a host.
		host = listen
	}
	if host == "" {
		return false // ":53" means every interface
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// parsePrefixes validates a CIDR list, accepting bare addresses as
// single-host prefixes.
func parsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q", raw)
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", raw)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// AllowedClientPrefixes returns the parsed client ACL. It is validated at
// load time, so an error here is not expected.
func (c *Config) AllowedClientPrefixes() []netip.Prefix {
	p, _ := parsePrefixes(c.DNS.AllowedClientCIDRs)
	return p
}

// DBPath returns the location of the SQLite database.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "dnsdaddy.db") }

// SecretPath returns the location of the generated cookie-signing secret.
func (c *Config) SecretPath() string { return filepath.Join(c.DataDir, "session.key") }
