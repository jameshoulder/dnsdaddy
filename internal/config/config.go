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
	// Detection is the behavioural detection engine. It is alert-only.
	Detection Detection `yaml:"detection"`
	// Integrations is the external API provider subsystem. Off by default.
	Integrations Integrations `yaml:"integrations"`
}

// Integrations configures the "bring your own intelligence" subsystem: the
// external threat-intelligence, reputation and enrichment APIs an operator
// attaches themselves.
//
// Every value here defaults to the inert one. A deployment that never opens
// the Integrations page starts no workers, reads no provider table, and
// resolves exactly as it did before. See docs/external-apis.md.
type Integrations struct {
	// Enabled starts the engine. With it off, no worker runs and the provider
	// tables are never read — the feature costs nothing at all.
	Enabled bool `yaml:"enabled"`

	// Workers drain the lookup queue. Two is right for a small VPS: the work
	// is network-bound, and more goroutines would mostly mean more concurrent
	// requests at a metered API.
	Workers int `yaml:"workers"`

	// QueueSize bounds the lookup queue. When it is full, lookups are dropped
	// and counted rather than making anything wait — the same contract the
	// query log and the detection engine already have.
	QueueSize int `yaml:"queue_size"`

	// CacheEntries bounds the in-memory verdict cache. This is the layer the
	// resolution path reads.
	CacheEntries int `yaml:"cache_entries"`

	// ReputationMode is how far the policy engine may rely on providers:
	//
	//   off         never consulted during resolution. The default.
	//   cache_only  reads the local cache and never waits. A miss returns
	//               "unknown" at once and queues a lookup for next time.
	//   blocking    reads the cache and, on a miss, waits up to
	//               reputation_budget before failing open.
	//
	// blocking is deliberately not offered in the dashboard. It is the only
	// mode that puts a third party's latency in front of a DNS answer, and
	// that should be a decision somebody made while reading the
	// documentation rather than a radio button they clicked past. Setting it
	// here is exactly that decision.
	ReputationMode string `yaml:"reputation_mode"`

	// ReputationBudget is the hard ceiling on a blocking-mode wait. A
	// ceiling, not a target: most lookups are cache hits and cost nothing.
	ReputationBudget Duration `yaml:"reputation_budget"`

	// Enrichment attaches provider context to query-log rows and findings.
	// Always asynchronous, never on the resolution path.
	Enrichment bool `yaml:"enrichment"`

	// DefaultCacheTTL is how long a verdict stays fresh when the provider
	// gives no hint of its own.
	DefaultCacheTTL Duration `yaml:"default_cache_ttl"`
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

	// DNSSECTelemetry sets the AD bit on outgoing queries so a validating
	// upstream reports whether it authenticated each answer (RFC 6840 §5.7).
	//
	// This is not DNSSEC validation. DNS Daddy forwards rather than validating
	// locally, and this records the upstream's verdict — a weaker statement,
	// made honestly. It does not request DNSSEC records, so response sizes are
	// unchanged, and the AD bit is stripped again for clients that did not ask
	// for it. On by default because it costs nothing and turns an untestable
	// claim about upstream configuration into a measurement.
	DNSSECTelemetry bool `yaml:"dnssec_telemetry"`
}

// Detection controls the behavioural detection engine (internal/detect).
//
// Nothing in this section can block a query. The engine observes, scores,
// explains and alerts; enforcement stays with the reputation and policy
// engine, which is driven by curated threat intelligence rather than by
// inference. See docs/detection/README.md.
type Detection struct {
	// Enabled turns the whole engine on or off. On by default: it is
	// alert-only, bounded in memory, and off the resolution path.
	Enabled bool `yaml:"enabled"`

	// BufferSize bounds the observation queue handed over by the DNS path.
	// When it is full, observations are dropped and counted rather than
	// making a lookup wait.
	BufferSize int `yaml:"buffer_size"`

	// EvalInterval is how often closed observation windows are scored.
	EvalInterval Duration `yaml:"eval_interval"`

	// Cooldown suppresses repeat findings for the same subject and event type.
	// Without it an ongoing problem produces one alert per window until
	// somebody stops reading them.
	Cooldown Duration `yaml:"cooldown"`

	// MinSeverity drops findings below this level before they are stored or
	// exported: info, low, medium, high.
	MinSeverity string `yaml:"min_severity"`

	// RetentionDays is how long findings are kept. They outlive the raw query
	// log by default because "has this host done this before?" is a
	// months-scale question and a finding is a few kilobytes where the traffic
	// behind it was thousands of rows.
	RetentionDays int `yaml:"retention_days"`

	// ExcludedDomains adds to the built-in list of parent domains that are
	// exempt from behavioural findings — reputation services, CDNs and the
	// like, whose normal operation is shaped exactly like the behaviour these
	// detectors hunt for. Matching is suffix-based.
	ExcludedDomains []string `yaml:"excluded_domains"`

	// DisableDefaultExclusions removes the built-in exclusions entirely.
	//
	// Supported because a lab wants detections to fire on traffic the defaults
	// would suppress, and because an operator running no mail or endpoint
	// security on the monitored network may want the tightest possible net.
	// On a normal network the defaults are what make the detectors usable, so
	// this is off.
	DisableDefaultExclusions bool `yaml:"disable_default_exclusions"`

	// FindingsFile writes findings as newline-delimited JSON for a log
	// shipper to tail. Relative paths are resolved inside data_dir. Empty
	// disables the file. See docs/siem.md.
	FindingsFile string `yaml:"findings_file"`

	// FindingsFileMaxBytes triggers rotation of the NDJSON file.
	FindingsFileMaxBytes int64 `yaml:"findings_file_max_bytes"`

	// FindingsFileKeep is how many rotated NDJSON files to retain.
	FindingsFileKeep int `yaml:"findings_file_keep"`

	// WindowScale multiplies every detector's observation window.
	//
	// 1.0 is production and is what the thresholds were calibrated against.
	// Lower values exist for demonstrations: the lab profile pairs
	// window_scale 0.1 with `dnsdaddy-lab -speed 10` so a scenario produces a
	// finding in under a minute instead of after five.
	//
	// The two must move together. Scaling the window without scaling the
	// traffic puts a tenth as many queries in each window, which drops most
	// scenarios below the detectors' minimum-volume gates and produces
	// silence — the opposite of what a demonstration wants. Scaling the
	// traffic without scaling the window is harmless but pointless.
	//
	// Not a tuning knob for a real deployment. Shortening the window makes
	// every rate-based signal noisier without making the detectors more
	// sensitive, because the volume gates do not scale with it.
	WindowScale float64 `yaml:"window_scale"`
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

	// AllowPublicBind is the acknowledgement required to bind the management
	// interface somewhere the public internet could reach.
	//
	// It gates two shapes, and only those two: a wildcard listener (":8080",
	// "0.0.0.0:8080", "[::]:8080"), which on a VPS covers the public NIC
	// whether or not the operator was thinking about it; and a specific
	// globally routable address, which is unambiguous about what it publishes.
	// Loopback needs nothing, and a specific private address needs nothing
	// either — someone who types 192.168.1.50 has already said what they mean,
	// and that is exactly how the LAN deployment is configured.
	//
	// The management API is authenticated but plaintext. Setting this without
	// TLS in front of it puts an admin session cookie on the wire, which is
	// why the startup path warns every time it is used and the documented
	// public path is a reverse proxy instead.
	//
	// The container image sets it, and that is not a loophole: inside a
	// network namespace a wildcard reaches nothing until Compose publishes
	// the port, and Compose publishes it to 127.0.0.1. The setting is where
	// the deployment declares that it is providing the boundary itself.
	AllowPublicBind bool `yaml:"allow_public_bind"`
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
			DNSSECTelemetry:    true,
		},
		HTTP: HTTP{
			// Loopback, deliberately.
			//
			// This is the management interface: it can repoint a whole
			// network's DNS, read the query log and rotate credentials.
			// ":8080" would have bound it to every interface, v4 and v6, so
			// `./dnsdaddy` on a VPS published an authenticated-but-plaintext
			// admin API to the internet with nothing asked of the operator.
			//
			// Docker's own boundary is not a substitute for this one. A
			// published port is a property of the deployment; a safe default
			// is a property of the program, and the program has to be safe
			// when somebody runs the binary directly. The container image
			// still sets DNSDADDY_HTTP_LISTEN=:8080 because inside a network
			// namespace that address is not reachable until Compose publishes
			// it — and Compose publishes it to 127.0.0.1.
			//
			// Widening this is a deliberate act: see validateManagementBind,
			// which requires http.allow_public_bind for anything that is not
			// loopback or a private address.
			Listen:        "127.0.0.1:8080",
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
		Detection: Detection{
			Enabled:      true,
			BufferSize:   4096,
			EvalInterval: Duration(30 * time.Second),
			Cooldown:     Duration(15 * time.Minute),
			// Info-level findings are telemetry rather than alerts, and
			// storing them on a busy network would bury the rest.
			MinSeverity:   "low",
			RetentionDays: 30,
			// Off by default: an operator who wants findings shipped to a SIEM
			// should say so, because the file is browsing history in a second
			// place and that is their decision to make, not a default.
			FindingsFile:         "",
			FindingsFileMaxBytes: 32 << 20,
			FindingsFileKeep:     3,
			WindowScale:          1,
		},
		Integrations: Integrations{
			// Off. Everything below is what the subsystem uses once an
			// operator turns it on, and none of it runs until they do.
			Enabled:          false,
			Workers:          2,
			QueueSize:        1024,
			CacheEntries:     4096,
			ReputationMode:   "off",
			ReputationBudget: Duration(50 * time.Millisecond),
			Enrichment:       false,
			DefaultCacheTTL:  Duration(6 * time.Hour),
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
	envStr("DNSDADDY_DETECTION_MIN_SEVERITY", &cfg.Detection.MinSeverity)
	envStr("DNSDADDY_DETECTION_FINDINGS_FILE", &cfg.Detection.FindingsFile)
	envList("DNSDADDY_DETECTION_EXCLUDED_DOMAINS", &cfg.Detection.ExcludedDomains)
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
		func() error { return envBool("DNSDADDY_DNSSEC_TELEMETRY", &cfg.DNS.DNSSECTelemetry) },
		func() error { return envBool("DNSDADDY_DETECTION_ENABLED", &cfg.Detection.Enabled) },
		func() error {
			return envBool("DNSDADDY_DETECTION_DISABLE_DEFAULT_EXCLUSIONS", &cfg.Detection.DisableDefaultExclusions)
		},
		func() error { return envInt("DNSDADDY_DETECTION_RETENTION_DAYS", &cfg.Detection.RetentionDays) },
		func() error { return envDur("DNSDADDY_DETECTION_EVAL_INTERVAL", &cfg.Detection.EvalInterval) },
		func() error { return envDur("DNSDADDY_DETECTION_COOLDOWN", &cfg.Detection.Cooldown) },
		func() error { return envFloat("DNSDADDY_DETECTION_WINDOW_SCALE", &cfg.Detection.WindowScale) },
		func() error { return envBool("DNSDADDY_ALLOW_UNTOKENIZED_DOH", &cfg.HTTP.AllowUntokenizedDoH) },
		func() error { return envBool("DNSDADDY_ALLOW_PUBLIC_BIND", &cfg.HTTP.AllowPublicBind) },
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

func envFloat(key string, dst *float64) error {
	v, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return fmt.Errorf("%s=%q is not a valid number: %w", key, v, err)
	}
	*dst = f
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

	switch strings.ToLower(c.Detection.MinSeverity) {
	case "", "info", "low", "medium", "high":
	default:
		return fmt.Errorf("detection.min_severity must be info, low, medium, or high, got %q",
			c.Detection.MinSeverity)
	}
	if c.Detection.RetentionDays < 0 {
		return fmt.Errorf("detection.retention_days must not be negative")
	}
	if c.Detection.EvalInterval.D() > 0 && c.Detection.EvalInterval.D() < time.Second {
		return fmt.Errorf("detection.eval_interval must be at least 1s")
	}
	if c.Detection.WindowScale != 0 && (c.Detection.WindowScale < 0.01 || c.Detection.WindowScale > 10) {
		return fmt.Errorf("detection.window_scale must be between 0.01 and 10, got %v",
			c.Detection.WindowScale)
	}

	if err := c.validateManagementBind(); err != nil {
		return err
	}

	return c.validateNotAnOpenResolver()
}

// ManagementBindKind classifies where the dashboard and API will be reachable.
type ManagementBindKind int

const (
	// BindLoopback is reachable only from this machine.
	BindLoopback ManagementBindKind = iota
	// BindPrivate is a specific address in private or shared address space.
	BindPrivate
	// BindWildcard is every interface this host has, present and future.
	BindWildcard
	// BindPublic is a specific globally routable address.
	BindPublic
	// BindUnknown is a listen string that could not be classified — a unix
	// socket, a hostname, or something malformed.
	BindUnknown
)

func (k ManagementBindKind) String() string {
	switch k {
	case BindLoopback:
		return "loopback"
	case BindPrivate:
		return "private"
	case BindWildcard:
		return "wildcard"
	case BindPublic:
		return "public"
	default:
		return "unknown"
	}
}

// NeedsPublicBindAck reports whether this shape may only be used with an
// explicit acknowledgement.
//
// Wildcard is included because ":8080" is the shape people reach for without
// meaning it. On a laptop it is harmless; on a VPS it is the whole internet,
// and the string looks identical either way. A specific private address is
// not included: typing 192.168.1.50 is already a statement of intent, and it
// is how the LAN deployment is meant to be configured.
func (k ManagementBindKind) NeedsPublicBindAck() bool {
	return k == BindWildcard || k == BindPublic
}

// ClassifyManagementBind reports what a listen address exposes.
func ClassifyManagementBind(listen string) ManagementBindKind {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		// An empty listen address means net/http's ":http" — every interface.
		return BindWildcard
	}

	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	host = strings.Trim(host, "[]")
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i] // drop an IPv6 zone
	}

	if host == "" {
		return BindWildcard // ":8080"
	}
	if strings.EqualFold(host, "localhost") {
		return BindLoopback
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return BindUnknown
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	switch {
	case addr.IsUnspecified(): // 0.0.0.0 and ::
		return BindWildcard
	case addr.IsLoopback():
		return BindLoopback
	case addr.IsPrivate(), addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return BindPrivate
	case isSharedAddressSpace(addr):
		return BindPrivate
	default:
		return BindPublic
	}
}

// isSharedAddressSpace covers RFC 6598 carrier-grade NAT, which netip does not
// classify as private but which is never globally routable.
func isSharedAddressSpace(addr netip.Addr) bool {
	return cgnatPrefix.Contains(addr)
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// validateManagementBind refuses to publish the management interface to the
// internet by accident.
//
// The dashboard and API can repoint a whole network's DNS, read every query
// this resolver has answered, and rotate the credentials that let a device use
// it. Binding that to a public address over plain HTTP is a decision, and this
// makes the operator make it rather than inherit it from a default nobody
// chose. Docker cannot be the control here: a security property of the
// program has to hold when the program is run directly.
func (c *Config) validateManagementBind() error {
	if c.HTTP.AllowPublicBind {
		return nil
	}
	kind := ClassifyManagementBind(c.HTTP.Listen)
	if !kind.NeedsPublicBindAck() {
		return nil
	}

	shape := "binds every interface on this machine"
	if kind == BindPublic {
		shape = "is a globally routable address"
	}
	return fmt.Errorf(
		"http.listen %q %s, which would publish the management dashboard and API "+
			"in plain HTTP to anything that can reach this host. Use \"127.0.0.1:8080\" and "+
			"reach it over an SSH tunnel, or put a TLS reverse proxy in front of loopback "+
			"(see deploy/Caddyfile.example). To bind a LAN address, name it explicitly "+
			"(e.g. \"192.168.1.50:8080\"). If you genuinely intend to publish this port, "+
			"set http.allow_public_bind: true (DNSDADDY_ALLOW_PUBLIC_BIND=true)",
		c.HTTP.Listen, shape)
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

// FindingsFilePath resolves detection.findings_file against the data
// directory, so a relative path lands beside the database rather than wherever
// the process happens to have been started from. Empty means no file sink.
func (c *Config) FindingsFilePath() string {
	p := strings.TrimSpace(c.Detection.FindingsFile)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.DataDir, p)
}
