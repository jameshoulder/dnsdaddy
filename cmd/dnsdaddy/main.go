// Command dnsdaddy is an open-source protective DNS resolver.
//
// It answers DNS for a network, blocks known-malicious domains using public
// threat-intelligence feeds, records what happened in plain English, and serves
// a dashboard and management API — from one binary, on hardware that costs
// about five dollars a month.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/api"
	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/diag"
	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
	"github.com/jameshoulder/dnsdaddy/internal/httpx"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/querylog"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/jameshoulder/dnsdaddy/internal/version"
)

func main() {
	// Subcommands are matched before flag parsing so that `dnsdaddy doctor`
	// can take its own flags without the daemon's set getting in the way.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "doctor":
			if err := runDoctor(os.Args[2:]); err != nil {
				// runDoctor has already printed its findings; this is the exit
				// status, not a second explanation.
				os.Exit(1)
			}
			return
		case "help", "-h", "--help":
			usage(os.Stdout)
			return
		}
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "dnsdaddy: %v\n", err)
		os.Exit(1)
	}
}

// usage describes the two things this binary does.
func usage(w io.Writer) {
	fmt.Fprint(w, `dnsdaddy — a self-hosted protective DNS resolver

Usage:
  dnsdaddy [flags]          run the resolver
  dnsdaddy doctor [flags]   diagnose a deployment and exit
  dnsdaddy help             show this message

Run flags:
  -config path              config file (default /etc/dnsdaddy/config.yaml)
  -log-level level          debug, info, warn, error
  -log-format format        text or json
  -version                  print the version and exit

Doctor flags:
  -config path              config file
  -json                     emit findings as JSON
  -timeout duration         per-probe timeout (default 5s)

Doctor exits non-zero when a check fails, so it can gate a deployment.
`)
}

// newFlagSet returns a flag set for a subcommand that reports its own errors
// rather than exiting from inside the flag package.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func run() error {
	var (
		configPath  = flag.String("config", envOr("DNSDADDY_CONFIG", "/etc/dnsdaddy/config.yaml"), "path to the config file")
		logLevel    = flag.String("log-level", envOr("DNSDADDY_LOG_LEVEL", "info"), "log level: debug, info, warn, error")
		logFormat   = flag.String("log-format", envOr("DNSDADDY_LOG_FORMAT", "text"), "log format: text or json")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("dnsdaddy", version.String())
		return nil
	}

	log := newLogger(*logLevel, *logFormat)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir %s: %w", cfg.DataDir, err)
	}

	log.Info("starting dnsdaddy",
		"version", version.String(),
		"config", *configPath,
		"data_dir", cfg.DataDir)

	// --- storage ------------------------------------------------------------
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()
	st.SetLocalFeedDir(cfg.Feeds.LocalFeedDir)
	if cfg.Feeds.LocalFeedDir != "" {
		log.Info("file:// feeds enabled", "local_feed_dir", cfg.Feeds.LocalFeedDir)
	}

	// --- blocklists ---------------------------------------------------------
	lists := blocklist.NewHolder()
	feeds, err := blocklist.NewManager(st, lists, cfg.Feeds, cfg.DataDir, log)
	if err != nil {
		return err
	}

	// Load whatever is already on disk before opening any listener. A restart
	// must not leave a window where the resolver is answering but filtering
	// nothing.
	loadCtx, cancelLoad := context.WithTimeout(context.Background(), 2*time.Minute)
	if err := feeds.LoadFromCache(loadCtx); err != nil {
		log.Warn("could not load cached feeds", "error", err)
	}
	cancelLoad()
	log.Info("blocklist loaded from cache", "domains", lists.Load().Len())

	// --- policy engine ------------------------------------------------------
	engine := policy.NewEngine(st, lists)
	if err := engine.Reload(context.Background()); err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	// --- resolver -----------------------------------------------------------
	res, err := resolver.New(cfg.DNS, cfg.Cache, log)
	if err != nil {
		return err
	}
	defer res.Close()

	for _, u := range res.Upstreams() {
		if u.Protocol == "udp" || u.Protocol == "tcp" {
			log.Warn("upstream uses unencrypted DNS; anyone on the path can see and alter your lookups",
				"upstream", u.Spec)
		}
	}

	// --- query log ----------------------------------------------------------
	qlog := querylog.New(st, querylog.Options{
		BufferSize:      cfg.Log.BufferSize,
		FlushIntervalMS: cfg.Log.FlushIntervalMS,
	}, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go qlog.Run(ctx)

	// --- detection engine ---------------------------------------------------
	// Built before the listeners open so that no query is served while the
	// engine is half-constructed, and so a bad detection configuration is a
	// startup error rather than a surprise at the first query.
	detector, findingsFile, err := buildDetector(cfg, st, log)
	if err != nil {
		return err
	}
	if detector != nil {
		go detector.Run(ctx)
		defer func() {
			if findingsFile != nil {
				if err := findingsFile.Close(); err != nil {
					log.Warn("close findings file", "error", err)
				}
			}
		}()
	}

	// --- DNS listeners ------------------------------------------------------
	trustedProxies, err := httpx.ParseTrustedProxies(cfg.HTTP.TrustedProxyCIDRs)
	if err != nil {
		return fmt.Errorf("http.trusted_proxy_cidrs: %w", err)
	}

	// The effective client ACL: the bootstrap list from configuration, plus
	// whatever the dashboard has been told to permit. It is reloaded, not
	// re-read from config, whenever networks change — so permitting a network
	// takes effect on the next query rather than the next container restart.
	acl := clientacl.NewController(cfg.DNS.AllowedClientCIDRs, cfg.DNS.AllowPublicResolver,
		storeNetworkLoader(st))
	if err := acl.Reload(context.Background()); err != nil {
		return fmt.Errorf("load client access: %w", err)
	}

	if acl.Current().Unrestricted() {
		if cfg.DNS.AllowPublicResolver {
			log.Warn("running as a PUBLIC resolver: dns.allow_public_resolver is set and no client ACL " +
				"is configured. An open resolver will be found and abused for DNS amplification; " +
				"make sure a firewall restricts port 53 to networks you serve")
		}
	} else {
		log.Info("dns client ACL active",
			"bootstrap_cidrs", cfg.DNS.AllowedClientCIDRs,
			"dashboard_permitted", len(acl.Current().Grants()))
		// A network configured in the dashboard whose addresses the ACL does
		// not permit is the single most confusing state this software can be
		// in: everything reports healthy and every client is REFUSED. Say so
		// at startup, where `docker compose logs` will find it.
		reportClientAccess(context.Background(), st, acl.Current(), log)
	}

	handler := dnsserver.NewHandler(engine, res, lists, qlog, log, dnsserver.HandlerOptions{
		LogClientIP:     cfg.Log.LogClientIP,
		QueryLogEnabled: cfg.Log.QueryLog,
		Timeout:         cfg.DNS.Timeout.D() + time.Second,
		ClientACL:       acl,
		RefuseANY:       cfg.DNS.RefuseANY,
		Detector:        detector,
	})

	dnsSrv, err := dnsserver.NewServer(cfg.DNS, handler, log)
	if err != nil {
		return err
	}
	if err := dnsSrv.Start(ctx); err != nil {
		return fmt.Errorf("start DNS listeners: %w", err)
	}

	// --- HTTP: dashboard, API, DoH -----------------------------------------
	auth, err := api.NewAuth(st, cfg.DataDir, api.AuthOptions{
		SecureCookies:  cfg.HTTP.SecureCookies,
		TrustedProxies: trustedProxies,
	})
	if err != nil {
		return err
	}
	generated, err := auth.EnsureAdminPassword(ctx, cfg.HTTP.AdminPassword, cfg.DataDir)
	if err != nil {
		return err
	}
	if generated != "" {
		// The password itself is deliberately not logged. It used to be, which
		// meant a credential in `docker compose logs` for the life of the
		// container and in whatever log shipper an operator has pointed at it
		// — and the only reason for that was to give the installer somewhere
		// to read it from. The file is a better source: 0600, inside the data
		// volume, and the installer reads it directly.
		log.Info("generated an initial admin password",
			"written_to", filepath.Join(cfg.DataDir, "initial-password.txt"),
			"read_it_with", "docker compose exec dnsdaddy cat /var/lib/dnsdaddy/initial-password.txt")
	}

	doh := dnsserver.NewDoHHandler(handler, st, log, dnsserver.DoHOptions{
		TrustedProxies:   trustedProxies,
		AllowUntokenized: cfg.HTTP.AllowUntokenizedDoH,
	})

	restAPI := api.New(api.Deps{
		Config:         cfg,
		Store:          st,
		Engine:         engine,
		Feeds:          feeds,
		Lists:          lists,
		Resolver:       res,
		DNS:            handler,
		DoH:            doh,
		QueryLog:       qlog,
		Detector:       detector,
		Auth:           auth,
		Log:            log,
		ClientACL:      acl,
		StartedAt:      time.Now(),
		TrustedProxies: trustedProxies,
	})

	httpSrv := &http.Server{
		Addr:              cfg.HTTP.Listen,
		Handler:           restAPI.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	httpErr := make(chan error, 1)
	go func() {
		log.Info("dashboard and API listening", "addr", cfg.HTTP.Listen)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErr <- err
		}
	}()

	// --- background jobs ----------------------------------------------------
	go feeds.Run(ctx)
	go runRetention(ctx, st, cfg, log)

	if cfg.Feeds.RefreshOnStart {
		go func() {
			// Give the listeners a moment to settle before competing for the
			// single vCPU with a few hundred thousand domains of parsing.
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			if err := feeds.Refresh(ctx); err != nil {
				log.Error("initial feed refresh failed", "error", err)
				return
			}
			log.Info("initial feed refresh complete", "domains", lists.Load().Len())
		}()
	}

	log.Info("dnsdaddy ready")

	// --- wait for shutdown --------------------------------------------------
	select {
	case err := <-httpErr:
		stop()
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dnsSrv.Shutdown(shutdownCtx)
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("http shutdown", "error", err)
	}
	// The query logger drains on ctx cancellation; wait so the last few
	// seconds of activity are not lost on a restart.
	qlog.Wait()
	if detector != nil {
		detector.Wait()
	}

	log.Info("stopped")
	return nil
}

// storeNetworkLoader adapts the database to what the ACL controller needs.
//
// The adapter lives here rather than in internal/clientacl because that
// package is imported by internal/store for its write-time validation rules,
// and a dependency the other way would close the loop.
func storeNetworkLoader(st *store.Store) clientacl.Loader {
	return func(ctx context.Context) ([]clientacl.Network, error) {
		networks, err := st.ListNetworks(ctx)
		if err != nil {
			return nil, err
		}
		return store.ClientACLNetworks(networks), nil
	}
}

// reportClientAccess logs any network that cannot actually reach the resolver.
//
// It is advisory, not fatal. An operator may legitimately have a network
// defined ahead of permitting it, and refusing to start would turn a warning
// into an outage.
func reportClientAccess(ctx context.Context, st *store.Store, acl *clientacl.Set, log *slog.Logger) {
	networks, err := st.ListNetworks(ctx)
	if err != nil {
		log.Warn("could not check network reachability", "error", err)
		return
	}
	policies, err := st.ListPolicies(ctx)
	if err != nil {
		log.Warn("could not check network reachability", "error", err)
		return
	}

	// Not stale, and known so: this runs immediately after a successful
	// reload, so the snapshot in force was built from the database a moment
	// ago. Leaving it nil would report it as unknown, which is the answer for
	// a diagnostic that could not reach the daemon — not for the daemon
	// itself.
	stale := false

	checks := diag.ClientAccess(diag.ClientAccessInput{
		ACL:            acl,
		Networks:       diag.FromStoreNetworks(networks, diag.PolicyNames(policies)),
		Stale:          &stale,
		RefusedQueries: nil, // nothing has been served yet
	})

	for _, c := range diag.Failures(checks) {
		log.Warn(c.Summary, "evidence", strings.Join(c.Evidence, "; "), "action", c.Action)
	}
}

// buildDetector assembles the behavioural detection engine from configuration.
//
// It returns a nil engine when detection is switched off, which every caller
// handles: detect.Engine's Observe and Wait are nil-safe precisely so that
// turning the feature off needs no branching on the query path.
func buildDetector(cfg config.Config, st *store.Store, log *slog.Logger) (*detect.Engine, *detect.FileSink, error) {
	if !cfg.Detection.Enabled {
		log.Info("behavioural detection is disabled")
		return nil, nil, nil
	}

	exclusions := detect.NewExclusions(cfg.Detection.ExcludedDomains, cfg.Detection.DisableDefaultExclusions)
	if cfg.Detection.DisableDefaultExclusions {
		log.Warn("built-in detection exclusions are disabled; expect findings from reputation " +
			"services, CDNs and reverse DNS, whose normal traffic is shaped like the behaviour " +
			"these detectors look for")
	}

	// Sinks, in order of how much an operator relies on them. The database is
	// what the dashboard reads; the log is what a `docker logs` shows; the
	// NDJSON file is what a SIEM tails.
	sinks := detect.MultiSink{
		detect.NewStoreSink(st),
		detect.LogSink{Log: log},
	}

	var fileSink *detect.FileSink
	if path := cfg.FindingsFilePath(); path != "" {
		fs, err := detect.NewFileSink(detect.FileSinkOptions{
			Path:     path,
			MaxBytes: cfg.Detection.FindingsFileMaxBytes,
			Keep:     cfg.Detection.FindingsFileKeep,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("detection findings file: %w", err)
		}
		fileSink = fs
		sinks = append(sinks, fs)
		log.Info("writing findings as NDJSON", "path", path)
	}

	minSeverity, ok := detect.ParseSeverity(cfg.Detection.MinSeverity)
	if !ok {
		minSeverity = detect.SeverityLow
	}

	// window_scale compresses every detector's observation window. It exists
	// for demonstrations and must be paired with proportionally faster traffic
	// — see config.Detection.WindowScale.
	scale := cfg.Detection.WindowScale
	if scale <= 0 {
		scale = 1
	}
	scaleWindow := func(d time.Duration) time.Duration {
		scaled := time.Duration(float64(d) * scale)
		if scaled < time.Second {
			scaled = time.Second
		}
		return scaled
	}

	tunnelCfg := detect.DefaultTunnelConfig()
	tunnelCfg.Window = scaleWindow(tunnelCfg.Window)
	beaconCfg := detect.DefaultBeaconConfig()
	beaconCfg.Window = scaleWindow(beaconCfg.Window)
	beaconCfg.MinInterval = scaleWindow(beaconCfg.MinInterval)
	beaconCfg.MaxInterval = scaleWindow(beaconCfg.MaxInterval)
	nxCfg := detect.DefaultNXDomainConfig()
	nxCfg.Window = scaleWindow(nxCfg.Window)
	dgaCfg := detect.DefaultDGAConfig()
	dgaCfg.Window = scaleWindow(dgaCfg.Window)
	txtCfg := detect.DefaultTXTConfig()
	txtCfg.Window = scaleWindow(txtCfg.Window)
	resCfg := detect.DefaultResolutionFailureConfig()
	resCfg.Window = scaleWindow(resCfg.Window)

	if scale != 1 {
		log.Warn("detection windows are compressed; this is a demonstration setting, "+
			"not a tuning knob — the detectors' volume gates do not scale with it, so "+
			"traffic must be sped up by the same factor for findings to appear",
			"window_scale", scale)
	}

	detectors := []detect.Detector{
		detect.NewTunnelDetector(tunnelCfg),
		detect.NewBeaconDetector(beaconCfg),
		detect.NewNXDomainDetector(nxCfg),
		detect.NewDGADetector(dgaCfg),
		detect.NewTXTDetector(txtCfg),
		detect.NewResolutionFailureDetector(resCfg),
	}

	engine := detect.New(detectors, sinks, exclusions, detect.Options{
		BufferSize:   cfg.Detection.BufferSize,
		EvalInterval: cfg.Detection.EvalInterval.D(),
		Cooldown:     cfg.Detection.Cooldown.D(),
		MinSeverity:  minSeverity,
	}, log)

	log.Info("behavioural detection active",
		"detectors", len(detectors),
		"min_severity", string(minSeverity),
		"exclusions", exclusions.Len(),
		"enforcement", "none (alert-only)")

	return engine, fileSink, nil
}

// runRetention prunes the query log on a timer, honouring the configured
// retention window.
func runRetention(ctx context.Context, st *store.Store, cfg config.Config, log *slog.Logger) {
	prune := func() {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		removed, err := st.Prune(pctx, cfg.Log.RetentionDays, cfg.Log.RollupDays)
		if err != nil {
			log.Error("retention prune failed", "error", err)
			return
		}
		if removed > 0 {
			log.Info("pruned expired query-log rows",
				"rows", removed, "retention_days", cfg.Log.RetentionDays)
		}

		// Findings have their own, longer retention: they are small, and the
		// question they answer is a months-scale one.
		findings, err := st.PruneFindings(pctx, cfg.Detection.RetentionDays)
		if err != nil {
			log.Error("findings prune failed", "error", err)
			return
		}
		if findings > 0 {
			log.Info("pruned expired findings",
				"rows", findings, "retention_days", cfg.Detection.RetentionDays)
		}
	}

	// Prune shortly after boot so an install that has been off for a while
	// reclaims disk before it starts writing again.
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
		prune()
	}

	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}

func newLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	if strings.EqualFold(format, "json") {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
