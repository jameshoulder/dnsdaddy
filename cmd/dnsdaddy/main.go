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
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
	"github.com/jameshoulder/dnsdaddy/internal/httpx"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/querylog"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/jameshoulder/dnsdaddy/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "dnsdaddy: %v\n", err)
		os.Exit(1)
	}
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

	// --- DNS listeners ------------------------------------------------------
	trustedProxies, err := httpx.ParseTrustedProxies(cfg.HTTP.TrustedProxyCIDRs)
	if err != nil {
		return fmt.Errorf("http.trusted_proxy_cidrs: %w", err)
	}

	allowedClients := cfg.AllowedClientPrefixes()
	if len(allowedClients) > 0 {
		log.Info("dns client ACL active", "allowed_cidrs", cfg.DNS.AllowedClientCIDRs)
	} else if cfg.DNS.AllowPublicResolver {
		log.Warn("running as a PUBLIC resolver: dns.allow_public_resolver is set and no client ACL " +
			"is configured. An open resolver will be found and abused for DNS amplification; " +
			"make sure a firewall restricts port 53 to networks you serve")
	}

	handler := dnsserver.NewHandler(engine, res, lists, qlog, log, dnsserver.HandlerOptions{
		LogClientIP:     cfg.Log.LogClientIP,
		QueryLogEnabled: cfg.Log.QueryLog,
		Timeout:         cfg.DNS.Timeout.D() + time.Second,
		AllowedClients:  allowedClients,
		RefuseANY:       cfg.DNS.RefuseANY,
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
		log.Info("generated an initial admin password",
			"password", generated,
			"also_written_to", filepath.Join(cfg.DataDir, "initial-password.txt"))
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
		Auth:           auth,
		Log:            log,
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

	log.Info("stopped")
	return nil
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
