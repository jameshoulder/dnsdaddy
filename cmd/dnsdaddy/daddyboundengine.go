package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/trustanchors"
)

// daddybound is the recursive engine and the trust anchors it validates
// against, built once and used for whichever job the configuration asks for.
//
// One engine, two jobs, never both at once:
//
//   - in native resolution mode it *serves*. The answer a client receives is
//     the answer it resolved and validated;
//   - in forward mode with Learn on it *observes*. The client's answer comes
//     from the forwarder, and this resolves the same name again to record what
//     Daddybound would have concluded.
//
// The "never both" is the whole of Part 5 of this milestone. Doing both means
// resolving every query twice — once through the upstream and once from the
// root — which doubles the outbound traffic, doubles the latency budget, and
// collects evidence about a code path that is already the one serving. See
// startDaddybound's caller in main.
type daddyboundEngine struct {
	engine   *native.Engine
	resolver *recursive.Resolver
	anchors  *trustanchors.Manager
}

// startDaddybound builds the recursive engine and starts maintaining its trust
// anchors, or returns nil when nothing needs it.
//
// Nil is a normal outcome and every caller tolerates it: a deployment in
// forward mode with local validation off never constructs a validator, never
// parses a trust anchor and never sends a query from the root, so it is
// indistinguishable from one built before any of this existed.
func startDaddybound(
	ctx context.Context,
	cfg config.Config,
	log *slog.Logger,
) (*daddyboundEngine, error) {
	if !cfg.DNS.Native() && !cfg.DNS.ObserveDNSSEC() {
		return nil, nil
	}

	anchors, err := loadTrustAnchors(cfg.DNS.LocalDNSSECTrustAnchorFile)
	if err != nil {
		return nil, fmt.Errorf("daddybound: %w", err)
	}

	resolver := recursive.New(recursive.Config{
		Timeout: cfg.DNS.LocalDNSSECTimeout.D(),
	})

	// The anchors are maintained rather than fixed. The root's key rolls, and a
	// resolver holding only what its binary shipped stops validating when it
	// does — or, worse, keeps validating against a key nobody signs with and
	// reports the whole Internet Bogus. RFC 5011 lets the zone announce its own
	// key changes and lets this resolver follow them, provided every
	// announcement is signed by a key it already trusts and every addition
	// waits out a thirty-day hold-down.
	//
	// The configured anchors are never discarded: the managed set is what has
	// been learned in addition to them, so a lost or unwritable state file
	// leaves this resolver validating with what it shipped rather than with
	// nothing.
	manager, err := trustanchors.NewManager(trustanchors.ManagerConfig{
		Zone:       ".",
		Configured: anchors,
		Store:      trustanchors.FileStore{Path: cfg.TrustAnchorStatePath()},
		Source:     native.NewKeySource(resolver),
		Policy:     dnssec.DefaultPolicy(),
		Verifier:   dnssec.StdVerifier(),
		Limits:     dnssec.DefaultLimits(),
		Log:        log,
	})
	if err != nil {
		return nil, fmt.Errorf("daddybound: %w", err)
	}

	engine, err := native.New(native.Config{
		Resolver: resolver,
		// Read per question, so a revocation takes effect on the next query
		// rather than at the next restart.
		AnchorSource: manager.Anchors,
		Policy:       dnssec.DefaultPolicy(),
		Clock:        dnssec.SystemClock{},
		Verifier:     dnssec.StdVerifier(),
		Limits:       dnssec.DefaultLimits(),
	})
	if err != nil {
		return nil, fmt.Errorf("daddybound: %w", err)
	}

	// Refreshing runs on its own goroutine and never blocks a query. A refresh
	// that fails leaves the anchors in force untouched.
	go native.RunAnchorRefresh(ctx, manager, time.Now, log)

	return &daddyboundEngine{engine: engine, resolver: resolver, anchors: manager}, nil
}
