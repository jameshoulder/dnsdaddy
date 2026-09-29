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

// nativeRuntime is one owner of the native resolver and managed anchor
// refresh. Live and Learn share this engine; running two managers against the
// same persisted RFC 5011 state would race the trust-point lifecycle.
type nativeRuntime struct {
	Engine   *native.Engine
	Client   *native.Client
	Resolver *recursive.Resolver
	Anchors  *trustanchors.Manager
	stop     context.CancelFunc
	done     chan struct{}
}

// startNativeRuntime performs no network work for an explicit Off mode. The
// mode controller calls it only after an enabled selection is accepted and
// uses the same runtime for subsequent Learn/Live transitions.
func startNativeRuntime(ctx context.Context, cfg config.Config, log *slog.Logger) (*nativeRuntime, error) {
	if cfg.DNS.LocalDNSSECMode() == config.LocalDNSSECOff {
		return nil, nil
	}
	anchors, err := loadTrustAnchors(cfg.DNS.LocalDNSSECTrustAnchorFile)
	if err != nil {
		return nil, fmt.Errorf("native trust anchors: %w", err)
	}
	resolver := recursive.New(recursive.Config{Timeout: cfg.DNS.LocalDNSSECTimeout.D()})
	manager, err := trustanchors.NewManager(trustanchors.ManagerConfig{
		Zone: ".", Configured: anchors,
		Store:  trustanchors.FileStore{Path: cfg.TrustAnchorStatePath()},
		Source: native.NewKeySource(resolver), Policy: dnssec.DefaultPolicy(),
		Verifier: dnssec.StdVerifier(), Limits: dnssec.DefaultLimits(), Log: log,
	})
	if err != nil {
		return nil, fmt.Errorf("native trust-anchor manager: %w", err)
	}
	engine, err := native.New(native.Config{
		Resolver: resolver, AnchorSource: manager.Anchors,
		Policy: dnssec.DefaultPolicy(), Clock: dnssec.SystemClock{},
		Verifier: dnssec.StdVerifier(), Limits: dnssec.DefaultLimits(),
	})
	if err != nil {
		return nil, fmt.Errorf("native engine: %w", err)
	}
	// Recursion and signatures cost more per query than forwarding. Keep a
	// conservative independent concurrency cap while honouring a smaller
	// deployment-wide DNS limit. This is a bound, not a capacity claim.
	maxInflight := 128
	if cfg.DNS.MaxInflight > 0 && cfg.DNS.MaxInflight < maxInflight {
		maxInflight = cfg.DNS.MaxInflight
	}
	client, err := native.NewClient(engine, native.ClientOptions{
		Timeout: cfg.DNS.LocalDNSSECTimeout.D(), MaxInflight: maxInflight,
	})
	if err != nil {
		return nil, err
	}
	rctx, stop := context.WithCancel(ctx)
	runtime := &nativeRuntime{Engine: engine, Client: client, Resolver: resolver,
		Anchors: manager, stop: stop, done: make(chan struct{})}
	go func() {
		defer close(runtime.done)
		native.RunAnchorRefresh(rctx, manager, time.Now, log)
	}()
	return runtime, nil
}

func (r *nativeRuntime) Stop() {
	if r != nil && r.stop != nil {
		r.stop()
	}
}

func (r *nativeRuntime) Wait() {
	if r != nil && r.done != nil {
		<-r.done
	}
}
