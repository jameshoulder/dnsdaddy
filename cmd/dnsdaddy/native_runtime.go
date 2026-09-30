package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/trustanchors"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
)

// nativeRuntime owns one local validation engine and its refresh loop. Engines
// may change transport while sharing one RFC 5011 manager, so no second writer
// can overwrite hold-down progress from an earlier snapshot of the state file.
type nativeRuntime struct {
	Engine   native.ClientEngine
	Client   *native.Client
	Resolver *recursive.Resolver // nil for encrypted forwarding; never a hidden native fallback
	Anchors  *trustanchors.Manager
	stop     context.CancelFunc
	done     chan struct{}

	ctx       context.Context
	log       *slog.Logger
	keySource trustanchors.KeySource
	mu        sync.Mutex
	prepared  bool
	activated bool
	stopped   bool
	finish    sync.Once
}

// prepareNativeRuntimeWithTransport performs no network work. The next engine
// can be fully built and configuration persisted while the old route continues
// serving. If shared is nonnil, the controller must stop/drain its old refresh
// loop before Activate; queries may already use the new engine in that interval.
// Reuse is valid only for a transport change with the same trust configuration.
func prepareNativeRuntimeWithTransport(ctx context.Context, cfg config.Config, log *slog.Logger, encrypted *resolver.EncryptedUpstreams, shared *trustanchors.Manager) (*nativeRuntime, error) {
	if cfg.DNS.LocalDNSSECMode() == config.LocalDNSSECOff {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var recursiveResolver *recursive.Resolver
	var keySource trustanchors.KeySource
	switch cfg.DNS.TransportMode() {
	case config.ResolutionNative:
		recursiveResolver = recursive.New(recursive.Config{Timeout: cfg.DNS.LocalDNSSECTimeout.D()})
		keySource = native.NewKeySource(recursiveResolver)
	case config.ResolutionEncrypted:
		if encrypted == nil {
			return nil, fmt.Errorf("encrypted local validation requires the controller's approved encrypted transport")
		}
		keySource = native.NewForwardKeySource(encrypted.Exchange)
	default:
		return nil, fmt.Errorf("unsupported local validation transport %q", cfg.DNS.TransportMode())
	}
	manager := shared
	if manager == nil {
		anchors, err := loadTrustAnchors(cfg.DNS.LocalDNSSECTrustAnchorFile)
		if err != nil {
			return nil, fmt.Errorf("local validation trust anchors: %w", err)
		}
		manager, err = trustanchors.NewManager(trustanchors.ManagerConfig{
			Zone: ".", Configured: anchors,
			Store:  trustanchors.FileStore{Path: cfg.TrustAnchorStatePath()},
			Source: keySource, Policy: dnssec.DefaultPolicy(),
			Verifier: dnssec.StdVerifier(), Limits: dnssec.DefaultLimits(), Log: log,
		})
		if err != nil {
			return nil, fmt.Errorf("local validation trust-anchor manager: %w", err)
		}
	}
	var engine native.ClientEngine
	var err error
	if recursiveResolver != nil {
		engine, err = native.New(native.Config{
			Resolver: recursiveResolver, AnchorSource: manager.Anchors,
			Policy: dnssec.DefaultPolicy(), Clock: dnssec.SystemClock{},
			Verifier: dnssec.StdVerifier(), Limits: dnssec.DefaultLimits(),
		})
	} else {
		engine, err = native.NewForwardEngine(native.ForwardConfig{
			Exchange: encrypted.Exchange, AnchorSource: manager.Anchors,
			Policy: dnssec.DefaultPolicy(), Clock: dnssec.SystemClock{},
			Verifier: dnssec.StdVerifier(), Limits: dnssec.DefaultLimits(),
		})
	}
	if err != nil {
		return nil, fmt.Errorf("local validation engine: %w", err)
	}
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
	return &nativeRuntime{Engine: engine, Client: client, Resolver: recursiveResolver,
		Anchors: manager, stop: stop, done: make(chan struct{}), ctx: rctx,
		log: log, keySource: keySource, prepared: true}, nil
}

// Activate starts the sole refresh loop after the controller has drained the
// previous owner. A stopped preparation can never send a late DNSKEY query.
func (r *nativeRuntime) Activate() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.prepared || r.activated || r.stopped {
		return
	}
	if r.ctx.Err() != nil {
		r.stopped = true
		r.finish.Do(func() { close(r.done) })
		return
	}
	r.Anchors.SetSource(r.keySource)
	if r.ctx.Err() != nil {
		r.stopped = true
		r.finish.Do(func() { close(r.done) })
		return
	}
	r.activated = true
	go func() {
		defer r.finish.Do(func() { close(r.done) })
		native.RunAnchorRefresh(r.ctx, r.Anchors, time.Now, r.log)
	}()
}

func (r *nativeRuntime) Stop() {
	if r == nil {
		return
	}
	if r.stop != nil {
		r.stop()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	if r.prepared && !r.activated {
		r.finish.Do(func() { close(r.done) })
	}
}

func (r *nativeRuntime) Wait() {
	if r != nil && r.done != nil {
		<-r.done
	}
}
