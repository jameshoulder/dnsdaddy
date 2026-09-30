package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
)

func TestPreparedRuntimeCannotRefreshBeforeActivationOrAfterStop(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECEnforce
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := prepareNativeRuntimeWithTransport(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Resolver.Stats().Queries != 0 || r.Anchors.Health().Saves != 0 {
		t.Fatal("preparation sent DNS or refreshed anchors")
	}
	r.Stop()
	r.Activate()
	done := make(chan struct{})
	go func() { r.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("an unactivated preparation could not be drained")
	}
	if r.Resolver.Stats().Queries != 0 || r.Anchors.Health().Saves != 0 {
		t.Fatal("stopped preparation performed a late refresh")
	}
}

func TestPreparedTransportRetainsTheExistingTrustManager(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECEnforce
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	first, err := prepareNativeRuntimeWithTransport(context.Background(), cfg, log, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { first.Stop(); first.Wait() })
	next, err := prepareNativeRuntimeWithTransport(context.Background(), cfg, log, nil, first.Anchors)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { next.Stop(); next.Wait() })
	if next.Anchors != first.Anchors {
		t.Fatal("transport preparation created a second trust manager")
	}
	if next.Resolver.Stats().Queries != 0 || first.Anchors.Health().Saves != 0 {
		t.Fatal("paused preparation refreshed shared state")
	}
}

func TestEncryptedProfileWithoutApprovedBundleNeverConstructsNativeFallback(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECEnforce
	cfg.DNS.ResolutionTransport = config.ResolutionEncrypted
	if r, err := prepareNativeRuntimeWithTransport(context.Background(), cfg, nil, nil, nil); err == nil || r != nil {
		t.Fatalf("missing encrypted bundle fell back: runtime=%v error=%v", r, err)
	}
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECObserve
	if obs, err := startDNSSECObserver(context.Background(), cfg, nil, nil); err == nil || obs != nil {
		t.Fatalf("legacy observer created a plaintext path under encrypted selection: observer=%v error=%v", obs, err)
	}
}

func TestEncryptedRuntimePreparationHasNoNativeResolverOrBackgroundQueries(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECEnforce
	cfg.DNS.ResolutionTransport = config.ResolutionEncrypted
	// Construction validates this named endpoint using a literal bootstrap
	// address. This test never activates the runtime or sends a network request.
	upstreams, err := resolver.NewEncryptedUpstreams([]resolver.EncryptedEndpoint{{Protocol: "doh2", Address: "https://dns.example/dns-query", BootstrapIPs: []string{"192.0.2.1"}}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstreams.Close() })
	r, err := prepareNativeRuntimeWithTransport(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), upstreams, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Stop(); r.Wait() })
	if r.Resolver != nil {
		t.Fatal("encrypted profile constructed native recursion")
	}
	if _, ok := r.Engine.(*native.ForwardEngine); !ok {
		t.Fatalf("wrong answer engine: %T", r.Engine)
	}
	if _, ok := r.keySource.(*native.ForwardKeySource); !ok {
		t.Fatalf("wrong managed-key source: %T", r.keySource)
	}
	if upstreams.Stats().Queries != 0 || r.Anchors.Health().Saves != 0 {
		t.Fatal("preparation sent DNS or refreshed managed keys")
	}
}
