package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/resolution"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// deadContext is already cancelled.
//
// startDaddybound spawns the RFC 5011 refresh loop, whose first act is to ask
// the real root for its DNSKEY RRset. These tests are about wiring, not about
// the root, and a unit test that sends UDP to the Internet is a unit test that
// fails on an aeroplane and is slow everywhere else. A cancelled context makes
// that first refresh fail immediately, without a packet, and changes nothing
// about the construction under test.
func deadContext() context.Context {
	c, cancel := context.WithCancel(context.Background())
	cancel()
	return c
}

// The configured mode selects the backend, and nothing else does.
//
// The routing test the milestone asks for. It matters more than it looks: a
// deployment that asked for native and silently got a forwarder would be one
// whose operator believes their DNS is resolved independently and validated
// locally when neither is true — and there is nothing in an answer that would
// tell them otherwise.
func TestTheConfiguredModeSelectsTheBackend(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        string
		upstreams   []string
		wantBackend string
		wantForward bool
	}{
		{
			name:        "native resolves with Daddybound",
			mode:        config.ResolutionNative,
			wantBackend: resolution.BackendNative,
			wantForward: false,
		},
		{
			name:        "forward uses the configured upstreams",
			mode:        config.ResolutionForward,
			upstreams:   []string{"1.1.1.1:53"},
			wantBackend: resolution.BackendForward,
			wantForward: true,
		},
		{
			name:        "an unset mode forwards, as every existing installation does",
			mode:        config.ResolutionUnset,
			upstreams:   []string{"1.1.1.1:53"},
			wantBackend: resolution.BackendForward,
			wantForward: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.DNS.ResolutionMode = tc.mode
			if tc.upstreams != nil {
				cfg.DNS.Upstreams = tc.upstreams
			}

			var db *daddyboundEngine
			if cfg.DNS.Native() {
				var err error
				db, err = startDaddybound(deadContext(), cfg, quietLogger())
				if err != nil {
					t.Fatalf("build Daddybound: %v", err)
				}
				if db == nil {
					t.Fatal("native mode built no Daddybound engine")
				}
			}

			backend, forwarder, err := buildBackend(cfg, db, quietLogger())
			if err != nil {
				t.Fatalf("build the backend: %v", err)
			}
			t.Cleanup(backend.Close)

			if got := backend.Name(); got != tc.wantBackend {
				t.Errorf("backend = %q, want %q", got, tc.wantBackend)
			}
			if (forwarder != nil) != tc.wantForward {
				t.Errorf("forwarder present = %v, want %v", forwarder != nil, tc.wantForward)
			}
		})
	}
}

// Native mode does not quietly build a forwarder to fall back to.
//
// There is no fallback anywhere in this design and there must be no machinery
// for one. A forwarder constructed "just in case" is a forwarder somebody will
// wire in the first time native mode has a bad afternoon, and at that point a
// bogus answer Daddybound refused would be served by the thing standing behind
// it.
func TestNativeModeBuildsNoForwarder(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.ResolutionMode = config.ResolutionNative

	db, err := startDaddybound(deadContext(), cfg, quietLogger())
	if err != nil {
		t.Fatalf("build Daddybound: %v", err)
	}
	backend, forwarder, err := buildBackend(cfg, db, quietLogger())
	if err != nil {
		t.Fatalf("build the backend: %v", err)
	}
	t.Cleanup(backend.Close)

	if forwarder != nil {
		t.Fatal("native mode built a forwarding resolver; there is no fallback and " +
			"machinery for one is how a fallback gets added later")
	}
}

// Native mode without an engine is a startup error, not a silent forward.
func TestNativeModeWithoutAnEngineRefusesToStart(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.ResolutionMode = config.ResolutionNative

	_, _, err := buildBackend(cfg, nil, quietLogger())
	if err == nil {
		t.Fatal("native mode started with no Daddybound engine")
	}
	if !strings.Contains(err.Error(), config.ResolutionNative) {
		t.Errorf("the error does not name the mode: %v", err)
	}
}

// Forward mode with Learn on builds one engine and uses it to observe; native
// mode builds one engine and uses it to serve. Never both.
//
// Part 5: once Daddybound is resolving the answer the client receives, a shadow
// resolution of the same name would double every query's outbound traffic to
// learn about the code path that is already serving.
func TestNativeModeDoesNotAlsoShadowResolve(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.ResolutionMode = config.ResolutionNative
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECObserve

	db, err := startDaddybound(deadContext(), cfg, quietLogger())
	if err != nil {
		t.Fatalf("build Daddybound: %v", err)
	}
	obs, err := startDNSSECObserver(deadContext(), cfg, db, nil, quietLogger())
	if err != nil {
		t.Fatalf("start the observer: %v", err)
	}
	if obs != nil {
		t.Fatal("native mode started a shadow observer as well as serving; " +
			"every query would be resolved twice")
	}
}

// Forward mode with Learn on does start the observer — otherwise the test
// above would pass because nothing ever starts one.
func TestForwardModeWithLearnStartsTheObserver(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.ResolutionMode = config.ResolutionForward
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECObserve

	db, err := startDaddybound(deadContext(), cfg, quietLogger())
	if err != nil {
		t.Fatalf("build Daddybound: %v", err)
	}
	if db == nil {
		t.Fatal("Learn mode built no Daddybound engine")
	}
	obs, err := startDNSSECObserver(deadContext(), cfg, db, nil, quietLogger())
	if err != nil {
		t.Fatalf("start the observer: %v", err)
	}
	if obs == nil {
		t.Fatal("forward mode with Learn on started no observer")
	}
}
