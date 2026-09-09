package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
)

// TestOffModeConstructsNothing is Phase 3 of the observe-mode brief.
//
// "off" must be indistinguishable from a build without the feature. Not
// "cheap" — absent: no validator, no worker, no trust anchor parsed, no
// upstream touched. The check is that nothing is constructed at all, because a
// validator that exists but is not called still holds memory, still needs its
// anchors to parse at startup, and still gives a future edit somewhere to
// accidentally start using it.
func TestOffModeConstructsNothing(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, mode := range []string{config.LocalDNSSECOff, ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			cfg := config.Default()
			cfg.DNS.LocalDNSSECValidation = mode
			// A trust anchor file that does not exist. In off mode nothing
			// may read it, so this passing is itself evidence that no anchor
			// loading happened.
			cfg.DNS.LocalDNSSECTrustAnchorFile = "/nonexistent/anchors"

			got, err := startDNSSECObserver(context.Background(), cfg, nil, nil, log)
			if err != nil {
				t.Fatalf("off mode returned an error: %v", err)
			}
			if got != nil {
				t.Fatal("off mode constructed an observer")
			}
		})
	}
}

// TestOffModeHandsTheHandlerATrueNil is a Go trap worth a test of its own.
//
// A nil *dnssecObservation assigned straight into the interface field would
// make the handler's `if h.dnssec == nil` false, and every query would call
// through a nil pointer. The bug would appear only in off mode, which is the
// default, and only at runtime.
func TestOffModeHandsTheHandlerATrueNil(t *testing.T) {
	var d *dnssecObservation
	if got := observerOrNil(d); got != nil {
		t.Fatal("a nil observation became a non-nil interface; the handler's nil check would not fire")
	}

	var iface dnsserver.DNSSECObserver = observerOrNil(nil)
	if iface != nil {
		t.Fatal("observerOrNil(nil) is not nil")
	}
}

// TestObserveModeRefusesToStartWithoutUsableAnchors.
//
// An operator who configured observe mode and got a silently disabled
// validator would draw conclusions from an empty dataset. Failing startup is
// the honest outcome, and it is the same reasoning as refusing "enforce".
func TestObserveModeRefusesToStartWithoutUsableAnchors(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Default()
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECObserve
	cfg.DNS.LocalDNSSECTrustAnchorFile = "/nonexistent/anchors"

	if _, err := startDNSSECObserver(context.Background(), cfg, nil, nil, log); err == nil {
		t.Fatal("observe mode started with an unreadable trust anchor file")
	}
}
