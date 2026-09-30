package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/api"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/miekg/dns"
)

func transportFixtureEndpoints() []resolver.EncryptedEndpoint {
	// No server is needed: constructing or reading an Off profile must not
	// query it. Tests that activate refresh can only reach this loopback port.
	return []resolver.EncryptedEndpoint{{Protocol: "doq", Address: "127.0.0.1:65354", ServerName: "resolver.invalid"}}
}

func TestTransportSelectionPersistsIndependentlyOfDaddyboundMode(t *testing.T) {
	c, st, _, _ := controlHarness(t, false)
	before := c.ForwardRoute()
	if err := c.SetTransport(context.Background(), config.ResolutionEncrypted, transportFixtureEndpoints()); err != nil {
		t.Fatal(err)
	}
	state := c.TransportState()
	if state.Transport != config.ResolutionEncrypted || !state.EncryptedOnly || state.PlaintextFallback || state.DaddyboundMode != config.LocalDNSSECOff || state.Stats.Queries != 0 {
		t.Fatalf("transport selection changed mode or sent traffic: %+v", state)
	}
	if _, _, err := before.Begin(context.Background()); err == nil {
		t.Fatal("retired plaintext route admitted new work")
	}
	saved, err := st.GetSetting(context.Background(), api.DNSTransportSetting)
	if err != nil || !strings.Contains(saved, `"transport":"encrypted"`) {
		t.Fatalf("transport not durable: %q %v", saved, err)
	}
	// The returned inventory cannot mutate the live selection.
	state.Endpoints[0].Address = "bad.invalid:853"
	if c.TransportState().Endpoints[0].Address != transportFixtureEndpoints()[0].Address {
		t.Fatal("status exposed a mutable configuration slice")
	}
	c.Close()
	reopened, err := newDNSSECControl(context.Background(), c.cfg, st, c.log, false, "config")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.TransportState().Transport != config.ResolutionEncrypted || reopened.TransportState().ChosenBy != "dashboard" || reopened.NativeClient() != nil {
		t.Fatal("restart lost encrypted selection or enabled validation")
	}
}

func TestInvalidOrFailedTransportSaveKeepsPreviousRoute(t *testing.T) {
	c, st, _, _ := controlHarness(t, false)
	before := c.ForwardRoute()
	for _, endpoints := range [][]resolver.EncryptedEndpoint{
		nil,
		{{Protocol: "udp", Address: "127.0.0.1:53"}},
		{{Protocol: "doh3", Address: "https://resolver.invalid/dns-query"}},
	} {
		if err := c.SetTransport(context.Background(), config.ResolutionEncrypted, endpoints); err == nil || c.ForwardRoute() != before {
			t.Fatal("invalid endpoint changed the selected route")
		}
	}
	st.Close()
	if err := c.SetTransport(context.Background(), config.ResolutionEncrypted, transportFixtureEndpoints()); err == nil || c.ForwardRoute() != before {
		t.Fatal("failed persistence changed the selected route")
	}
	_, done, err := before.Begin(context.Background())
	if err != nil {
		t.Fatal("failed preparation retired the previous route")
	}
	done()
}

func TestFailedModeSaveKeepsEncryptedOffProfileInert(t *testing.T) {
	for _, mode := range []string{config.LocalDNSSECEnforce, config.LocalDNSSECObserve} {
		t.Run(mode, func(t *testing.T) {
			c, st, _, _ := controlHarness(t, false)
			c.cfg.DNS.LocalDNSSECTrustAnchorFile = ""
			if err := c.SetTransport(context.Background(), config.ResolutionEncrypted, transportFixtureEndpoints()); err != nil {
				t.Fatal(err)
			}
			selection := c.current.Load()
			route := c.ForwardRoute()
			bundle := route.Encrypted()
			before := bundle.Stats()
			st.Close()
			if err := c.SetMode(context.Background(), mode); err == nil || !strings.Contains(err.Error(), "save Daddybound mode") {
				t.Fatalf("mode did not reach the failed persistence boundary: %v", err)
			}
			if after := c.current.Load(); after != selection || after.mode != config.LocalDNSSECOff || after.runtime != nil || after.learn != nil || c.NativeClient() != nil {
				t.Fatal("failed mode save changed Off selection or published local validation work")
			}
			if c.ForwardRoute() != route || c.ForwardRoute().Encrypted() != bundle {
				t.Fatal("failed mode save replaced the approved encrypted route")
			}
			if after := bundle.Stats(); !reflect.DeepEqual(before, after) {
				t.Fatalf("failed mode save started encrypted validation or anchor refresh: before=%+v after=%+v", before, after)
			}
			_, done, err := route.Begin(context.Background())
			if err != nil {
				t.Fatalf("failed mode save retired the original approved route: %v", err)
			}
			done()
		})
	}
}

func TestPinnedAndCorruptTransportSelectionsNeverFallBack(t *testing.T) {
	c, st, _, _ := controlHarness(t, false)
	c.transportPinned = true
	if err := c.SetTransport(context.Background(), config.ResolutionEncrypted, transportFixtureEndpoints()); !errors.Is(err, api.ErrDNSTransportLocked) {
		t.Fatal("pinned transport was overwritten")
	}
	c.Close()
	for _, raw := range []string{`{}`, `null`, `{"transport":"encrypted","endpoints":[]}`, `{"transport":"unknown"}`, `{"transport":"native"} {"transport":"encrypted"}`, `{"transport":"native","ignored":true}`} {
		if err := st.SetSetting(context.Background(), api.DNSTransportSetting, raw); err != nil {
			t.Fatal(err)
		}
		other, err := newDNSSECControl(context.Background(), c.cfg, st, c.log, false, "config")
		if err == nil {
			other.Close()
			t.Fatalf("corrupt saved transport silently started: %s", raw)
		}
	}
}

func TestClosedTransportControllerCannotRestart(t *testing.T) {
	c, _, engine, builds := controlHarness(t, false)
	if err := c.SetTransport(context.Background(), config.ResolutionEncrypted, transportFixtureEndpoints()); err != nil {
		t.Fatal(err)
	}
	c.Close()
	closed := c.current.Load()
	beforeBuilds, beforeCalls := builds.Load(), engine.calls.Load()
	for _, mode := range []string{config.LocalDNSSECOff, config.LocalDNSSECObserve, config.LocalDNSSECEnforce} {
		if err := c.SetMode(context.Background(), mode); err == nil {
			t.Fatalf("closed controller accepted mode %q", mode)
		}
	}
	for _, transport := range []string{config.ResolutionNative, config.ResolutionEncrypted} {
		if err := c.SetTransport(context.Background(), transport, transportFixtureEndpoints()); err == nil {
			t.Fatalf("closed controller accepted transport %q", transport)
		}
	}
	if c.current.Load() != closed || builds.Load() != beforeBuilds || engine.calls.Load() != beforeCalls || c.NativeClient() != nil {
		t.Fatal("closed controller published or constructed a replacement runtime")
	}
	if _, _, err := c.ForwardRoute().Begin(context.Background()); err == nil {
		t.Fatal("closed controller's captured route admitted network work")
	}
}

func TestEncryptedSwitchCancelsCapturedNativeQueriesWithoutRelabellingThem(t *testing.T) {
	c, _, engine, _ := controlHarness(t, false)
	c.cfg.DNS.LocalDNSSECTrustAnchorFile = ""
	c.cfg.DNS.Timeout = config.Duration(50 * time.Millisecond)
	if err := c.SetMode(context.Background(), config.LocalDNSSECEnforce); err != nil {
		t.Fatal(err)
	}
	oldClient := c.NativeClient()
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	done := make(chan native.ClientResult, 1)
	go func() { done <- oldClient.ResolveClient(context.Background(), query) }()
	select {
	case <-engine.called:
	case <-time.After(time.Second):
		t.Fatal("old native resolution did not start")
	}
	if err := c.SetTransport(context.Background(), config.ResolutionEncrypted, transportFixtureEndpoints()); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.Msg.Rcode != dns.RcodeServerFailure || result.ResolutionSource != "native" {
		t.Fatalf("retired query escaped or changed evidence source: %+v", result)
	}
	late := oldClient.ResolveClient(context.Background(), query)
	if late.Msg.Rcode != dns.RcodeServerFailure || engine.calls.Load() != 1 {
		t.Fatal("captured native pointer restarted after encrypted activation")
	}
	if !c.State().NativeAvailable || c.State().Effective != config.LocalDNSSECEnforce || c.State().Transport != config.ResolutionEncrypted {
		t.Fatal("encrypted switch disabled local Live validation")
	}
}
