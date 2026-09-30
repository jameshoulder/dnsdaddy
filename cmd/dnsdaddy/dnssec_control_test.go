package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/api"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/miekg/dns"
)

type controlEngine struct {
	called chan struct{}
	calls  atomic.Int32
}

func (e *controlEngine) Resolve(ctx context.Context, _ string, _ uint16) (*native.Answer, error) {
	if e.calls.Add(1) == 1 {
		close(e.called)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (e *controlEngine) ResolveUnchecked(ctx context.Context, n string, q uint16) (*native.Answer, error) {
	return e.Resolve(ctx, n, q)
}

func controlHarness(t *testing.T, pinned bool) (*dnssecControl, *store.Store, *controlEngine, *atomic.Int32) {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	// Off must not read this missing anchor path or start any DNS activity.
	cfg.DNS.LocalDNSSECTrustAnchorFile = filepath.Join(cfg.DataDir, "absent-anchor-file")
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	source := "config"
	if pinned {
		cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECOff
	} else {
		installation, err := st.GetSetting(context.Background(), store.SettingLocalDNSSECDefault)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ResolveLocalDNSSEC(installation)
		source = "installation_default"
	}
	ctx, cancel := context.WithCancel(context.Background())
	c, err := newDNSSECControl(ctx, cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), pinned, source)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); c.Close() })
	engine := &controlEngine{called: make(chan struct{})}
	builds := &atomic.Int32{}
	c.buildNative = func(ctx context.Context, cfg config.Config, log *slog.Logger) (*nativeRuntime, error) {
		builds.Add(1)
		client, err := native.NewClient(engine, native.ClientOptions{Timeout: time.Second, MaxInflight: 2})
		if err != nil {
			return nil, err
		}
		done := make(chan struct{})
		close(done)
		return &nativeRuntime{Client: client, done: done, stop: func() {}}, nil
	}
	return c, st, engine, builds
}

func TestNativeModeOffIsInertAndPinnedChoiceCannotBeOverridden(t *testing.T) {
	c, _, _, builds := controlHarness(t, true)
	if c.NativeClient() != nil || c.State().NativeAvailable {
		t.Fatal("off constructed native runtime")
	}
	if err := c.SetMode(context.Background(), config.LocalDNSSECEnforce); !errors.Is(err, api.ErrDNSSECModeLocked) {
		t.Fatalf("pin not respected: %v", err)
	}
	if builds.Load() != 0 {
		t.Fatal("pinned change started native work")
	}
}

func TestNativeModePersistsAndOffCancelsCapturedQueries(t *testing.T) {
	c, st, engine, builds := controlHarness(t, false)
	if err := c.SetMode(context.Background(), config.LocalDNSSECEnforce); err != nil {
		t.Fatal(err)
	}
	mode, err := st.GetSetting(context.Background(), api.DNSSECModeSetting)
	if err != nil || mode != config.LocalDNSSECEnforce {
		t.Fatalf("mode not persisted: %q %v", mode, err)
	}
	client := c.NativeClient()
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	done := make(chan native.ClientResult, 1)
	go func() { done <- client.ResolveClient(context.Background(), q) }()
	select {
	case <-engine.called:
	case <-time.After(time.Second):
		t.Fatal("query did not start")
	}
	if err := c.SetMode(context.Background(), config.LocalDNSSECOff); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.Msg.Rcode != dns.RcodeServerFailure {
			t.Fatal("canceled query escaped as success")
		}
	case <-time.After(time.Second):
		t.Fatal("off left native query running")
	}
	late := client.ResolveClient(context.Background(), q)
	if late.Msg.Rcode != dns.RcodeServerFailure || engine.calls.Load() != 1 || c.NativeClient() != nil || builds.Load() != 1 {
		t.Fatal("late captured pointer restarted native work")
	}
}

func TestNativeModeCreationFailureLeavesPreviousSelectionAndSetting(t *testing.T) {
	c, st, _, _ := controlHarness(t, false)
	if err := c.SetMode(context.Background(), config.LocalDNSSECOff); err != nil {
		t.Fatal(err)
	}
	c.buildNative = func(context.Context, config.Config, *slog.Logger) (*nativeRuntime, error) {
		return nil, errors.New("fixture anchor validation failure")
	}
	if err := c.SetMode(context.Background(), config.LocalDNSSECEnforce); err == nil {
		t.Fatal("failed native runtime published")
	}
	mode, _ := st.GetSetting(context.Background(), api.DNSSECModeSetting)
	if mode != config.LocalDNSSECOff || c.State().Effective != config.LocalDNSSECOff {
		t.Fatal("failed activation changed persisted/effective mode")
	}
}

func TestNativeModeWriteFailureDoesNotPublishRuntime(t *testing.T) {
	c, st, _, builds := controlHarness(t, false)
	if _, err := st.DB().Exec(`CREATE TRIGGER reject_mode BEFORE INSERT ON settings WHEN NEW.key='dnssec.mode' BEGIN SELECT RAISE(FAIL,'fixture write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := c.SetMode(context.Background(), config.LocalDNSSECEnforce); err == nil {
		t.Fatal("database failure was ignored")
	}
	if c.NativeClient() != nil || c.State().Effective != config.LocalDNSSECOff || builds.Load() != 1 {
		t.Fatal("uncommitted selection exposed")
	}
}

func TestStoppedLearnRetainsLateDropCountersWithoutRemainingActive(t *testing.T) {
	c, _, _, builds := controlHarness(t, false)
	if err := c.SetMode(context.Background(), config.LocalDNSSECObserve); err != nil {
		t.Fatal(err)
	}
	captured := c.current.Load().learn.observer
	if !c.State().ObserverActive || c.State().Observer == nil {
		t.Fatal("active Learn is not reporting")
	}
	if err := c.SetMode(context.Background(), config.LocalDNSSECOff); err != nil {
		t.Fatal(err)
	}
	if captured.Observe(observe.Request{}) {
		t.Fatal("retired observer accepted work")
	}
	state := c.State()
	if state.ObserverActive || state.NativeAvailable || state.Observer == nil || state.Observer.Stats().Dropped != 1 {
		t.Fatalf("late drop hidden or stopped observer reported active: %+v", state)
	}
	if builds.Load() != 1 {
		t.Fatal("reading retained counters restarted native work")
	}
}
