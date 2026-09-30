package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/querylog"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/miekg/dns"
)

// Forward is a working answer path even though its stored mode is "off".
// Exercise the real DNS handler and forwarding socket around an enforced
// query, then restore the saved Forward choice over an older Live default.
func TestForwardAnswersBeforeAfterLiveAndAfterModeRestore(t *testing.T) {
	ctx := context.Background()
	control, st, nativeEngine, builds := controlHarness(t, false)
	if state := control.State(); state.Effective != config.LocalDNSSECOff || state.Locked || state.NativeAvailable {
		t.Fatalf("new installation did not start in editable Forward mode: %+v", state)
	}
	control.cfg.DNS.Upstreams = []string{"udp://" + answeringDNS(t)}
	control.cfg.Cache.Enabled = false // every assertion must exercise forwarding
	addr := forwardingModeListener(t, control)
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	client := &dns.Client{Timeout: 2 * time.Second}
	assertForward := func(addr string) {
		t.Helper()
		reply, _, err := client.Exchange(query.Copy(), addr)
		if err != nil || reply == nil {
			t.Fatalf("Forward did not answer: %v", err)
		}
		if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
			t.Fatalf("Forward lost the upstream answer: %v", reply)
		}
		if a, ok := reply.Answer[0].(*dns.A); !ok || a.A.String() != "93.184.216.34" {
			t.Fatalf("Forward changed the upstream address: %v", reply)
		}
	}
	assertForward(addr)
	if builds.Load() != 0 {
		t.Fatal("Forward constructed a local validator")
	}

	if err := control.SetMode(ctx, config.LocalDNSSECEnforce); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		msg *dns.Msg
		err error
	}
	liveResult := make(chan outcome, 1)
	go func() {
		reply, _, err := client.Exchange(query.Copy(), addr)
		liveResult <- outcome{reply, err}
	}()
	select {
	case <-nativeEngine.called:
	case <-time.After(time.Second):
		t.Fatal("Live did not use the local validator")
	}
	if err := control.SetMode(ctx, config.LocalDNSSECOff); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-liveResult:
		if result.err != nil || result.msg == nil || result.msg.Rcode != dns.RcodeServerFailure {
			t.Fatalf("cancelled Live query fell through to forwarding: %v, %v", result.msg, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("returning to Forward left Live work running")
	}
	assertForward(addr)
	if builds.Load() != 1 || nativeEngine.calls.Load() != 1 {
		t.Fatal("returning to Forward still used the local validator")
	}

	// Older releases recorded Live at installation. A dashboard choice of
	// Forward must still win when resolving the saved mode for the next boot.
	if err := st.SetSetting(ctx, store.SettingLocalDNSSECDefault, config.LocalDNSSECEnforce); err != nil {
		t.Fatal(err)
	}
	control.Close()
	restoredConfig := control.cfg
	restoredConfig.DNS.LocalDNSSECValidation = config.LocalDNSSECUnset
	if err := doctorResolveDNSSECMode(ctx, st, &restoredConfig); err != nil {
		t.Fatal(err)
	}
	if restoredConfig.DNS.LocalDNSSECMode() != config.LocalDNSSECOff {
		t.Fatal("saved Forward mode was replaced by the older Live installation default")
	}
	restored, err := newDNSSECControl(ctx, restoredConfig, st, control.log, false, "dashboard")
	if err != nil {
		t.Fatalf("restoring Forward required local validation prerequisites: %v", err)
	}
	t.Cleanup(restored.Close)
	assertForward(forwardingModeListener(t, restored))
}

func forwardingModeListener(t *testing.T, control *dnssecControl) string {
	t.Helper()
	ctx := context.Background()
	holder := blocklist.NewHolder()
	engine := policy.NewEngine(control.st, holder)
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	acl := clientacl.NewController(control.cfg.DNS.AllowedClientCIDRs, false, storeNetworkLoader(control.st))
	if err := acl.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	forwarder, err := resolver.New(control.cfg.DNS, control.cfg.Cache, control.log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(forwarder.Close)
	forwarder.SetRouteProvider(control.ForwardRoute)
	qlog := querylog.New(control.st, querylog.Options{}, control.log)
	qctx, stop := context.WithCancel(ctx)
	go qlog.Run(qctx)
	t.Cleanup(func() { stop(); qlog.Wait() })
	handler := dnsserver.NewHandler(engine, forwarder, holder, qlog, control.log, dnsserver.HandlerOptions{
		Timeout: 2 * time.Second, ClientACL: acl, Native: control, DNSSEC: control,
	})
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready, done := make(chan struct{}), make(chan error, 1)
	server := &dns.Server{PacketConn: conn, Handler: handler, NotifyStartedFunc: func() { close(ready) }}
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		_ = conn.Close()
		t.Fatalf("DNS listener did not start: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return conn.LocalAddr().String()
}
