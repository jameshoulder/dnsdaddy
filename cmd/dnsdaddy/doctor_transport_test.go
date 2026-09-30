package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/api"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/diag"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func doctorTransportStore(t *testing.T) (*store.Store, config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, cfg
}

func doctorSetSetting(t *testing.T, st *store.Store, key, value string) {
	t.Helper()
	if err := st.SetSetting(context.Background(), key, value); err != nil {
		t.Fatal(err)
	}
}

func doctorSavedEncrypted(t *testing.T, endpoint resolver.EncryptedEndpoint) string {
	t.Helper()
	raw, err := json.Marshal(savedDNSTransport{Transport: config.ResolutionEncrypted, Endpoints: []resolver.EncryptedEndpoint{endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func doctorConfiguredEndpoint() resolver.EncryptedEndpoint {
	return resolver.EncryptedEndpoint{Protocol: "doh2", Address: "https://doctor-dns.invalid/dns-query",
		BootstrapIPs: []string{"127.0.0.1"}}
}

func TestDoctorReadsSavedTransportAndModeWithoutStartingWorkers(t *testing.T) {
	st, cfg := doctorTransportStore(t)
	raw := doctorSavedEncrypted(t, doctorConfiguredEndpoint())
	doctorSetSetting(t, st, api.DNSTransportSetting, raw)
	doctorSetSetting(t, st, store.SettingLocalDNSSECDefault, config.LocalDNSSECOff)
	doctorSetSetting(t, st, api.DNSSECModeSetting, config.LocalDNSSECEnforce)
	// Preparation must not load anchors or create a runtime. A bad path is
	// diagnosed later by the static trust-material check.
	cfg.DNS.LocalDNSSECTrustAnchorFile = filepath.Join(t.TempDir(), "missing-anchor")

	selection, effective, check := prepareDoctorTransport(context.Background(), st, cfg)
	if selection == nil || check.Status != diag.StatusPass {
		t.Fatalf("prepare: %#v", check)
	}
	defer selection.Close()
	if effective.DNS.TransportMode() != config.ResolutionEncrypted || effective.DNS.LocalDNSSECMode() != config.LocalDNSSECEnforce {
		t.Fatalf("effective transport/mode = %s/%s", effective.DNS.TransportMode(), effective.DNS.LocalDNSSECMode())
	}
	if selection.selection.transportSource != "dashboard" || len(effective.DNS.EncryptedUpstreams) != 1 {
		t.Fatalf("saved selection lost: %#v", selection.selection)
	}
	if selection.selection.runtime != nil || selection.selection.route.Encrypted().Stats().Queries != 0 {
		t.Fatal("read-only preparation started native or encrypted DNS work")
	}
	stored, err := st.GetSetting(context.Background(), api.DNSTransportSetting)
	if err != nil || stored != raw {
		t.Fatalf("doctor changed stored transport: %q, %v", stored, err)
	}
}

func TestDoctorPinnedConfigurationWinsOverCorruptSavedSelections(t *testing.T) {
	st, cfg := doctorTransportStore(t)
	doctorSetSetting(t, st, api.DNSTransportSetting, "malformed")
	doctorSetSetting(t, st, api.DNSSECModeSetting, "malformed")
	cfg.DNS.ResolutionTransport = config.ResolutionNative
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECOff
	for _, database := range []*store.Store{st, nil} {
		selection, effective, check := prepareDoctorTransport(context.Background(), database, cfg)
		if selection == nil || check.Status != diag.StatusPass {
			t.Fatalf("explicit valid settings were not used: %#v", check)
		}
		if effective.DNS.TransportMode() != config.ResolutionNative || effective.DNS.LocalDNSSECMode() != config.LocalDNSSECOff {
			t.Fatalf("unexpected effective profile: %#v", effective.DNS)
		}
		selection.Close()
	}
}

func TestDoctorCannotGuessSavedSelectionFromUnreadableDatabase(t *testing.T) {
	st, cfg := doctorTransportStore(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for _, database := range []*store.Store{st, nil} {
		selection, _, check := prepareDoctorTransport(context.Background(), database, cfg)
		if selection != nil || check.Status != diag.StatusFail {
			if selection != nil {
				selection.Close()
			}
			t.Fatalf("unreadable settings became an active profile: %#v", check)
		}
	}
}

func TestDoctorRejectsInvalidSavedSelections(t *testing.T) {
	for _, tt := range []struct {
		name, transport, mode string
	}{
		{"invalid JSON", "malformed", config.LocalDNSSECOff},
		{"unknown transport", `{"transport":"opportunistic"}`, config.LocalDNSSECOff},
		{"unknown field", `{"transport":"native","fallback":"udp"}`, config.LocalDNSSECOff},
		{"missing approved endpoints", `{"transport":"encrypted"}`, config.LocalDNSSECOff},
		{"missing literal bootstrap", `{"transport":"encrypted","endpoints":[{"protocol":"doh2","address":"https://doctor-dns.invalid/dns-query"}]}`, config.LocalDNSSECOff},
		{"invalid saved mode", `{"transport":"native"}`, "invalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st, cfg := doctorTransportStore(t)
			doctorSetSetting(t, st, api.DNSTransportSetting, tt.transport)
			doctorSetSetting(t, st, api.DNSSECModeSetting, tt.mode)
			selection, _, check := prepareDoctorTransport(context.Background(), st, cfg)
			if selection != nil || check.Status != diag.StatusFail {
				if selection != nil {
					selection.Close()
				}
				t.Fatalf("invalid settings became an active profile: %#v", check)
			}
		})
	}
}

// Keeping the packet in the socket until after doctor returns makes the
// absence assertion independent of DNS handler goroutine scheduling.
func doctorPlaintextTrap(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func doctorRequireNoPacket(t *testing.T, pc net.PacketConn) {
	t.Helper()
	if err := pc.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var wire [2048]byte
	n, _, err := pc.ReadFrom(wire[:])
	if err == nil {
		t.Fatalf("doctor leaked a %d-byte plaintext DNS datagram", n)
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("checking plaintext trap: %v", err)
	}
}

func TestDoctorInvalidConfigurationSendsNoNetworkProbes(t *testing.T) {
	plain := doctorPlaintextTrap(t)
	var webRequests atomic.Int64
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		webRequests.Add(1)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer web.Close()
	t.Setenv("DNSDADDY_UPSTREAMS", "udp://"+plain.LocalAddr().String())
	t.Setenv("DNSDADDY_HTTP_LISTEN", web.Listener.Addr().String())
	t.Setenv("DNSDADDY_DNS_LISTEN_UDP", plain.LocalAddr().String())
	t.Setenv("DNSDADDY_LOCAL_DNSSEC_VALIDATION", config.LocalDNSSECOff)
	t.Setenv("DNSDADDY_DATA_DIR", t.TempDir())
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("dns: [not valid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := net.DefaultResolver
	checks := collectDoctorChecks(context.Background(), path, 100*time.Millisecond)
	if len(checks) != 2 || checks[0].Status != diag.StatusFail || checks[1].Name != "Network probes skipped" {
		t.Fatalf("invalid config did not stop probes: %#v", checks)
	}
	if net.DefaultResolver != previous || webRequests.Load() != 0 {
		t.Fatal("invalid config reached the network phase")
	}
	doctorRequireNoPacket(t, plain)
}

func TestDoctorUnreadableSavedSelectionSendsNoNetworkProbes(t *testing.T) {
	plain := doctorPlaintextTrap(t)
	var webRequests atomic.Int64
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		webRequests.Add(1)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer web.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	dataDir := t.TempDir() // No database: the dashboard's transport is unknown.
	body := fmt.Sprintf("data_dir: %q\ndns:\n  listen_udp: %q\n  listen_tcp: ''\n  upstreams: [%q]\nhttp:\n  listen: %q\n", dataDir, plain.LocalAddr().String(), "udp://"+plain.LocalAddr().String(), web.Listener.Addr().String())
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	checks := collectDoctorChecks(context.Background(), path, 100*time.Millisecond)
	var skipped bool
	for _, check := range checks {
		skipped = skipped || check.Name == "Network probes skipped"
	}
	if !skipped || webRequests.Load() != 0 {
		t.Fatalf("unknown saved selection reached network probes: %#v", checks)
	}
	doctorRequireNoPacket(t, plain)
}

func TestDoctorNativeLiveSkipsInactiveLegacyForwarders(t *testing.T) {
	plain := doctorPlaintextTrap(t)
	cfg := config.Default()
	cfg.DNS.ResolutionTransport = config.ResolutionNative
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECEnforce
	cfg.DNS.Upstreams = []string{"udp://" + plain.LocalAddr().String()}
	checks := doctorUpstreams(context.Background(), cfg, 100*time.Millisecond)
	if len(checks) != 1 || checks[0].Name != "Native authoritative resolution" || checks[0].Status != diag.StatusPass {
		t.Fatalf("inactive upstreams were tested: %#v", checks)
	}
	doctorRequireNoPacket(t, plain)
}

func TestDoctorNativeOffAndLearnProbeActiveLegacyForwarders(t *testing.T) {
	address := answeringDNS(t)
	for _, mode := range []string{config.LocalDNSSECOff, config.LocalDNSSECObserve} {
		cfg := config.Default()
		cfg.DNS.ResolutionTransport = config.ResolutionNative
		cfg.DNS.LocalDNSSECValidation = mode
		cfg.DNS.Upstreams = []string{"udp://" + address}
		checks := doctorUpstreams(context.Background(), cfg, time.Second)
		if len(checks) != 1 || checks[0].Status != diag.StatusPass || !strings.Contains(checks[0].Name, address) {
			t.Fatalf("mode %s did not test active upstream: %#v", mode, checks)
		}
	}
}

func TestDoctorEncryptedProbeRejectsUntrustedTLSWithoutPlaintextFallback(t *testing.T) {
	plain := doctorPlaintextTrap(t)
	var connections, requests atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.Config.ErrorLog = log.New(io.Discard, "", 0)
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DNS.ResolutionTransport = config.ResolutionEncrypted
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECEnforce
	cfg.DNS.EncryptedUpstreams = []config.EncryptedUpstream{{
		Protocol: "doh2", Address: "https://doctor-dns.invalid:" + port + "/dns-query", BootstrapIPs: []string{"127.0.0.1"},
	}}
	cfg.DNS.Upstreams = []string{"udp://" + plain.LocalAddr().String()}
	checks := doctorUpstreams(context.Background(), cfg, time.Second)
	if diag.Worst(checks) != diag.StatusFail || connections.Load() == 0 || requests.Load() != 0 {
		t.Fatalf("TLS was not attempted and rejected before HTTP: connections=%d requests=%d checks=%#v", connections.Load(), requests.Load(), checks)
	}
	for _, check := range checks {
		if strings.Contains(check.Name, plain.LocalAddr().String()) {
			t.Fatalf("plaintext legacy endpoint was selected: %#v", check)
		}
	}
	doctorRequireNoPacket(t, plain)
}

type doctorUnexpectedHTTP struct{ calls *atomic.Int64 }

func (d doctorUnexpectedHTTP) RoundTrip(*http.Request) (*http.Response, error) {
	d.calls.Add(1)
	return nil, fmt.Errorf("unexpected shared HTTP transport")
}

func TestDoctorDashboardUsesDirectTransportAndDoesNotFollowRedirects(t *testing.T) {
	var sharedCalls, redirected, direct atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer destination.Close()
	dashboard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct.Add(1)
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer dashboard.Close()
	previousClient, previousTransport := http.DefaultClient, http.DefaultTransport
	http.DefaultTransport = doctorUnexpectedHTTP{calls: &sharedCalls}
	http.DefaultClient = &http.Client{Transport: doctorUnexpectedHTTP{calls: &sharedCalls}}
	t.Cleanup(func() { http.DefaultClient, http.DefaultTransport = previousClient, previousTransport })
	t.Setenv("HTTP_PROXY", destination.URL)
	t.Setenv("HTTPS_PROXY", destination.URL)
	cfg := config.Default()
	cfg.HTTP.Listen = dashboard.Listener.Addr().String()
	checks, stale := doctorWeb(context.Background(), nil, cfg, time.Second)
	if direct.Load() != 1 || sharedCalls.Load() != 0 || redirected.Load() != 0 {
		t.Fatalf("request escaped the direct local transport: direct=%d shared=%d redirected=%d", direct.Load(), sharedCalls.Load(), redirected.Load())
	}
	if len(checks) == 0 || checks[0].Status != diag.StatusFail || stale != nil || !strings.Contains(checks[0].Summary, "302") {
		t.Fatalf("redirect became a healthy dashboard result: %#v", checks)
	}
}

func TestDoctorDashboardReadsLocalHealth(t *testing.T) {
	dashboard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"status":"ok","blocklistSize":42,"clientAclStale":true}`)
	}))
	defer dashboard.Close()
	cfg := config.Default()
	cfg.HTTP.Listen = dashboard.Listener.Addr().String()
	checks, stale := doctorWeb(context.Background(), nil, cfg, time.Second)
	if len(checks) != 2 || checks[0].Status != diag.StatusPass || stale == nil || !*stale {
		t.Fatalf("local health response was lost: %#v stale=%v", checks, stale)
	}
}

func TestDoctorListenerTargetsAreLiteralAndLocal(t *testing.T) {
	for _, address := range []string{"127.0.0.1:53", "[::1]:53", "localhost:53", ":53", "0.0.0.0:53"} {
		got, err := doctorLocalProbeTarget(address)
		if err != nil {
			t.Errorf("local target %q rejected: %v", address, err)
			continue
		}
		host, _, err := net.SplitHostPort(got)
		if err != nil || net.ParseIP(host) == nil {
			t.Errorf("target %q could trigger hostname resolution: %q", address, got)
		}
	}
	for _, address := range []string{"203.0.113.99:53", "[2001:db8::99]:53", "resolver.example:53", "localhost.example:53", "invalid"} {
		if got, err := doctorLocalProbeTarget(address); err == nil {
			t.Errorf("nonlocal or unresolved target %q accepted: %q", address, got)
		}
	}
}

func TestDoctorReportsLiveValidationAndEncryptedSupportAccurately(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.LocalDNSSECValidation = config.LocalDNSSECEnforce
	cfg.DNS.ResolutionTransport = config.ResolutionEncrypted
	check := doctorLocalDNSSEC(context.Background(), cfg)
	if check.Status != diag.StatusPass || !strings.Contains(check.Summary, "independently validates") || !strings.Contains(strings.Join(check.Evidence, " "), "approved authenticated encrypted") {
		t.Fatalf("Live encrypted mode was misrepresented: %#v", check)
	}
}
