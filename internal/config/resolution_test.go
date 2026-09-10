package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

// write puts a configuration file on disk and loads it.
func write(t *testing.T, body string) (config.Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dnsdaddy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the configuration: %v", err)
	}
	return config.Load(path)
}

// Native mode needs no upstreams.
//
// They were unconditionally required, which is right for a forwarder and
// nonsense for a resolver that never contacts one: an operator switching to
// native should not have to keep a Quad9 address in their file to satisfy a
// check that no longer applies to them.
func TestNativeModeNeedsNoUpstreams(t *testing.T) {
	// Explicitly empty, which is the case the validation governs. Omitting the
	// key entirely leaves the built-in defaults in place — configuration is
	// unmarshalled over Default(), so an absent key means "keep the default"
	// throughout this file and native mode does not change that.
	cfg, err := write(t, `
data_dir: /tmp/dnsdaddy-test
dns:
  resolution_mode: native
  upstreams: []
  listen_udp: "127.0.0.1:5353"
  allowed_client_cidrs: ["127.0.0.0/8"]
`)
	if err != nil {
		t.Fatalf("native mode with no upstreams was refused: %v", err)
	}
	if !cfg.DNS.Native() {
		t.Errorf("mode is %q, want native", cfg.DNS.EffectiveResolutionMode())
	}
	if len(cfg.DNS.Upstreams) != 0 {
		t.Errorf("upstreams were invented: %v", cfg.DNS.Upstreams)
	}
}

// Forward mode with nothing to forward to is a startup error, and the message
// points at the way out.
func TestForwardModeWithNoUpstreamsIsRefused(t *testing.T) {
	_, err := write(t, `
data_dir: /tmp/dnsdaddy-test
dns:
  resolution_mode: forward
  upstreams: []
  listen_udp: "127.0.0.1:5353"
  allowed_client_cidrs: ["127.0.0.0/8"]
`)
	if err == nil {
		t.Fatal("forward mode with no upstreams started")
	}
	if !strings.Contains(err.Error(), "native") {
		t.Errorf("the error does not mention the alternative: %v", err)
	}
}

// An unknown mode is refused rather than defaulted.
//
// A typo silently becoming forward would mean an operator who wrote "Native"
// gets a forwarder and never finds out.
func TestAnUnknownResolutionModeIsRefused(t *testing.T) {
	_, err := write(t, `
data_dir: /tmp/dnsdaddy-test
dns:
  resolution_mode: recursive
  upstreams: ["1.1.1.1:53"]
  listen_udp: "127.0.0.1:5353"
  allowed_client_cidrs: ["127.0.0.0/8"]
`)
	if err == nil {
		t.Fatal("an unrecognised resolution_mode started")
	}
	if !strings.Contains(err.Error(), "resolution_mode") {
		t.Errorf("the error does not name the setting: %v", err)
	}
}

// An existing installation keeps forwarding.
//
// The migration rule for this milestone: a deployment that was upgraded must
// not change how it resolves DNS because it was upgraded. A configuration
// written before resolution_mode existed says nothing about it, and the
// absence has to mean "carry on".
func TestAConfigurationWrittenBeforeThisFeatureKeepsForwarding(t *testing.T) {
	cfg, err := write(t, `
data_dir: /tmp/dnsdaddy-test
dns:
  upstreams:
    - "tls://9.9.9.9:853#dns.quad9.net"
  listen_udp: "127.0.0.1:5353"
  allowed_client_cidrs: ["127.0.0.0/8"]
`)
	if err != nil {
		t.Fatalf("an existing configuration stopped loading: %v", err)
	}
	if cfg.DNS.Native() {
		t.Fatal("an upgrade silently switched an existing installation to native resolution; " +
			"a release must not change how somebody's DNS is resolved without them asking")
	}
	if got := cfg.DNS.EffectiveResolutionMode(); got != config.ResolutionForward {
		t.Errorf("mode = %q, want %q", got, config.ResolutionForward)
	}
	if len(cfg.DNS.Upstreams) != 1 {
		t.Errorf("the configured upstream was lost: %v", cfg.DNS.Upstreams)
	}
}

// The default, on a fresh install with no file at all, is also forward.
//
// Deliberate for this milestone rather than an oversight. Native resolution is
// new, and defaulting to it would make every fresh install the first test of
// it. See docs/daddybound/native-resolution.md on what would have to be true
// for that to change.
func TestTheDefaultIsForward(t *testing.T) {
	cfg := config.Default()
	if cfg.DNS.Native() {
		t.Fatal("the built-in default is native resolution")
	}
	if got := cfg.DNS.EffectiveResolutionMode(); got != config.ResolutionForward {
		t.Errorf("default mode = %q, want %q", got, config.ResolutionForward)
	}
}

// Native mode still accepts upstreams, so an operator can try it without
// deleting their configuration and can go back by changing one line.
func TestNativeModeToleratesLeftoverUpstreams(t *testing.T) {
	cfg, err := write(t, `
data_dir: /tmp/dnsdaddy-test
dns:
  resolution_mode: native
  upstreams:
    - "tls://9.9.9.9:853#dns.quad9.net"
  listen_udp: "127.0.0.1:5353"
  allowed_client_cidrs: ["127.0.0.0/8"]
`)
	if err != nil {
		t.Fatalf("native mode with upstreams still listed was refused: %v", err)
	}
	if !cfg.DNS.Native() {
		t.Error("the mode was overridden by the presence of upstreams")
	}
}

// Advertised addresses survive the round trip and the environment override.
func TestAdvertisedAddressesAreConfigurable(t *testing.T) {
	cfg, err := write(t, `
data_dir: /tmp/dnsdaddy-test
dns:
  upstreams: ["1.1.1.1:53"]
  listen_udp: "127.0.0.1:5353"
  allowed_client_cidrs: ["127.0.0.0/8"]
  advertised_addresses:
    - 203.0.113.10
    - "2001:db8::1"
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.DNS.AdvertisedAddresses) != 2 {
		t.Fatalf("advertised addresses = %v, want two", cfg.DNS.AdvertisedAddresses)
	}
	if cfg.DNS.AdvertisedAddresses[0] != "203.0.113.10" {
		t.Errorf("first address = %q", cfg.DNS.AdvertisedAddresses[0])
	}
}
