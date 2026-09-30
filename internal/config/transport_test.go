package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransportSelectionNeverDefaultsAnExplicitInvalidOrEmptyEncryptedChoice(t *testing.T) {
	for _, d := range []DNS{
		{ResolutionTransport: "udp"},
		{ResolutionTransport: ResolutionEncrypted},
		{EncryptedUpstreams: []EncryptedUpstream{{Protocol: "doq", Address: "resolver.invalid"}}},
	} {
		if d.ValidateTransport() == nil {
			t.Fatalf("invalid transport selection accepted: %+v", d)
		}
	}
	var unset DNS
	if unset.TransportConfigured() || unset.TransportMode() != ResolutionNative {
		t.Fatal("unspecified transport silently selected a provider")
	}
}

func TestEncryptedExampleStartsWithoutLegacyUpstreams(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "dnsdaddy.encrypted.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.TransportMode() != ResolutionEncrypted || cfg.DNS.LocalDNSSECMode() != LocalDNSSECEnforce {
		t.Fatal("encrypted example does not select Live over encrypted transport")
	}
	if len(cfg.DNS.Upstreams) != 0 || len(cfg.DNS.EncryptedUpstreams) != 1 {
		t.Fatal("example requires unused legacy resolvers or lost its explicit encrypted endpoint")
	}
	if cfg.DNS.ListenUDP != "127.0.0.1:5353" || cfg.DNS.ListenTCP != "127.0.0.1:5353" || cfg.HTTP.Listen != "127.0.0.1:8080" {
		t.Fatal("standalone example would publish a service or require privileged ports")
	}
	if cfg.DNS.AllowPublicResolver || cfg.HTTP.AllowPublicBind || !cfg.Protection.RateLimit.Enabled || !cfg.Protection.Rebinding.Enabled {
		t.Fatal("example unexpectedly widens access or disables normal local protection")
	}
	// Empty legacy upstreams remain invalid if a mode can actually use them.
	cfg.DNS.ResolutionTransport = ResolutionNative
	if cfg.validate() == nil {
		t.Fatal("native Off/Learn configuration accepted without any forwarders")
	}
}

func TestEncryptedEndpointEnvironmentOverridesYAMLAsACompleteBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`dns:
  resolution_transport: encrypted
  encrypted_upstreams:
    - protocol: doh2
      address: https://old.example/dns-query
      bootstrap_ips: [192.0.2.1]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DNSDADDY_ENCRYPTED_UPSTREAMS", `[{"protocol":"doh2","address":"https://new.example/dns-query","serverName":"new.example","bootstrapIPs":["192.0.2.2","192.0.2.3"]}]`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DNS.EncryptedUpstreams) != 1 {
		t.Fatalf("environment appended to the old approved bundle: %+v", cfg.DNS.EncryptedUpstreams)
	}
	endpoint := cfg.DNS.EncryptedUpstreams[0]
	if endpoint.Address != "https://new.example/dns-query" || endpoint.ServerName != "new.example" || strings.Join(endpoint.BootstrapIPs, ",") != "192.0.2.2,192.0.2.3" {
		t.Fatalf("environment fields were ignored: %+v", endpoint)
	}
}

func TestMalformedEncryptedEndpointEnvironmentCannotSilentlyFallBack(t *testing.T) {
	for _, raw := range []string{
		"", "null", `{}`, `[`, `[] []`,
		`[{"protocol":"doh2","address":"https://dns.example/dns-query","bootstrap_ips":["192.0.2.1"]}]`,
		strings.Repeat(" ", 64<<10) + "[]",
	} {
		t.Run(raw[:min(len(raw), 32)], func(t *testing.T) {
			t.Setenv("DNSDADDY_ENCRYPTED_UPSTREAMS", raw)
			if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "DNSDADDY_ENCRYPTED_UPSTREAMS") {
				t.Fatalf("malformed environment did not produce an actionable error: %v", err)
			}
		})
	}
	// Setting just the selection remains an error; there is no implicit provider.
	t.Setenv("DNSDADDY_RESOLUTION_TRANSPORT", ResolutionEncrypted)
	t.Setenv("DNSDADDY_ENCRYPTED_UPSTREAMS", "[]")
	if _, err := Load(""); err == nil {
		t.Fatal("encrypted selection started without an approved endpoint")
	}
}
