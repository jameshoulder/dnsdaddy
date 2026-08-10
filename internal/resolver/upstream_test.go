package resolver

import (
	"testing"
	"time"
)

func TestParseUpstream(t *testing.T) {
	tests := []struct {
		name, spec          string
		wantProto, wantAddr string
		wantServerName      string
	}{
		{"bare IP defaults to udp:53", "9.9.9.9", "udp", "9.9.9.9:53", ""},
		{"explicit udp", "udp://9.9.9.9:5353", "udp", "9.9.9.9:5353", ""},
		{"tcp", "tcp://9.9.9.9", "tcp", "9.9.9.9:53", ""},
		{"dot defaults to 853", "tls://9.9.9.9#dns.quad9.net", "tls", "9.9.9.9:853", "dns.quad9.net"},
		{"dot with explicit port", "tls://1.1.1.1:853#cloudflare-dns.com", "tls", "1.1.1.1:853", "cloudflare-dns.com"},
		{"doh", "https://dns.quad9.net/dns-query", "https", "dns.quad9.net", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ParseUpstream(tt.spec, time.Second)
			if err != nil {
				t.Fatalf("ParseUpstream(%q): %v", tt.spec, err)
			}
			if u.Protocol != tt.wantProto {
				t.Errorf("Protocol = %q, want %q", u.Protocol, tt.wantProto)
			}
			if u.Address != tt.wantAddr {
				t.Errorf("Address = %q, want %q", u.Address, tt.wantAddr)
			}
			if tt.wantServerName != "" && u.ServerName != tt.wantServerName {
				t.Errorf("ServerName = %q, want %q", u.ServerName, tt.wantServerName)
			}
		})
	}
}

func TestParseUpstreamDoTAlwaysVerifiesAName(t *testing.T) {
	// Without a server name a DoT connection to a bare IP cannot be verified,
	// which would defeat the point of encrypting the query.
	u, err := ParseUpstream("tls://9.9.9.9:853", time.Second)
	if err != nil {
		t.Fatalf("ParseUpstream: %v", err)
	}
	if u.ServerName == "" {
		t.Error("no TLS server name was derived")
	}
	if u.client.TLSConfig.InsecureSkipVerify {
		t.Error("DoT upstream was configured to skip certificate verification")
	}
}

func TestParseUpstreamRejectsUnknownScheme(t *testing.T) {
	for _, spec := range []string{"quic://9.9.9.9", "ftp://example.org", ""} {
		if _, err := ParseUpstream(spec, time.Second); err == nil {
			t.Errorf("ParseUpstream(%q) succeeded, want an error", spec)
		}
	}
}

func TestUpstreamStatsStartAtZero(t *testing.T) {
	u, err := ParseUpstream("9.9.9.9", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	q, e, avg := u.Stats()
	if q != 0 || e != 0 || avg != 0 {
		t.Errorf("Stats() = (%d, %d, %v), want zeroes", q, e, avg)
	}
}
