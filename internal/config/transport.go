package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	ResolutionNative    = "native"
	ResolutionEncrypted = "encrypted"
)

// EncryptedUpstream is an operator-approved recursive resolver. Its literal
// bootstrap addresses avoid asking plaintext DNS how to reach encrypted DNS.
// A bootstrap address is a dial target, never a substitute for certificate
// authentication against ServerName (or the endpoint hostname).
type EncryptedUpstream struct {
	Protocol     string   `yaml:"protocol" json:"protocol"`
	Address      string   `yaml:"address" json:"address"`
	ServerName   string   `yaml:"server_name,omitempty" json:"serverName"`
	BootstrapIPs []string `yaml:"bootstrap_ips,omitempty" json:"bootstrapIPs"`
}

func (d DNS) TransportMode() string {
	if d.ResolutionTransport == "" {
		return ResolutionNative
	}
	return d.ResolutionTransport
}

func (d DNS) TransportConfigured() bool { return d.ResolutionTransport != "" }

// Environment deployments need both the transport selection and its endpoint
// bundle. Accept the same JSON field names as the dashboard API, with strict
// decoding so a misspelled bootstrap field cannot silently change DNS setup.
func applyEncryptedUpstreamsEnv(d *DNS) error {
	const key = "DNSDADDY_ENCRYPTED_UPSTREAMS"
	raw, present := os.LookupEnv(key)
	if !present {
		return nil
	}
	if len(raw) > 64<<10 {
		return fmt.Errorf("%s exceeds its 64 KiB limit", key)
	}
	var endpoints []EncryptedUpstream
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&endpoints); err != nil {
		return fmt.Errorf("%s must be a JSON array of encrypted endpoints: %w", key, err)
	}
	if endpoints == nil {
		return fmt.Errorf("%s must be a JSON array; use [] to clear it", key)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("%s must contain exactly one JSON array", key)
	}
	d.EncryptedUpstreams = endpoints
	return nil
}

// ValidateTransport checks selection shape without starting any network work.
// The transport constructor also validates every endpoint before activation.
func (d DNS) ValidateTransport() error {
	switch d.ResolutionTransport {
	case "", ResolutionNative, ResolutionEncrypted:
	default:
		return fmt.Errorf("dns.resolution_transport must be native or encrypted")
	}
	if len(d.EncryptedUpstreams) > 16 {
		return fmt.Errorf("dns.encrypted_upstreams permits at most 16 approved endpoints")
	}
	if d.ResolutionTransport == "" && len(d.EncryptedUpstreams) != 0 {
		return fmt.Errorf("set dns.resolution_transport when configuring encrypted_upstreams")
	}
	if d.ResolutionTransport == ResolutionEncrypted && len(d.EncryptedUpstreams) == 0 {
		return fmt.Errorf("encrypted transport requires at least one approved encrypted_upstreams endpoint")
	}
	return nil
}
