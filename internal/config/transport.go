package config

import "fmt"

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
