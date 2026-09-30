package config

import "testing"

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
