package config

import "testing"

func TestSecurityBlankCIDRsDoNotPermitOpenResolver(t *testing.T) {
    c := &Config{}
    c.DNS.ListenUDP = "0.0.0.0:53"
    c.DNS.AllowedClientCIDRs = []string{"", "   ", "\t"}
    if err := c.validateNotAnOpenResolver(); err == nil {
        t.Fatal("blank-only configured CIDRs must not disable the open-resolver guard")
    }
    c.DNS.AllowPublicResolver = true
    if err := c.validateNotAnOpenResolver(); err != nil {
        t.Fatalf("explicit public-resolver opt-in should remain possible: %v", err)
    }
}

func TestSecurityUnclassifiedManagementHostRequiresAcknowledgement(t *testing.T) {
    c := &Config{}
    c.HTTP.Listen = "unclassified.example:8080"
    if err := c.validateManagementBind(); err == nil {
        t.Fatal("unclassified hostname must not bind an HTTP management interface without acknowledgement")
    }
    c.HTTP.AllowPublicBind = true
    if err := c.validateManagementBind(); err != nil {
        t.Fatalf("explicit public bind opt-in should be possible: %v", err)
    }
}
