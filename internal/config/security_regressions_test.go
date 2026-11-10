package config

import (
	"net/netip"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
)

// TestSecurityBlankCIDRsDoNotPermitOpenResolver ensures empty ACL entries never bypass the public-resolver acknowledgement.
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

// TestSecurityUnclassifiedManagementHostRequiresAcknowledgement fails closed for HTTP management listener hostnames with unknown reachability.
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

// TestSecurityBootstrapACLUsesRuntimeParser ensures a malformed mapped IPv4
// prefix cannot bypass startup checks and become an unrestricted runtime ACL.
func TestSecurityBootstrapACLUsesRuntimeParser(t *testing.T) {
	c := Default()
	c.DNS.AllowedClientCIDRs = []string{"::ffff:0:0/95"}
	if _, err := parseClientPrefixes(c.DNS.AllowedClientCIDRs); err == nil {
		t.Fatal("the bootstrap ACL accepted a mapped prefix rejected by the runtime")
	}
	if err := c.validate(); err == nil {
		t.Fatal("startup accepted an ACL that the runtime cannot enforce")
	}
	if err := c.validateNotAnOpenResolver(); err == nil {
		t.Fatal("open-resolver guard accepted a mapped prefix ignored at runtime")
	}
}

// TestSecurityMappedBootstrapCIDRMatchesRuntime verifies that a valid mapped
// IPv4 CIDR has the same effective range as the resolver's ACL.
func TestSecurityMappedBootstrapCIDRMatchesRuntime(t *testing.T) {
	c := Default()
	c.DNS.AllowedClientCIDRs = []string{"::ffff:192.0.2.0/120"}
	got := c.AllowedClientPrefixes()
	want := netip.MustParsePrefix("192.0.2.0/24")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("mapped CIDR = %v, want %s", got, want)
	}
	if err := c.validate(); err != nil {
		t.Fatalf("valid mapped CIDR rejected: %v", err)
	}
	effective := clientacl.Compute(c.DNS.AllowedClientCIDRs, false, nil)
	if effective.Unrestricted() {
		t.Fatal("valid restrictive bootstrap ACL became unrestricted")
	}
}

// TestSecurityWholeAddressFamilyRequiresExplicitPublicOptIn rejects an ACL
// that appears nonempty but effectively allows all IPv4 or IPv6 clients.
func TestSecurityWholeAddressFamilyRequiresExplicitPublicOptIn(t *testing.T) {
	cases := [][]string{
		{"0.0.0.0/0"},
		{"::/0"},
		{"::ffff:0:0/96"},
		{"0.0.0.0/1", "128.0.0.0/1"},
	}
	for _, cidrs := range cases {
		c := Default()
		c.DNS.AllowedClientCIDRs = cidrs
		if err := c.validateNotAnOpenResolver(); err == nil {
			t.Errorf("effective public ACL %v bypassed acknowledgement", cidrs)
		}
		c.DNS.AllowPublicResolver = true
		if err := c.validateNotAnOpenResolver(); err != nil {
			t.Errorf("public opt-in failed for ACL %v: %v", cidrs, err)
		}
	}
}
