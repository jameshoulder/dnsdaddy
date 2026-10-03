package dnsserver

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Use the actual seeded database. Tests that constructed an ACL with no
// n_default row missed the first-run gate closing all non-loopback access.
func installSeededACL(t *testing.T, h *testHarness, bootstrap []string) *clientacl.Controller {
	t.Helper()
	acl := clientacl.NewController(bootstrap, false, func(ctx context.Context) ([]clientacl.Network, error) {
		networks, err := h.store.ListNetworks(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]clientacl.Network, 0, len(networks))
		for _, n := range networks {
			out = append(out, clientacl.Network{
				ID: n.ID, Name: n.Name, Enabled: n.Enabled,
				AllowResolver: n.AllowResolver, CIDRs: n.CIDRs,
			})
		}
		return out, nil
	})
	if err := acl.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.handler.acl = acl
	return acl
}

func assertClientAnswer(t *testing.T, h *testHarness, ip, domain string, want int) {
	t.Helper()
	resp := h.handler.Handle(context.Background(), query(domain, dns.TypeA), clientMeta(ip))
	if resp == nil {
		t.Fatalf("%s querying %s: no response", ip, domain)
	}
	if resp.Rcode != want {
		t.Fatalf("%s querying %s: got %s, want %s", ip, domain,
			dns.RcodeToString[resp.Rcode], dns.RcodeToString[want])
	}
	if want == dns.RcodeSuccess && len(resp.Answer) == 0 {
		t.Fatalf("%s querying %s: NOERROR without an answer", ip, domain)
	}
}

func TestFreshInstallConfiguredClientsReceiveAnswers(t *testing.T) {
	h := newHarness(t, map[string]string{"blocked.example": "malware"})
	installSeededACL(t, h, []string{
		"127.0.0.0/8", "::1/128", "192.168.1.0/24", "fd00:1::/64",
	})
	for _, ip := range []string{"127.0.0.1", "::1", "192.168.1.50", "::ffff:192.168.1.50", "fd00:1::50"} {
		t.Run(ip, func(t *testing.T) {
			assertClientAnswer(t, h, ip, "example.com", dns.RcodeSuccess)
		})
	}
	for _, ip := range []string{"192.168.2.50", "fd00:2::50", "203.0.113.9"} {
		t.Run("refuse-"+ip, func(t *testing.T) {
			assertClientAnswer(t, h, ip, "example.com", dns.RcodeRefused)
		})
	}
	// Admission is not an allow-list bypass: the standard policy still blocks.
	assertClientAnswer(t, h, "192.168.1.50", "blocked.example", dns.RcodeNameError)
}

func TestFreshInstallExplicitPublicBootstrapIsNotSuppressedOrWidened(t *testing.T) {
	h := newHarness(t, nil)
	installSeededACL(t, h, []string{"127.0.0.0/8", "203.0.113.9/32"})
	assertClientAnswer(t, h, "203.0.113.9", "example.com", dns.RcodeSuccess)
	assertClientAnswer(t, h, "203.0.113.10", "example.com", dns.RcodeRefused)
}

func TestManagedClientRecoversWithoutOpeningDefaultAccess(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	acl := installSeededACL(t, h, []string{"127.0.0.0/8", "192.168.1.0/24"})
	off, on := false, true
	if _, err := h.store.UpdateNetwork(ctx, clientacl.DefaultNetworkID,
		store.NetworkInput{AllowResolver: &off}); err != nil {
		t.Fatal(err)
	}
	if err := acl.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	assertClientAnswer(t, h, "192.168.1.50", "example.com", dns.RcodeRefused)
	assertClientAnswer(t, h, "203.0.113.9", "example.com", dns.RcodeRefused)

	name, policyID := "Home egress", "p_standard"
	cidrs := []string{"203.0.113.9/32"}
	n, err := h.store.CreateNetwork(ctx, store.NetworkInput{
		Name: &name, PolicyID: &policyID, CIDRs: &cidrs,
		Enabled: &on, AllowResolver: &on, PublicAck: &on,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if err := acl.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	assertClientAnswer(t, h, "203.0.113.9", "example.com", dns.RcodeSuccess)
	assertClientAnswer(t, h, "203.0.113.10", "example.com", dns.RcodeRefused)
	assertClientAnswer(t, h, "192.168.1.50", "example.com", dns.RcodeRefused)

	if _, err := h.store.UpdateNetwork(ctx, n.ID, store.NetworkInput{AllowResolver: &off}); err != nil {
		t.Fatal(err)
	}
	if err := acl.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	assertClientAnswer(t, h, "203.0.113.9", "example.com", dns.RcodeRefused)
}
