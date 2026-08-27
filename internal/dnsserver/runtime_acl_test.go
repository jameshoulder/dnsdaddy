package dnsserver

import (
	"context"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
)

// Adding or removing a permitted network in the dashboard has to change what
// the resolver accepts on the very next query. "Restart the container" was the
// old answer and is the reason the feature was unusable: an operator locked
// out by their own ACL cannot reach the dashboard to fix it, and one adding a
// client should not have to take DNS down for the whole network to do it.
func TestHandlerHonoursRuntimeACLChanges(t *testing.T) {
	networks := []clientacl.Network{}
	acl := clientacl.NewController([]string{"127.0.0.0/8"}, false,
		func(context.Context) ([]clientacl.Network, error) { return networks, nil })

	h := newHarnessWithOptions(t, nil, func(o *HandlerOptions) { o.ClientACL = acl })

	ask := func() int {
		return h.handler.Handle(context.Background(),
			query("example.com", dns.TypeA), clientMeta("192.168.1.50")).Rcode
	}

	if got := ask(); got != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED before anything permits this client", dns.RcodeToString[got])
	}

	networks = []clientacl.Network{{
		ID: "n1", Name: "Home", Enabled: true, AllowResolver: true,
		CIDRs: []string{"192.168.1.0/24"},
	}}
	if err := acl.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := ask(); got == dns.RcodeRefused {
		t.Error("a network permitted at runtime is still REFUSED; the change needed a restart")
	}

	// And revocation, which is the direction that matters for security. No
	// grace period, no cached snapshot lasting until a timer expires.
	networks[0].AllowResolver = false
	if err := acl.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := ask(); got != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED immediately after the permission was withdrawn",
			dns.RcodeToString[got])
	}
}

// Deleting the network entirely revokes just as immediately as unticking the
// box: the permission lived on the row, and the row is gone.
func TestHandlerRefusesAfterAPermittedNetworkIsDeleted(t *testing.T) {
	networks := []clientacl.Network{{
		ID: "n1", Name: "Home", Enabled: true, AllowResolver: true,
		CIDRs: []string{"192.168.1.0/24"},
	}}
	acl := clientacl.NewController([]string{"127.0.0.0/8"}, false,
		func(context.Context) ([]clientacl.Network, error) { return networks, nil })
	if err := acl.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	h := newHarnessWithOptions(t, nil, func(o *HandlerOptions) { o.ClientACL = acl })
	meta := clientMeta("192.168.1.50")
	if h.handler.Handle(context.Background(), query("example.com", dns.TypeA), meta).Rcode == dns.RcodeRefused {
		t.Fatal("precondition: the permitted network should resolve")
	}

	networks = nil
	if err := acl.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	got := h.handler.Handle(context.Background(), query("example.com", dns.TypeA), meta).Rcode
	if got != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED after the network was deleted", dns.RcodeToString[got])
	}
}

// Refusals are counted rather than logged, so an unauthorised source cannot
// fill the query log — and the counter is what tells an operator that this is
// why their clients see nothing.
func TestRuntimeRefusalsAreCounted(t *testing.T) {
	acl := clientacl.Compute([]string{"127.0.0.0/8"}, false, nil)
	h := newHarnessWithOptions(t, nil, func(o *HandlerOptions) { o.ClientACL = acl })

	before := h.handler.RefusedClients()
	h.handler.Handle(context.Background(), query("example.com", dns.TypeA), clientMeta("203.0.113.9"))
	if got := h.handler.RefusedClients(); got != before+1 {
		t.Errorf("refused counter = %d, want %d", got, before+1)
	}
}

// A nil ACL permits everything, which is what config validation allows only
// for a loopback-only deployment or a deliberate public resolver. Asserted so
// the interface change cannot quietly start failing closed and breaking those.
func TestNilACLPermitsEverything(t *testing.T) {
	h := newHarnessWithOptions(t, nil, func(o *HandlerOptions) { o.ClientACL = nil })
	for _, ip := range []string{"203.0.113.9", "10.0.0.5"} {
		got := h.handler.Handle(context.Background(), query("example.com", dns.TypeA), clientMeta(ip)).Rcode
		if got == dns.RcodeRefused {
			t.Errorf("%s was REFUSED with no ACL configured", ip)
		}
	}
}

// A DoH or DoT client presenting a per-network token is identified by the
// token, not its source address — that is the whole point of a roaming
// profile. The ACL must not refuse it for arriving from a coffee shop.
func TestTokenIdentifiedClientBypassesTheSourceACL(t *testing.T) {
	acl := clientacl.Compute([]string{"127.0.0.0/8"}, false, nil)
	h := newHarnessWithOptions(t, nil, func(o *HandlerOptions) { o.ClientACL = acl })

	meta := requestMeta{
		clientAddr: netip.MustParseAddr("203.0.113.9"),
		proto:      "dot",
		networkID:  "n_default",
	}
	if got := h.handler.Handle(context.Background(), query("example.com", dns.TypeA), meta).Rcode; got == dns.RcodeRefused {
		t.Error("a token-identified client was refused on its source address")
	}
}
