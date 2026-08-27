package dnsserver

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func allowClients(cidrs ...string) func(*HandlerOptions) {
	return func(o *HandlerOptions) {
		for _, c := range cidrs {
			o.AllowedClients = append(o.AllowedClients, netip.MustParsePrefix(c))
		}
	}
}

// An open resolver is found and conscripted into amplification attacks within
// days. The ACL is deliberately redundant with the host firewall.
func TestClientACLRefusesOutsiders(t *testing.T) {
	h := newHarnessWithOptions(t, nil, allowClients("192.168.0.0/16", "10.0.0.0/8"))

	tests := []struct {
		client string
		want   int
	}{
		{"192.168.1.50", dns.RcodeSuccess},
		{"10.4.4.4", dns.RcodeSuccess},
		{"203.0.113.9", dns.RcodeRefused},
		{"172.16.0.1", dns.RcodeRefused},
	}

	for _, tt := range tests {
		t.Run(tt.client, func(t *testing.T) {
			resp := h.handler.Handle(context.Background(), query("example.com", dns.TypeA), clientMeta(tt.client))
			if resp.Rcode != tt.want {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.want])
			}
		})
	}

	if got := h.handler.RefusedClients(); got != 2 {
		t.Errorf("RefusedClients = %d, want 2", got)
	}
}

func TestClientACLEmptyAllowsEverything(t *testing.T) {
	h := newHarnessWithOptions(t, nil)
	resp := h.handler.Handle(context.Background(), query("example.com", dns.TypeA), clientMeta("203.0.113.9"))
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR with no ACL configured", dns.RcodeToString[resp.Rcode])
	}
}

// A DoH or DoT client presents a per-network token, which identifies it far
// better than a source address ever could. A roaming laptop on a coffee-shop
// IP must not be locked out by the LAN ACL.
func TestClientACLNotAppliedToTokenAuthenticatedClients(t *testing.T) {
	h := newHarnessWithOptions(t, nil, allowClients("192.168.0.0/16"))

	meta := clientMeta("203.0.113.9")
	meta.networkID = "n_test"
	meta.proto = "doh"

	resp := h.handler.Handle(context.Background(), query("example.com", dns.TypeA), meta)
	if resp.Rcode == dns.RcodeRefused {
		t.Error("a token-authenticated client was refused by the IP ACL")
	}
}

// A refused client must not be able to write rows into the query log; that
// would turn the ACL into a free disk-filling primitive.
func TestRefusedClientIsNotLogged(t *testing.T) {
	h := newHarnessWithOptions(t, nil, allowClients("192.168.0.0/16"))

	for range 5 {
		h.handler.Handle(context.Background(), query("refused.example", dns.TypeA), clientMeta("203.0.113.9"))
	}
	// One allowed query, so we are waiting for a real flush rather than
	// asserting on a batch that simply has not been written yet.
	h.handler.Handle(context.Background(), query("allowed.example", dns.TypeA), clientMeta("192.168.1.50"))

	deadline := time.Now().Add(5 * time.Second)
	var rows int64
	for time.Now().Before(deadline) {
		var err error
		rows, err = h.store.CountQueryLogRows(context.Background())
		if err != nil {
			t.Fatalf("CountQueryLogRows: %v", err)
		}
		if rows > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if rows != 1 {
		t.Errorf("query_log has %d rows, want 1 (only the allowed query)", rows)
	}
}

// RFC 8482. ANY responses are large, which is exactly what an amplification
// attack wants.
func TestANYGetsMinimalRFC8482Response(t *testing.T) {
	h := newHarnessWithOptions(t, nil, func(o *HandlerOptions) { o.RefuseANY = true })

	resp := h.handler.Handle(context.Background(), query("example.com", dns.TypeANY), clientMeta("192.168.1.50"))
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(resp.Answer))
	}
	hinfo, ok := resp.Answer[0].(*dns.HINFO)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.HINFO", resp.Answer[0])
	}
	if hinfo.Cpu != "RFC8482" {
		t.Errorf("HINFO CPU = %q, want RFC8482", hinfo.Cpu)
	}

	// The whole point is that the reply is small. A response larger than the
	// request gives an attacker leverage.
	if resp.Len() > 512 {
		t.Errorf("RFC 8482 response is %d bytes, which is not minimal", resp.Len())
	}
}

func TestANYIsForwardedWhenRefuseANYIsOff(t *testing.T) {
	h := newHarnessWithOptions(t, nil, func(o *HandlerOptions) { o.RefuseANY = false })

	resp := h.handler.Handle(context.Background(), query("example.com", dns.TypeANY), clientMeta("192.168.1.50"))
	for _, rr := range resp.Answer {
		if hinfo, ok := rr.(*dns.HINFO); ok && hinfo.Cpu == "RFC8482" {
			t.Error("ANY was answered locally with refuse_any disabled")
		}
	}
}

// The policy engine walks every suffix of a name. Without a length bound, a
// single query carrying a pathologically long name makes us do work
// proportional to its length — which is the cheap half of an asymmetric attack.
func TestAbsurdlyLongNameIsRejected(t *testing.T) {
	h := newHarnessWithOptions(t, nil)

	// Labels of 63 bytes, well past maxPresentationNameLen in total.
	label := strings.Repeat("a", 63)
	var sb strings.Builder
	for range 40 {
		sb.WriteString(label)
		sb.WriteByte('.')
	}

	req := new(dns.Msg)
	// SetQuestion would reject this, so build the question directly — a
	// malicious peer is under no obligation to use our helpers either.
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{{
		Name: sb.String(), Qtype: dns.TypeA, Qclass: dns.ClassINET,
	}}

	resp := h.handler.Handle(context.Background(), req, clientMeta("192.168.1.50"))
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("rcode = %s, want FORMERR for a %d-byte name",
			dns.RcodeToString[resp.Rcode], len(sb.String()))
	}
}

func TestNormalLengthNameIsAccepted(t *testing.T) {
	h := newHarnessWithOptions(t, nil)
	// 253 bytes is the RFC 1035 maximum and must still resolve.
	name := strings.TrimSuffix(strings.Repeat(strings.Repeat("a", 49)+".", 5), ".")
	if len(name) > 253 {
		t.Fatalf("test name is %d bytes, over the 253-byte limit", len(name))
	}
	resp := h.handler.Handle(context.Background(), query(name, dns.TypeA), clientMeta("192.168.1.50"))
	if resp.Rcode == dns.RcodeFormatError {
		t.Errorf("a %d-byte name was rejected as malformed", len(name))
	}
}

// A link-local IPv6 client arrives with a scope zone: the kernel reports the
// peer as "fe80::1%eth0", and netip.ParseAddrPort keeps the zone. netip.Prefix
// strips zones and its Contains reports false for any zoned address, so a
// client the shipped ACL plainly intends to serve — fe80::/10 is in
// config.DefaultAllowedClientCIDRs — was refused.
//
// Link-local is how a router advertises a resolver over RFC 8106 RDNSS, so
// this is a real deployment, not a curiosity.
func TestClientACLAllowsZonedLinkLocalIPv6(t *testing.T) {
	h := newHarnessWithOptions(t, nil, allowClients("fe80::/10", "192.168.0.0/16"))

	meta := requestMeta{clientAddr: netip.MustParseAddr("fe80::1%eth0"), proto: "udp"}
	resp := h.handler.Handle(context.Background(), query("example.com", dns.TypeA), meta)
	if resp.Rcode == dns.RcodeRefused {
		t.Fatal("a link-local IPv6 client inside fe80::/10 was REFUSED because its address carried a scope zone")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
}

// The same zone must not become a way around the ACL: an address outside every
// configured prefix stays refused whether or not it carries one.
func TestClientACLStillRefusesZonedAddressOutsidePrefixes(t *testing.T) {
	h := newHarnessWithOptions(t, nil, allowClients("fe80::/10"))

	meta := requestMeta{clientAddr: netip.MustParseAddr("2001:db8::1%eth0"), proto: "udp"}
	resp := h.handler.Handle(context.Background(), query("example.com", dns.TypeA), meta)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED for a zoned address outside the ACL", dns.RcodeToString[resp.Rcode])
	}
}
