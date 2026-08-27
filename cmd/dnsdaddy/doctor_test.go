package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// blackholeUDP accepts datagrams and never answers, which is what a wedged or
// firewalled resolver looks like from a client's seat.
func blackholeUDP(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := c.ReadFrom(buf); err != nil {
				return
			}
			// Read it and say nothing.
		}
	}()
	return c.LocalAddr().String()
}

// blackholeTCP accepts connections and never speaks, which is what a plain-TCP
// listener sitting where a DoT server should be looks like.
func blackholeTCP(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	return l.Addr().String()
}

// answeringDNS starts a real DNS server that answers A queries.
func answeringDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := pc.LocalAddr().String()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(93, 184, 216, 34),
		}}
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return addr
}

// A UDP "connection" is a local socket association: net.DialTimeout succeeds
// without a packet leaving the machine, so a silent or absent resolver was
// reported as having answered. The UPSTREAM section then passed while every
// cache miss returned SERVFAIL.
func TestProbeUpstreamFailsOnASilentUDPResolver(t *testing.T) {
	p := probeUpstream("udp://"+blackholeUDP(t), 500*time.Millisecond)
	if p.Err == nil {
		t.Fatal("a resolver that never answers was reported as reachable")
	}
}

// Nothing listening at all must fail too — and on UDP that is invisible to a
// connect, because there is no handshake to refuse.
func TestProbeUpstreamFailsWhenNothingIsListening(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close() // free the port; nothing is there now

	p := probeUpstream("udp://"+addr, 500*time.Millisecond)
	if p.Err == nil {
		t.Fatalf("an absent resolver at %s was reported as reachable", addr)
	}
}

// A TCP accept proves a socket opened, not that DNS is spoken over it.
func TestProbeUpstreamFailsOnASilentTCPResolver(t *testing.T) {
	p := probeUpstream("tcp://"+blackholeTCP(t), 500*time.Millisecond)
	if p.Err == nil {
		t.Fatal("a TCP listener that speaks no DNS was reported as reachable")
	}
}

// DoT to a plain-TCP listener connects and then fails the TLS handshake. A raw
// dial cannot see that, so a broken certificate or a wrong port passed.
func TestProbeUpstreamFailsOnDoTWithoutTLS(t *testing.T) {
	p := probeUpstream("tls://"+blackholeTCP(t)+"#dns.example.com", 500*time.Millisecond)
	if p.Err == nil {
		t.Fatal("a DoT upstream with no TLS behind it was reported as reachable")
	}
}

// The probe must still pass against something that really answers, or it has
// simply traded one wrong verdict for another.
func TestProbeUpstreamPassesAgainstARealResolver(t *testing.T) {
	p := probeUpstream("udp://"+answeringDNS(t), 2*time.Second)
	if p.Err != nil {
		t.Fatalf("a working resolver was reported as failing: %v", p.Err)
	}
}

// A malformed upstream spec is a configuration error, and must be reported as
// one rather than silently skipped.
func TestProbeUpstreamReportsAnUnparseableSpec(t *testing.T) {
	p := probeUpstream("tls://", 500*time.Millisecond)
	if p.Err == nil {
		t.Fatal("an unparseable upstream spec was reported as reachable")
	}
	if !strings.Contains(p.Spec, "tls://") {
		t.Errorf("the finding does not name the spec it came from: %q", p.Spec)
	}
}
