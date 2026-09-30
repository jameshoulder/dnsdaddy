package recursive

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startAuthorityDNS(t *testing.T, network string, handler dns.HandlerFunc) netip.AddrPort {
	t.Helper()
	ready := make(chan struct{})
	done := make(chan error, 1)
	server := &dns.Server{Handler: handler, NotifyStartedFunc: func() { close(ready) }}
	var addr netip.AddrPort
	if network == "tcp" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.Listener = listener
		addr = listener.Addr().(*net.TCPAddr).AddrPort()
	} else {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.PacketConn = conn
		addr = conn.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("start authority: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.ShutdownContext(ctx); err != nil {
			t.Errorf("shutdown authority: %v", err)
		}
		if err := <-done; err != nil {
			t.Errorf("authority failed: %v", err)
		}
	})
	return addr
}

// The native runtime uses one overall deadline for resolution and validation.
// A dropped UDP packet must not consume that entire deadline before the next
// configured authority or root hint can even be contacted.
func TestBlackholedAuthorityLeavesTimeForBackup(t *testing.T) {
	for _, phase := range []string{"delegation", "root_priming"} {
		t.Run(phase, func(t *testing.T) {
			var primaryQueries, backupQueries atomic.Int32
			primary := startAuthorityDNS(t, "udp", func(dns.ResponseWriter, *dns.Msg) {
				primaryQueries.Add(1) // A live socket that deliberately sends nothing.
			})
			backupIP := netip.MustParseAddr("192.0.2.54")
			backup := startAuthorityDNS(t, "udp", func(w dns.ResponseWriter, q *dns.Msg) {
				backupQueries.Add(1)
				m := new(dns.Msg)
				m.SetReply(q)
				m.Authoritative = true
				name := q.Question[0].Name
				if name == "." && q.Question[0].Qtype == dns.TypeNS {
					m.Answer = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "b.root.test."}}
					m.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "b.root.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IP(backupIP.AsSlice())}}
				} else {
					m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(93, 184, 216, 34)}}
				}
				if err := w.WriteMsg(m); err != nil {
					t.Errorf("write authority answer: %v", err)
				}
			})
			primaryIP := netip.MustParseAddr("192.0.2.53")
			transport := NewNetExchanger(2*time.Second, 1232, true)
			ex := limitsExchange(func(ctx context.Context, server netip.AddrPort, q *dns.Msg) (*dns.Msg, error) {
				target := backup
				if server.Addr() == primaryIP {
					target = primary
				}
				return transport.Exchange(ctx, target, q)
			})
			minimise := false
			r := New(Config{Exchange: ex, Timeout: 2 * time.Second, AllowNonGlobalTargets: true, QnameMinimisation: &minimise,
				RootHints: []RootHint{{Name: "a.root.test.", Addr: []netip.Addr{primaryIP}}, {Name: "b.root.test.", Addr: []netip.Addr{backupIP}}}})
			if phase == "delegation" {
				r.cache.PutDelegation("example.", []string{"a.example.", "b.example."}, map[string][]netip.Addr{
					"a.example.": {primaryIP}, "b.example.": {backupIP},
				})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			res, err := r.Resolve(ctx, "www.example.", dns.TypeA)
			if err != nil {
				t.Fatalf("a blackholed primary exhausted the whole query deadline: %v (primary=%d backup=%d)", err, primaryQueries.Load(), backupQueries.Load())
			}
			if ctx.Err() != nil || res.Msg.Rcode != dns.RcodeSuccess || len(res.Msg.Answer) != 1 || primaryQueries.Load() != 1 || backupQueries.Load() == 0 {
				t.Fatalf("backup did not answer within the original operation deadline: ctx=%v result=%v primary=%d backup=%d", ctx.Err(), res, primaryQueries.Load(), backupQueries.Load())
			}
		})
	}
}

func TestNativeAuthorityReadStopsWhenTheQueryIsCancelled(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			queried := make(chan struct{}, 1)
			addr := startAuthorityDNS(t, network, func(dns.ResponseWriter, *dns.Msg) {
				queried <- struct{}{}
			})
			transport := NewNetExchanger(2*time.Second, 1232, true).(*netExchanger)
			r := New(Config{Timeout: 2 * time.Second, AllowNonGlobalTargets: true,
				Exchange: limitsExchange(func(ctx context.Context, server netip.AddrPort, q *dns.Msg) (*dns.Msg, error) {
					return transport.exchange(ctx, network, server, q)
				})})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := r.exchange(ctx, addr, query("www.example.", dns.TypeA, 1232))
				done <- err
			}()
			select {
			case <-queried:
			case <-time.After(time.Second):
				t.Fatal("authority never received the query")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("operation cancellation was replaced by a recoverable timeout: %v", err)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("cancelled authority read kept waiting for its original deadline")
			}
		})
	}
}
