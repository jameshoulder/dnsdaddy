package recursive

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// Hosting providers commonly put a domain's nameservers outside that domain.
// Their A and AAAA addresses must survive together: a warm address cache must
// not make a previously working IPv4 resolver depend on IPv6 connectivity.
func TestOutOfBailiwickNameserverKeepsBothAddressFamiliesOnWarmQueries(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	ns4 := netip.MustParseAddr("192.0.2.53")
	ns6 := netip.MustParseAddr("2001:db8::53")
	addressLookups := 0
	ex := limitsExchange(func(_ context.Context, server netip.AddrPort, q *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(q)
		name, typ := q.Question[0].Name, q.Question[0].Qtype
		switch server.Addr() {
		case root:
			if name == "ns.provider." {
				addressLookups++
				m.Authoritative = true
				hdr := dns.RR_Header{Name: name, Rrtype: typ, Class: dns.ClassINET, Ttl: 60}
				switch typ {
				case dns.TypeA:
					m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IP(ns4.AsSlice())}}
				case dns.TypeAAAA:
					m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IP(ns6.AsSlice())}}
				default:
					return nil, fmt.Errorf("unexpected address question: %v", q.Question)
				}
			} else {
				m.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.provider."}}
			}
		case ns4:
			m.Authoritative = true
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(93, 184, 216, 34)}}
		case ns6:
			return nil, fmt.Errorf("IPv6 route is unavailable")
		default:
			return nil, fmt.Errorf("unexpected server %s", server)
		}
		return m, nil
	})
	minimise := false
	r := New(Config{Exchange: ex, AllowNonGlobalTargets: true, QnameMinimisation: &minimise})
	r.cache.PutDelegation(".", []string{"ns.root."}, map[string][]netip.Addr{"ns.root.": {root}})

	for _, name := range []string{"first.example.", "second.example.", "third.example."} {
		res, err := r.Resolve(context.Background(), name, dns.TypeA)
		if err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		if res.Msg.Rcode != dns.RcodeSuccess || len(res.Msg.Answer) != 1 {
			t.Fatalf("resolve %s: incomplete answer %v", name, res.Msg)
		}
	}
	if addressLookups != 2 {
		t.Fatalf("warm queries did not reuse nameserver addresses: %d address lookups", addressLookups)
	}
	addrs, ok := r.cache.GetAddrs("ns.provider.")
	if !ok || len(addrs) != 2 || addrs[0] != ns4 || addrs[1] != ns6 {
		t.Fatalf("nameserver cache lost an address family: %v", addrs)
	}
}

func TestUnreachableOutOfBailiwickNameserverTriesTheDelegatedBackup(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	primary := netip.MustParseAddr("192.0.2.53")
	backup := netip.MustParseAddr("192.0.2.54")
	primaryFailed := false
	backupLookups := 0
	primaryQueries := 0
	ex := limitsExchange(func(_ context.Context, server netip.AddrPort, q *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(q)
		name, typ := q.Question[0].Name, q.Question[0].Qtype
		switch server.Addr() {
		case root:
			if name == "a.provider." || name == "b.provider." {
				addr := primary
				if name == "b.provider." {
					if !primaryFailed {
						t.Fatal("backup address was fetched before a primary failure")
					}
					backupLookups++
					addr = backup
				}
				m.Authoritative = true
				if typ == dns.TypeA {
					m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: typ, Class: dns.ClassINET, Ttl: 60}, A: net.IP(addr.AsSlice())}}
				}
			} else {
				for _, ns := range []string{"a.provider.", "b.provider."} {
					m.Ns = append(m.Ns, &dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: ns})
				}
			}
		case primary:
			primaryFailed = true
			primaryQueries++
			return nil, fmt.Errorf("primary authority is unavailable")
		case backup:
			m.Authoritative = true
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(93, 184, 216, 34)}}
		default:
			return nil, fmt.Errorf("unexpected server %s", server)
		}
		return m, nil
	})
	minimise := false
	r := New(Config{Exchange: ex, AllowNonGlobalTargets: true, QnameMinimisation: &minimise})
	r.cache.PutDelegation(".", []string{"ns.root."}, map[string][]netip.Addr{"ns.root.": {root}})

	for _, name := range []string{"first.example.", "second.example."} {
		res, err := r.Resolve(context.Background(), name, dns.TypeA)
		if err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		if res.Msg.Rcode != dns.RcodeSuccess || len(res.Msg.Answer) != 1 {
			t.Fatalf("resolve %s: incomplete answer %v", name, res.Msg)
		}
	}
	if backupLookups != 2 || primaryQueries != 2 {
		t.Fatalf("failover duplicated lookups or retried a failed address: backup lookups=%d primary queries=%d", backupLookups, primaryQueries)
	}
}

func TestMinimisedQuestionRetryTriesAnotherAuthorityAfterFailure(t *testing.T) {
	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			primary := netip.MustParseAddrPort("192.0.2.53:53")
			backup := netip.MustParseAddrPort("192.0.2.54:53")
			backupQueries := 0
			ex := limitsExchange(func(_ context.Context, server netip.AddrPort, q *dns.Msg) (*dns.Msg, error) {
				m := new(dns.Msg)
				m.SetReply(q)
				m.Authoritative = true
				if server == backup {
					backupQueries++
				}
				if q.Question[0].Qtype == dns.TypeNS {
					// The intermediate name exists without its own NS RRset.
					return m, nil
				}
				if server == primary {
					m.Rcode = rcode
					return m, nil
				}
				m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(93, 184, 216, 34)}}
				return m, nil
			})
			r := New(Config{Exchange: ex, AllowNonGlobalTargets: true})
			r.cache.PutDelegation("example.", []string{"a.example.", "b.example."}, map[string][]netip.Addr{
				"a.example.": {primary.Addr()}, "b.example.": {backup.Addr()},
			})
			res, err := r.Resolve(context.Background(), "www.service.example.", dns.TypeA)
			if err != nil || res.Msg.Rcode != dns.RcodeSuccess || len(res.Msg.Answer) != 1 {
				t.Fatalf("failed full query was accepted without trying the backup: result=%v err=%v", res, err)
			}
			if backupQueries != 2 {
				t.Fatalf("expected minimised and full questions to the backup, got %d", backupQueries)
			}
		})
	}
}
