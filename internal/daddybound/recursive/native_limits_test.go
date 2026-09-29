package recursive

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestMaterialCacheSeparatesUnknownNumericRRTypes(t *testing.T) {
	c := NewCache(CacheOptions{})
	for _, typ := range []uint16{65280, 65281} {
		q := new(dns.Msg)
		q.SetQuestion("private-type.example.", typ)
		m := new(dns.Msg)
		m.SetReply(q)
		m.Answer = []dns.RR{&dns.RFC3597{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: typ, Class: dns.ClassINET, Ttl: 60}, Rdata: "abcd"}}
		c.PutMsg(q.Question[0].Name, typ, m)
	}
	for _, typ := range []uint16{65280, 65281} {
		m, ok := c.GetMsg("private-type.example.", typ)
		if !ok || m.Question[0].Qtype != typ || m.Answer[0].Header().Rrtype != typ {
			t.Fatalf("unknown RR type %d collided: %v", typ, m)
		}
	}
}

type limitsExchange func(context.Context, netip.AddrPort, *dns.Msg) (*dns.Msg, error)

func (f limitsExchange) Exchange(ctx context.Context, addr netip.AddrPort, q *dns.Msg) (*dns.Msg, error) {
	return f(ctx, addr, q)
}

func TestMinimisationRetryCannotExceedQueryBudget(t *testing.T) {
	var calls int
	ex := limitsExchange(func(_ context.Context, _ netip.AddrPort, q *dns.Msg) (*dns.Msg, error) {
		calls++
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		return m, nil
	})
	r := New(Config{Exchange: ex, Limits: Limits{MaxQueries: 1}, AllowNonGlobalTargets: true})
	rs := &resolution{r: r, ctx: context.Background()}
	_, err := rs.ask(".", []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}, "a.b.example.", dns.TypeA, true)
	if !errors.Is(err, ErrLimit) || calls != 1 || rs.queries != 1 {
		t.Fatalf("minimisation retry spent beyond the bound: calls=%d queries=%d err=%v", calls, rs.queries, err)
	}
}

func TestNameserverDependencyDepthIsCarriedAcrossNestedResolution(t *testing.T) {
	var calls int
	ex := limitsExchange(func(_ context.Context, _ netip.AddrPort, q *dns.Msg) (*dns.Msg, error) {
		calls++
		name := q.Question[0].Name
		child, next := "example.", 1
		if name != "www.example." {
			var n int
			if _, err := fmt.Sscanf(name, "ns.dep%d.", &n); err != nil {
				return nil, err
			}
			child, next = fmt.Sprintf("dep%d.", n), n+1
		}
		m := new(dns.Msg)
		m.SetReply(q)
		m.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: child, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: fmt.Sprintf("ns.dep%d.", next)}}
		return m, nil
	})
	minimise := false
	r := New(Config{Exchange: ex, Limits: Limits{MaxNSResolutionDepth: 2}, AllowNonGlobalTargets: true, QnameMinimisation: &minimise})
	r.cache.PutDelegation(".", []string{"ns.root."}, map[string][]netip.Addr{"ns.root.": {netip.MustParseAddr("127.0.0.1")}})
	_, err := r.Resolve(context.Background(), "www.example.", dns.TypeA)
	if !errors.Is(err, ErrLimit) || calls != 3 {
		t.Fatalf("nested nameserver dependencies ignored depth bound: calls=%d err=%v", calls, err)
	}
}
