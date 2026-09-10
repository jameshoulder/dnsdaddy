package recursive_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive/reclab"
)

// hierarchy builds root -> com -> example.com, each a separate authoritative
// server, and returns a resolver pointed only at the root.
//
// "Pointed only at the root" is the whole point: nothing here tells the
// resolver where com or example.com live. If it answers, it did so by
// following referrals, which is the difference between a resolver and a
// forwarder.
func hierarchy(t *testing.T, extra ...func(*[]reclab.Zone)) (*recursive.Resolver, *reclab.Hierarchy) {
	t.Helper()

	zones := []reclab.Zone{
		{
			Name:        ".",
			Delegations: map[string][]string{"com.": {"ns1.com."}},
			// The root's own NS RRset, so priming has something real to
			// learn. Its address is filled in by the test below, which is
			// the only place that knows where the laboratory root landed.
			Records: []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
					Ns:  "a.root-servers.test.",
				},
			},
		},
		{
			Name:        "com.",
			Delegations: map[string][]string{"example.com.": {"ns1.example.com."}},
		},
		{
			Name: "example.com.",
			Records: []dns.RR{
				reclab.A("www.example.com.", "93.184.216.34"),
				reclab.A("other.example.com.", "93.184.216.35"),
			},
		},
	}
	for _, f := range extra {
		f(&zones)
	}
	h := reclab.Start(t, zones...)

	r := recursive.New(recursive.Config{
		RootHints: []recursive.RootHint{{
			Name: "a.root-servers.test.",
			Addr: []netip.Addr{h.Addr(".").Addr()},
		}},
		// The laboratory lives on loopback, which usableTarget refuses for
		// every real delegation. This is the only safety rule a test may
		// relax, and it exists so the rule itself can stay absolute in
		// production.
		AllowNonGlobalTargets: true,
		Exchange:              h.Exchanger(recursive.NewNetExchanger(2*time.Second, 1232, true)),
	})
	return r, h
}

func TestResolvesFromRootByFollowingReferrals(t *testing.T) {
	r, _ := hierarchy(t)

	res, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("Resolve: %v\ntrace:\n%s", err, traceOf(res))
	}
	if res.Msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[res.Msg.Rcode])
	}

	var got string
	for _, rr := range res.Msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			got = a.A.String()
		}
	}
	if got != "93.184.216.34" {
		t.Fatalf("answer = %q, want the authoritative server's record", got)
	}

	// The delegations it crossed are the evidence that it recursed rather
	// than asking one server everything.
	if len(res.Delegations) != 2 {
		t.Fatalf("crossed %d delegations, want 2 (root->com, com->example.com): %+v",
			len(res.Delegations), res.Delegations)
	}
	if res.Delegations[0].Parent != "." || res.Delegations[0].Child != "com." {
		t.Errorf("first delegation = %+v, want . -> com.", res.Delegations[0])
	}
	if res.Delegations[1].Parent != "com." || res.Delegations[1].Child != "example.com." {
		t.Errorf("second delegation = %+v, want com. -> example.com.", res.Delegations[1])
	}
	if res.Zone != "example.com." {
		t.Errorf("answer zone = %q, want example.com.", res.Zone)
	}
}

// The answer must come from the authoritative server, so a test can tell a
// real recursion from a forwarded one.
func TestTheAnswerComesFromTheAuthoritativeServer(t *testing.T) {
	r, h := hierarchy(t)

	if _, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	asked := h.QueriesTo("example.com.")
	if len(asked) == 0 {
		t.Fatal("the authoritative server was never asked; the answer came from somewhere else")
	}
}

func TestNXDOMAINFromTheAuthority(t *testing.T) {
	r, _ := hierarchy(t)

	res, err := r.Resolve(context.Background(), "absent.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Msg.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[res.Msg.Rcode])
	}
}

func TestNODATAKeepsTheNameButNotTheType(t *testing.T) {
	r, _ := hierarchy(t)

	res, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeMX)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR for a name that exists without that type",
			dns.RcodeToString[res.Msg.Rcode])
	}
	if len(res.Msg.Answer) != 0 {
		t.Fatalf("got %d answers for a NODATA", len(res.Msg.Answer))
	}
}

func TestCNAMEChainsAreFollowed(t *testing.T) {
	r, _ := hierarchy(t, func(zones *[]reclab.Zone) {
		(*zones)[2].Records = append((*zones)[2].Records,
			reclab.CNAME("alias.example.com.", "www.example.com."))
	})

	res, err := r.Resolve(context.Background(), "alias.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var sawCNAME, sawA bool
	for _, rr := range res.Msg.Answer {
		switch rr.(type) {
		case *dns.CNAME:
			sawCNAME = true
		case *dns.A:
			sawA = true
		}
	}
	if !sawCNAME || !sawA {
		t.Fatalf("alias chain incomplete: cname=%v a=%v, answer=%v", sawCNAME, sawA, res.Msg.Answer)
	}
}

// The second resolution of a name under the same zone must not walk from the
// root again: the delegation is cached, which is what makes a resolver usable.
func TestASecondQueryReusesTheCachedDelegation(t *testing.T) {
	r, _ := hierarchy(t)
	ctx := context.Background()

	if _, err := r.Resolve(ctx, "www.example.com.", dns.TypeA); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := r.Stats().Queries

	if _, err := r.Resolve(ctx, "other.example.com.", dns.TypeA); err != nil {
		t.Fatalf("second: %v", err)
	}
	second := r.Stats().Queries - first

	if second >= first {
		t.Fatalf("second resolution sent %d queries against the first's %d; the delegation was not reused",
			second, first)
	}
}

func traceOf(res *recursive.Result) string {
	if res == nil {
		return "(none)"
	}
	out := ""
	for _, s := range res.Trace {
		out += s.String() + "\n"
	}
	return out
}
