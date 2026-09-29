package native_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
)

func nativeClient(t *testing.T, e native.ClientEngine) *native.Client {
	t.Helper()
	c, err := native.NewClient(e, native.ClientOptions{Timeout: 5 * time.Second, MaxInflight: 4})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func clientQuery(name string, typ uint16, ad, cd, do bool) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, typ)
	q.AuthenticatedData, q.CheckingDisabled = ad, cd
	if do {
		q.SetEdns0(1232, true)
	}
	return q
}

func edeCode(msg *dns.Msg) uint16 {
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if ede, ok := option.(*dns.EDNS0_EDE); ok {
				return ede.InfoCode
			}
		}
	}
	return 65535
}

func TestNativeClientSecureADCDDOFlagMatrix(t *testing.T) {
	e, _, _ := engine(t)
	c := nativeClient(t, e)
	for _, ad := range []bool{false, true} {
		for _, cd := range []bool{false, true} {
			for _, do := range []bool{false, true} {
				q := clientQuery("WWW.example.dnsdaddylab.", dns.TypeA, ad, cd, do)
				out := c.ResolveClient(context.Background(), q)
				if out.Msg.Rcode != dns.RcodeSuccess {
					t.Fatalf("AD=%v CD=%v DO=%v: %s %s", ad, cd, do, out.ValidationStatus, out.Reason)
				}
				wantAD := !cd && (ad || do)
				if out.Msg.AuthenticatedData != wantAD || out.Msg.CheckingDisabled != cd {
					t.Errorf("AD=%v CD=%v DO=%v: reply AD=%v CD=%v", ad, cd, do, out.Msg.AuthenticatedData, out.Msg.CheckingDisabled)
				}
				if out.Msg.Id != q.Id || out.Msg.Question[0] != q.Question[0] || out.Msg.Authoritative || !out.Msg.RecursionAvailable {
					t.Errorf("client header/question was not rebuilt: %v", out.Msg)
				}
				var sig bool
				for _, rr := range out.Msg.Answer {
					if _, ok := rr.(*dns.RRSIG); ok {
						sig = true
					}
				}
				if sig != do {
					t.Errorf("DO=%v but signature present=%v", do, sig)
				}
				if cd && (out.Enforced || out.ValidationStatus != "checking_disabled") {
					t.Errorf("CD answer claimed enforcement: %+v", out)
				}
			}
		}
	}
	if got := c.Stats(); got.Secure != 4 || got.CheckingDisabled != 4 || got.Inflight != 0 {
		t.Errorf("flag matrix counters: %+v", got)
	}
}

func TestNativeClientBogusFailsClosedAndCDCannotPoisonValidatedCache(t *testing.T) {
	e, _, _ := engine(t, func(h *lab.Hierarchy) {
		if err := h.TamperData(lab.LeafZone, lab.AnswerName, dns.TypeA, func(rr dns.RR) {
			rr.(*dns.A).A = net.IPv4(192, 0, 2, 99)
		}); err != nil {
			t.Fatal(err)
		}
	})
	c := nativeClient(t, e)
	for _, cd := range []bool{false, true, false} {
		out := c.ResolveClient(context.Background(), clientQuery(lab.AnswerName, dns.TypeA, true, cd, true))
		if cd {
			if out.Msg.Rcode != dns.RcodeSuccess || out.Msg.AuthenticatedData || len(out.Msg.Answer) == 0 {
				t.Fatalf("CD did not receive unchecked native data: %+v", out)
			}
		} else if out.Msg.Rcode != dns.RcodeServerFailure || out.Msg.AuthenticatedData || len(out.Msg.Answer) != 0 || edeCode(out.Msg) != dns.ExtendedErrorCodeDNSBogus || out.ValidationStatus != "bogus" {
			t.Fatalf("bogus answer escaped enforcement: %+v", out)
		}
	}
}

func TestNativeClientUnsignedAliasCannotHideBogusSignedTarget(t *testing.T) {
	e, _, _ := engine(t, func(h *lab.Hierarchy) {
		if err := h.CorruptSignature(lab.LeafZone, lab.AnswerName, dns.TypeA); err != nil {
			t.Fatal(err)
		}
	})
	out := nativeClient(t, e).ResolveClient(context.Background(), clientQuery(lab.InsecureAliasName, dns.TypeA, true, false, true))
	if out.ValidationStatus != "bogus" || out.Msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("an unsigned alias bypassed validation of its signed target: %s %s\n%s", out.ValidationStatus, out.Reason, out.Validation.Trace())
	}
}

func TestNativeClientNativeAliasAndDenialShapes(t *testing.T) {
	e, _, _ := engine(t)
	c := nativeClient(t, e)
	for _, tc := range []struct {
		name   string
		typ    uint16
		status string
		rcode  int
	}{
		{lab.AliasName, dns.TypeA, "secure", dns.RcodeSuccess},
		{lab.CrossZoneAlias, dns.TypeA, "secure", dns.RcodeSuccess},
		{lab.AliasHop1, dns.TypeA, "secure", dns.RcodeSuccess},
		{lab.WildcardAliasMatch, dns.TypeA, "secure", dns.RcodeSuccess},
		{lab.DnameMatch, dns.TypeA, "secure", dns.RcodeSuccess},
		{lab.DnameMatch, dns.TypeCNAME, "secure", dns.RcodeSuccess},
		{lab.UnsignedName, dns.TypeA, "insecure", dns.RcodeSuccess},
		{lab.InsecureAliasName, dns.TypeA, "insecure", dns.RcodeSuccess},
		{lab.AliasToInsecure, dns.TypeA, "insecure", dns.RcodeSuccess},
		{lab.MissingName, dns.TypeA, "secure", dns.RcodeNameError},
		{lab.AliasName, dns.TypeAAAA, "secure", dns.RcodeSuccess},
	} {
		t.Run(tc.name+dns.TypeToString[tc.typ], func(t *testing.T) {
			out := c.ResolveClient(context.Background(), clientQuery(tc.name, tc.typ, true, false, true))
			if out.ValidationStatus != tc.status || out.Msg.Rcode != tc.rcode {
				t.Fatalf("want %s/%d, got %s/%d: %s\n%s", tc.status, tc.rcode, out.ValidationStatus, out.Msg.Rcode, out.Reason, out.Validation.Trace())
			}
			if out.Msg.AuthenticatedData != (tc.status == "secure") {
				t.Errorf("AD=%v for %s", out.Msg.AuthenticatedData, tc.status)
			}
		})
	}
}

func TestNativeClientBundledTargetIsNotValidatedFromAReplacementAndThenServed(t *testing.T) {
	e, servers, _ := engine(t, func(h *lab.Hierarchy) {
		bundled := append(h.Set(lab.LeafZone, lab.AliasName, dns.TypeCNAME), h.Set(lab.LeafZone, lab.AnswerName, dns.TypeA)...)
		for i, rr := range bundled {
			if a, ok := rr.(*dns.A); ok {
				copied := dns.Copy(a).(*dns.A)
				copied.A = net.IPv4(192, 0, 2, 99)
				bundled[i] = copied
			}
		}
		h.SubstituteAnswer(lab.AliasName, dns.TypeA, bundled)
	})
	out := nativeClient(t, e).ResolveClient(context.Background(), clientQuery(lab.AliasName, dns.TypeA, true, false, true))
	if out.ValidationStatus != "secure" {
		t.Fatalf("expected the independently resolved real target: %s\n%s", out.Reason, out.Validation.Trace())
	}
	var found bool
	for _, rr := range out.Msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			found = true
			if !a.A.Equal(lab.AnswerAddress) {
				t.Fatalf("forged bundled answer was served under AD: %v", a)
			}
		}
	}
	if !found {
		t.Fatal("no terminal answer")
	}
	var askedTarget bool
	for _, q := range servers.QueriesTo(lab.LeafZone) {
		if q.Name == lab.AnswerName && q.Type == dns.TypeA {
			askedTarget = true
		}
	}
	if !askedTarget {
		t.Fatal("terminal reply was never independently resolved")
	}
}

func TestNativeClientDNAMERecomputesAnAttackerSuppliedCNAME(t *testing.T) {
	e, _, _ := engine(t, func(h *lab.Hierarchy) {
		answer := h.Set(lab.LeafZone, lab.DnameOwner, dns.TypeDNAME)
		answer = append(answer, &dns.CNAME{Hdr: dns.RR_Header{Name: lab.DnameMatch, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600}, Target: lab.OtherName})
		h.SubstituteAnswer(lab.DnameMatch, dns.TypeA, answer)
	})
	out := nativeClient(t, e).ResolveClient(context.Background(), clientQuery(lab.DnameMatch, dns.TypeA, true, false, true))
	if out.ValidationStatus != "secure" {
		t.Fatalf("DNAME result: %s\n%s", out.Reason, out.Validation.Trace())
	}
	for _, rr := range out.Msg.Answer {
		if c, ok := rr.(*dns.CNAME); ok && c.Target != lab.AnswerName {
			t.Fatalf("unsigned CNAME changed authenticated redirection: %s", c)
		}
		if a, ok := rr.(*dns.A); ok && !a.A.Equal(lab.AnswerAddress) {
			t.Fatalf("DNAME returned the wrong target data: %s", a)
		}
	}
}

func TestNativeClientNegativeSOAIsPartOfTheAuthenticatedPacket(t *testing.T) {
	e, _, _ := engine(t, func(h *lab.Hierarchy) {
		if err := h.TamperData(lab.LeafZone, lab.LeafZone, dns.TypeSOA, func(rr dns.RR) { rr.(*dns.SOA).Serial++ }); err != nil {
			t.Fatal(err)
		}
	})
	out := nativeClient(t, e).ResolveClient(context.Background(), clientQuery(lab.MissingName, dns.TypeA, true, false, true))
	if out.ValidationStatus != "bogus" || out.Msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("tampered negative SOA escaped: %s\n%s", out.Reason, out.Validation.Trace())
	}
}

func TestNativeClientDirectDNSKEYWithoutDOKeepsTheRequestedData(t *testing.T) {
	e, _, _ := engine(t)
	out := nativeClient(t, e).ResolveClient(context.Background(), clientQuery(lab.LeafZone, dns.TypeDNSKEY, true, false, false))
	if out.Msg.Rcode != dns.RcodeSuccess || !out.Msg.AuthenticatedData {
		t.Fatalf("DNSKEY query failed: %s", out.Reason)
	}
	var found bool
	for _, rr := range out.Msg.Answer {
		if _, ok := rr.(*dns.DNSKEY); ok {
			found = true
		}
		if _, ok := rr.(*dns.RRSIG); ok {
			t.Fatal("unsolicited RRSIG retained without DO")
		}
	}
	if !found {
		t.Fatal("explicitly requested DNSKEY was stripped")
	}
}

type mutableClock struct{ seconds atomic.Int64 }

func (c *mutableClock) Now() time.Time { return time.Unix(c.seconds.Load(), 0) }

func TestNativeClientCacheRevalidatesWithCurrentClockAndCapsSignatureTTL(t *testing.T) {
	_, _, resolver := engine(t)
	h, err := lab.Standard()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := h.Config(lab.Expiration.Add(-2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	clock := &mutableClock{}
	clock.seconds.Store(lab.Expiration.Add(-2 * time.Second).Unix())
	e, err := native.New(native.Config{Resolver: resolver, Anchors: cfg.Anchors, Clock: clock, Policy: cfg.Policy, Verifier: cfg.Verifier, Limits: cfg.Limits})
	if err != nil {
		t.Fatal(err)
	}
	c := nativeClient(t, e)
	out := c.ResolveClient(context.Background(), clientQuery(lab.AnswerName, dns.TypeA, true, false, true))
	if out.ValidationStatus != "secure" {
		t.Fatalf("before expiry: %s", out.Reason)
	}
	for _, rr := range out.Msg.Answer {
		if rr.Header().Ttl > 2 {
			t.Fatalf("TTL outlives verified signature: %s", rr)
		}
	}
	clock.seconds.Store(lab.Expiration.Add(time.Second).Unix())
	out = c.ResolveClient(context.Background(), clientQuery(lab.AnswerName, dns.TypeA, true, false, true))
	if out.Msg.Rcode != dns.RcodeServerFailure || out.ValidationStatus != "bogus" {
		t.Fatalf("cached signature remained trusted after expiry: %s", out.Reason)
	}
}

func TestNativeClientAnchorWithdrawalCannotLeaveCachedSecureAnswers(t *testing.T) {
	_, _, resolver := engine(t)
	h, _ := lab.Standard()
	cfg, _ := h.Config(labInstant())
	anchors := cfg.Anchors
	e, err := native.New(native.Config{Resolver: resolver, AnchorSource: func() dnssec.TrustAnchors { return anchors }, Clock: cfg.Clock, Policy: cfg.Policy, Verifier: cfg.Verifier, Limits: cfg.Limits})
	if err != nil {
		t.Fatal(err)
	}
	c := nativeClient(t, e)
	q := clientQuery(lab.AnswerName, dns.TypeA, true, false, true)
	if out := c.ResolveClient(context.Background(), q); out.ValidationStatus != "secure" {
		t.Fatal(out.Reason)
	}
	anchors = dnssec.TrustAnchors{}
	out := c.ResolveClient(context.Background(), q)
	if out.ValidationStatus != "indeterminate" || out.ReasonCode != "no_trust_anchor" || out.Msg.Rcode != dns.RcodeServerFailure || edeCode(out.Msg) != dns.ExtendedErrorCodeDNSSECIndeterminate {
		t.Fatalf("anchor withdrawal became a downgrade: %+v", out)
	}
	q.CheckingDisabled = true
	if out := c.ResolveClient(context.Background(), q); out.Msg.Rcode != dns.RcodeSuccess || out.Msg.AuthenticatedData {
		t.Fatalf("CD incorrectly depended on anchors: %+v", out)
	}
}

type clientEngineFunc struct {
	resolve func(context.Context, string, uint16) (*native.Answer, error)
}

func (f clientEngineFunc) Resolve(ctx context.Context, n string, q uint16) (*native.Answer, error) {
	return f.resolve(ctx, n, q)
}
func (f clientEngineFunc) ResolveUnchecked(ctx context.Context, n string, q uint16) (*native.Answer, error) {
	return f.resolve(ctx, n, q)
}

func TestNativeClientCapacityTimeoutAndPanicAreExplicit(t *testing.T) {
	entered := make(chan struct{})
	e := clientEngineFunc{resolve: func(ctx context.Context, _ string, _ uint16) (*native.Answer, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	c, err := native.NewClient(e, native.ClientOptions{Timeout: time.Second, MaxInflight: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	completed := make(chan native.ClientResult, 1)
	q := clientQuery(lab.AnswerName, dns.TypeA, true, false, true)
	go func() { completed <- c.ResolveClient(ctx, q) }()
	<-entered
	if out := c.ResolveClient(context.Background(), q); out.ValidationStatus != "resource_limit" || out.Msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("in-flight bound did not refuse work: %+v", out)
	}
	cancel()
	if out := <-completed; out.ValidationStatus != "timeout" {
		t.Fatalf("deadline blamed DNSSEC data: %s", out.ValidationStatus)
	}
	if stats := c.Stats(); stats.Inflight != 0 || stats.InflightPeak != 1 || stats.LimitRejected != 1 {
		t.Fatalf("capacity state leaked: %+v", stats)
	}
	p := nativeClient(t, clientEngineFunc{resolve: func(context.Context, string, uint16) (*native.Answer, error) { panic("test panic") }})
	out := p.ResolveClient(context.Background(), q)
	if out.ValidationStatus != "internal_error" || p.Stats().Panics != 1 || p.Stats().Inflight != 0 {
		t.Fatalf("panic not contained and counted: %+v %+v", out, p.Stats())
	}
}

func TestNativeClientInvalidProtocolDoesNotStartRecursion(t *testing.T) {
	var calls int
	c := nativeClient(t, clientEngineFunc{resolve: func(context.Context, string, uint16) (*native.Answer, error) {
		calls++
		return nil, errors.New("must not run")
	}})
	q := clientQuery(lab.AnswerName, dns.TypeA, true, false, true)
	q.RecursionDesired = false
	if out := c.ResolveClient(context.Background(), q); out.Msg.Rcode != dns.RcodeRefused {
		t.Fatal("RD=0 must not trigger recursion")
	}
	q.RecursionDesired = true
	q.IsEdns0().SetVersion(1)
	if out := c.ResolveClient(context.Background(), q); out.Msg.Rcode != dns.RcodeBadVers || out.Msg.IsEdns0().Version() != 0 {
		t.Fatal("bad EDNS version did not produce BADVERS")
	}
	if calls != 0 {
		t.Fatalf("invalid request triggered %d native calls", calls)
	}
}
