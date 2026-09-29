package dnsserver

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/protection"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/miekg/dns"
)

type nativeRuntimeStub struct {
	calls   int
	address string
	fail    bool
}

func (s *nativeRuntimeStub) NativeClient() NativeResolver { return s }
func (s *nativeRuntimeStub) ResolveClient(_ context.Context, q *dns.Msg) native.ClientResult {
	s.calls++
	m := new(dns.Msg)
	m.SetReply(q)
	m.RecursionAvailable = true
	result := native.ClientResult{Msg: m, ValidationStatus: "secure", Reason: "Exact native answer authenticated", Enforced: true, Validation: dnssec.ValidationResult{Status: dnssec.StatusSecure}}
	if s.fail {
		m.Rcode = dns.RcodeServerFailure
		result.ValidationStatus = "bogus"
		result.Reason = "Native signature validation failed"
		return result
	}
	m.AuthenticatedData = true
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(s.address)}}
	return result
}

type learningCapture struct {
	observations []detect.Observation
	skipped      int
}

func (c *learningCapture) Observe(o detect.Observation) bool {
	c.observations = append(c.observations, o)
	return true
}
func (c *learningCapture) SkipPrivacy() { c.skipped++ }

func TestNativeSelectionBypassesForwardedCacheAndNeverFallsBack(t *testing.T) {
	h := newHarness(t, nil)
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	meta := requestMeta{clientAddr: netip.MustParseAddr("192.168.1.10"), proto: "udp"}
	if m := h.handler.Handle(context.Background(), q, meta); m.Rcode != dns.RcodeSuccess {
		t.Fatal(m)
	}
	native := &nativeRuntimeStub{address: "9.9.9.9"}
	h.handler.native = native
	// A native query must not even need a forwarding resolver, warm cache or not.
	h.handler.resolver = nil
	m := h.handler.Handle(context.Background(), q, meta)
	if native.calls != 1 || len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "9.9.9.9" {
		t.Fatalf("native path not used: %v", m)
	}
	native.fail = true
	m = h.handler.Handle(context.Background(), q, meta)
	if m.Rcode != dns.RcodeServerFailure || len(m.Answer) != 0 || native.calls != 2 {
		t.Fatalf("native failure did not remain failure: %v", m)
	}
}

func TestPolicyBlockPrecedesNativeRecursion(t *testing.T) {
	native := &nativeRuntimeStub{address: "9.9.9.9"}
	h := newHarnessWithQueryLog(t, map[string]string{"blocked.test": "malware"}, true, func(o *HandlerOptions) { o.Native = native })
	q := new(dns.Msg)
	q.SetQuestion("blocked.test.", dns.TypeA)
	m := h.handler.Handle(context.Background(), q, requestMeta{clientAddr: netip.MustParseAddr("192.168.1.10")})
	if native.calls != 0 || m.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked query reached native: calls=%d response=%v", native.calls, m)
	}
}

func TestRebindingProtectsNativeCDRepliesAndForwardedCache(t *testing.T) {
	c, err := protection.New(protection.Default(), nil)
	if err != nil {
		t.Fatal(err)
	}
	native := &nativeRuntimeStub{address: "10.1.2.3"}
	h := newHarnessWithQueryLog(t, nil, true, func(o *HandlerOptions) { o.Native = native; o.Protection = c })
	q := new(dns.Msg)
	q.SetQuestion("public.test.", dns.TypeA)
	q.CheckingDisabled = true
	q.SetEdns0(1232, true)
	m := h.handler.Handle(context.Background(), q, requestMeta{clientAddr: netip.MustParseAddr("192.168.1.10")})
	if m.Rcode != dns.RcodeRefused || m.AuthenticatedData || len(m.Answer) != 0 || m.IsEdns0() == nil {
		t.Fatalf("unsafe native/CD answer leaked: %v", m)
	}
	if c.Counters().RebindingBlocked != 1 {
		t.Fatal("missing rebinding count")
	}
	// The ordinary upstream fixture returns a documentation address. The
	// cache is filled before enabling the guard; enabling must protect hits.
	h2 := newHarness(t, nil)
	meta := requestMeta{clientAddr: netip.MustParseAddr("192.168.1.11")}
	h2.handler.Handle(context.Background(), q, meta)
	h2.handler.protection = c
	m = h2.handler.Handle(context.Background(), q, meta)
	if m.Rcode != dns.RcodeRefused {
		t.Fatalf("cached answer bypassed rebinding guard: %v", m)
	}
}

func TestRateLimitPrecedesResolutionAndAllocatesNoQueryRecord(t *testing.T) {
	cfg := protection.Default()
	cfg.RateLimit.QPS = 1
	cfg.RateLimit.Burst = 1
	c, err := protection.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	native := &nativeRuntimeStub{address: "9.9.9.9"}
	h := newHarnessWithQueryLog(t, nil, true, func(o *HandlerOptions) { o.Native = native; o.Protection = c })
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	meta := requestMeta{clientAddr: netip.MustParseAddr("192.168.1.10")}
	if m := h.handler.Handle(context.Background(), q, meta); m.Rcode != dns.RcodeSuccess {
		t.Fatal(m)
	}
	if m := h.handler.Handle(context.Background(), q, meta); m.Rcode != dns.RcodeRefused {
		t.Fatalf("unlimited: %v", m)
	}
	queries, _, _ := h.handler.Stats()
	if native.calls != 1 || queries != 1 || c.Counters().RateLimited != 1 {
		t.Fatalf("rejected request reached downstream work: calls=%d queries=%d counts=%+v", native.calls, queries, c.Counters())
	}
}

func TestLearningRunsWithoutHeuristicDetectorAndHonorsAllPrivacyGates(t *testing.T) {
	for _, tc := range []struct {
		name               string
		global, ip, policy bool
	}{{"normal", true, true, true}, {"global", false, true, true}, {"client_ip", true, false, true}, {"policy", true, true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			capture := &learningCapture{}
			h := newHarnessWithQueryLog(t, nil, tc.global, func(o *HandlerOptions) { o.Learning = capture; o.LogClientIP = tc.ip })
			if !tc.policy {
				p, err := h.store.GetPolicy(context.Background(), "p_standard")
				if err != nil {
					t.Fatal(err)
				}
				p.LogQueries = false
				if _, err := h.store.UpdatePolicy(context.Background(), p.ID, store.PolicyInput{LogQueries: &p.LogQueries}); err != nil {
					t.Fatal(err)
				}
				if err := h.engine.Reload(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			q := new(dns.Msg)
			q.SetQuestion("example.test.", dns.TypeA)
			h.handler.Handle(context.Background(), q, requestMeta{clientAddr: netip.MustParseAddr("::ffff:192.168.1.10"), proto: "udp"})
			want := 0
			if tc.global && tc.ip && tc.policy {
				want = 1
			}
			if len(capture.observations) != want || capture.skipped != 1-want {
				t.Fatalf("privacy leak or missing observation: %+v", capture)
			}
			if want == 1 && capture.observations[0].ClientIP != "192.168.1.10" {
				t.Fatalf("unnormalized client: %+v", capture.observations[0])
			}
		})
	}
}
