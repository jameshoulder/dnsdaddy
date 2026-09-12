package dnsserver

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/ratelimit"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// limited builds a handler whose limiter admits exactly burst queries before
// refusing. Rate is deliberately tiny so nothing is earned back inside a test.
func limited(t *testing.T, burst float64, opts ...func(*HandlerOptions)) *testHarness {
	t.Helper()
	all := append([]func(*HandlerOptions){func(o *HandlerOptions) {
		o.RateLimiter = ratelimit.New(ratelimit.Config{Rate: 0.001, Burst: burst, MaxClients: 256})
	}}, opts...)
	return newHarnessWithOptions(t, nil, all...)
}

// TestAClientOverItsLimitIsRefused — the control, end to end through the
// handler rather than against the limiter in isolation.
func TestAClientOverItsLimitIsRefused(t *testing.T) {
	h := limited(t, 3)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if got := h.handler.Handle(ctx, query("example.com", dns.TypeA), clientMeta("10.0.0.5")).Rcode; got == dns.RcodeRefused {
			t.Fatalf("query %d was refused inside the burst", i)
		}
	}
	resp := h.handler.Handle(ctx, query("example.com", dns.TypeA), clientMeta("10.0.0.5"))
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if h.handler.RateLimited() != 1 {
		t.Errorf("RateLimited() = %d, want 1", h.handler.RateLimited())
	}
	// The counter must not be conflated with the ACL's, which means something
	// else entirely to an operator reading /metrics.
	if h.handler.RefusedClients() != 0 {
		t.Errorf("RefusedClients() = %d; a rate limit is not an ACL refusal", h.handler.RefusedClients())
	}
}

// TestARateLimitedQueryIsAnsweredNotDropped. Silence is indistinguishable from
// the resolver being down, and a client that is told no can back off.
func TestARateLimitedQueryIsAnsweredNotDropped(t *testing.T) {
	h := limited(t, 1)
	ctx := context.Background()
	req := query("example.com", dns.TypeA)

	h.handler.Handle(ctx, req, clientMeta("10.0.0.6"))
	resp := h.handler.Handle(ctx, req, clientMeta("10.0.0.6"))
	if resp == nil {
		t.Fatal("a rate-limited query produced no response at all")
	}
	if resp.Id != req.Id || len(resp.Question) != 1 || resp.Question[0].Name != req.Question[0].Name {
		t.Error("the refusal does not answer the question it was sent")
	}
	if len(resp.Answer) != 0 {
		t.Error("a refusal carried answer records")
	}
}

// TestARateLimitedQueryWritesNoQueryLogRow is the disk-exhaustion property,
// and the reason the ACL refusal path writes nothing either. A client sending
// faster than it is allowed to must not be able to convert that into unbounded
// storage — otherwise the control meant to bound resource use becomes a way to
// consume a different resource.
func TestARateLimitedQueryWritesNoQueryLogRow(t *testing.T) {
	h := limited(t, 1)
	ctx := context.Background()

	// One admitted query, so there is a row to wait for and the absence of the
	// others is measured rather than assumed from an empty table.
	h.handler.Handle(ctx, query("allowed.example", dns.TypeA), clientMeta("10.0.0.7"))
	for i := 0; i < 200; i++ {
		h.handler.Handle(ctx, query("flood.example", dns.TypeA), clientMeta("10.0.0.7"))
	}

	deadline := time.Now().Add(3 * time.Second)
	var rows []store.QueryEvent
	for time.Now().Before(deadline) {
		var err error
		rows, _, err = h.store.ListQueries(ctx, store.QueryFilter{Limit: 500})
		if err != nil {
			t.Fatalf("ListQueries: %v", err)
		}
		if len(rows) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(rows) != 1 {
		t.Fatalf("200 rate-limited queries produced %d query-log rows, want only the 1 admitted query", len(rows))
	}
	if rows[0].Domain != "allowed.example" {
		t.Errorf("the row that was written is %q, want the admitted query", rows[0].Domain)
	}
}

// TestARateLimitedQueryNeverReachesAnUpstream. A limiter that runs after the
// work it is meant to prevent has already been done is decoration: the point
// is that the refused query costs a map lookup and nothing else.
func TestARateLimitedQueryNeverReachesAnUpstream(t *testing.T) {
	var mu sync.Mutex
	var seen []*dns.Msg
	addr := recordingUpstream(t, &mu, &seen)

	h := newHarnessAgainstUpstream(t, addr, func(o *HandlerOptions) {
		o.RateLimiter = ratelimit.New(ratelimit.Config{Rate: 0.001, Burst: 1, MaxClients: 64})
	})
	ctx := context.Background()

	h.handler.Handle(ctx, query("first.example", dns.TypeA), clientMeta("10.0.0.8"))
	for i := 0; i < 50; i++ {
		h.handler.Handle(ctx, query("blocked-by-rate.example", dns.TypeA), clientMeta("10.0.0.8"))
	}

	mu.Lock()
	defer mu.Unlock()
	for _, m := range seen {
		if len(m.Question) > 0 && m.Question[0].Name == "blocked-by-rate.example." {
			t.Fatal("a rate-limited question was sent upstream")
		}
	}
	if len(seen) == 0 {
		t.Fatal("nothing reached the upstream at all; the test proves nothing")
	}
}

// TestTheRateLimitIsNotCountedAsAQuery. dnsdaddy_queries_total is what an
// operator divides by, and counting refusals in it would make the block rate
// and the error rate move when nothing was resolved.
func TestTheRateLimitIsNotCountedAsAQuery(t *testing.T) {
	h := limited(t, 1)
	ctx := context.Background()

	h.handler.Handle(ctx, query("example.com", dns.TypeA), clientMeta("10.0.0.9"))
	before, _, _ := h.handler.Stats()
	for i := 0; i < 20; i++ {
		h.handler.Handle(ctx, query("example.com", dns.TypeA), clientMeta("10.0.0.9"))
	}
	after, _, _ := h.handler.Stats()
	if after != before {
		t.Errorf("queries_total moved from %d to %d across 20 rate-limited queries", before, after)
	}
}

// TestOneNoisyClientDoesNotRefuseAnother, through the handler. This is the
// property that decides whether the feature is safe to have on by default: a
// limiter that refuses the wrong client is an outage.
func TestOneNoisyClientDoesNotRefuseAnother(t *testing.T) {
	h := limited(t, 2)
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		h.handler.Handle(ctx, query("example.com", dns.TypeA), clientMeta("10.0.1.1"))
	}
	if got := h.handler.Handle(ctx, query("example.com", dns.TypeA), clientMeta("10.0.1.2")).Rcode; got == dns.RcodeRefused {
		t.Error("a quiet client was refused because a different client was over its limit")
	}
}

// TestTheACLIsCheckedBeforeTheRateLimit. Order matters for a reason that is
// not aesthetic: a source that is not permitted here at all must not be able
// to occupy a slot in the limiter's bounded table, or an unauthorised flood
// would evict the state of the authorised clients the limiter is protecting.
func TestTheACLIsCheckedBeforeTheRateLimit(t *testing.T) {
	acl := clientacl.Compute([]string{"10.0.0.0/8"}, false, nil)
	h := limited(t, 5, func(o *HandlerOptions) { o.ClientACL = acl })
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		h.handler.Handle(ctx, query("example.com", dns.TypeA), clientMeta("203.0.113.9"))
	}
	if h.handler.RefusedClients() != 100 {
		t.Errorf("RefusedClients() = %d, want 100", h.handler.RefusedClients())
	}
	if h.handler.RateLimited() != 0 {
		t.Errorf("RateLimited() = %d; an ACL-refused source reached the limiter", h.handler.RateLimited())
	}
	if n := h.handler.RateLimiter().Tracked(); n != 0 {
		t.Errorf("an unauthorised source occupies %d slots in the limiter's table", n)
	}
}

// TestATokenIdentifiedClientIsNotRateLimitedOnAnAddressItDoesNotHave.
// A roaming DoH or DoT client is identified by its token; there may be no
// usable peer address, and inventing a shared one would put every roaming
// client on the same allowance.
func TestATokenIdentifiedClientIsNotRateLimitedOnAnAddressItDoesNotHave(t *testing.T) {
	h := limited(t, 1)
	meta := requestMeta{proto: "doh", networkID: "n_default"}

	for i := 0; i < 50; i++ {
		if got := h.handler.Handle(context.Background(), query("example.com", dns.TypeA), meta).Rcode; got == dns.RcodeRefused {
			t.Fatalf("a token-identified client with no source address was refused at query %d", i)
		}
	}
}

// TestNoLimiterMeansNoLimit. "Off" is a nil pointer all the way down, so the
// handler must not have grown a code path that behaves differently when the
// feature is disabled.
func TestNoLimiterMeansNoLimit(t *testing.T) {
	h := newHarnessWithOptions(t, nil, func(o *HandlerOptions) { o.RateLimiter = nil })
	ctx := context.Background()
	for i := 0; i < 200; i++ {
		if got := h.handler.Handle(ctx, query("example.com", dns.TypeA), clientMeta("10.0.2.2")).Rcode; got == dns.RcodeRefused {
			t.Fatalf("query %d refused with no limiter configured", i)
		}
	}
	if h.handler.RateLimited() != 0 || h.handler.RateLimiter() != nil {
		t.Error("a handler with no limiter reported limiter state")
	}
}

// TestARateLimitedClientRecovers. The limit is a rate, not a ban: a client
// that slows down must be served again without an operator doing anything.
func TestARateLimitedClientRecovers(t *testing.T) {
	h := newHarnessWithOptions(t, nil, func(o *HandlerOptions) {
		// 100/s, burst 2: the third immediate query is refused and 10ms of
		// real time earns one back.
		o.RateLimiter = ratelimit.New(ratelimit.Config{Rate: 100, Burst: 2, MaxClients: 64})
	})
	ctx := context.Background()
	c := clientMeta("10.0.3.3")

	h.handler.Handle(ctx, query("example.com", dns.TypeA), c)
	h.handler.Handle(ctx, query("example.com", dns.TypeA), c)
	if got := h.handler.Handle(ctx, query("example.com", dns.TypeA), c).Rcode; got != dns.RcodeRefused {
		t.Fatalf("expected a refusal to recover from, got %s", dns.RcodeToString[got])
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(15 * time.Millisecond)
		if got := h.handler.Handle(ctx, query("example.com", dns.TypeA), c).Rcode; got != dns.RcodeRefused {
			return
		}
	}
	t.Error("a client that stopped sending was never admitted again")
}

// TestADualStackedClientGetsOneAllowanceThroughTheHandler, because a listener
// bound to :: reports IPv4 peers in mapped form and two allowances per host
// would halve the effectiveness of the limit.
func TestADualStackedClientGetsOneAllowanceThroughTheHandler(t *testing.T) {
	h := limited(t, 2)
	ctx := context.Background()

	plain := requestMeta{clientAddr: netip.MustParseAddr("10.0.4.4"), proto: "udp"}
	mapped := requestMeta{clientAddr: netip.MustParseAddr("::ffff:10.0.4.4"), proto: "udp"}

	h.handler.Handle(ctx, query("example.com", dns.TypeA), plain)
	h.handler.Handle(ctx, query("example.com", dns.TypeA), mapped)
	if got := h.handler.Handle(ctx, query("example.com", dns.TypeA), plain).Rcode; got != dns.RcodeRefused {
		t.Error("the mapped and unmapped forms of one address were given separate allowances")
	}
}
