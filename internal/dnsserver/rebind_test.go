package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/querylog"
	"github.com/jameshoulder/dnsdaddy/internal/ratelimit"
	"github.com/jameshoulder/dnsdaddy/internal/rebind"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// rebindingUpstream answers every A question with one public and one private
// address, and every AAAA question with a ULA. That is the shape of a real
// rebinding payload: the public address keeps the page loading while the
// private one is what the attacker is actually after.
func rebindingUpstream(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(req)
			if len(req.Question) > 0 {
				q := req.Question[0]
				switch q.Qtype {
				case dns.TypeA:
					m.Answer = []dns.RR{
						&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(93, 184, 216, 34)},
						&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(10, 0, 0, 1)},
					}
				case dns.TypeAAAA:
					m.Answer = []dns.RR{
						&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.ParseIP("fd00::1")},
					}
				}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func filtering(t *testing.T, action rebind.EmptyAction) *rebind.Filter {
	t.Helper()
	f, err := rebind.New(rebind.Config{Ranges: rebind.DefaultRanges(), EmptyAction: action})
	if err != nil {
		t.Fatalf("rebind.New: %v", err)
	}
	return f
}

// answerAddrs lists the addresses a response carries.
func answerAddrs(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		}
	}
	return out
}

// TestTheClientNeverSeesThePrivateAddress. The upstream returns it happily;
// whether it leaves this resolver is our decision, and this is that decision
// observed from the client's seat.
func TestTheClientNeverSeesThePrivateAddress(t *testing.T) {
	h := newHarnessAgainstUpstream(t, rebindingUpstream(t), func(o *HandlerOptions) {
		o.Rebinding = filtering(t, rebind.EmptyNoData)
	})

	resp := h.handler.Handle(context.Background(), query("rebind.example", dns.TypeA), clientMeta("10.0.4.1"))
	got := answerAddrs(resp)
	if len(got) != 1 || got[0] != "93.184.216.34" {
		t.Fatalf("client received %v, want only the public address", got)
	}
	if filtered, emptied := h.handler.RebindingStats(); filtered != 1 || emptied != 0 {
		t.Errorf("stats = filtered %d emptied %d, want 1 and 0", filtered, emptied)
	}
}

// TestAnAnswerWithNothingLeftBecomesTheConfiguredEmptyAction, end to end, for
// each of the three settings. A client must get a defined outcome rather than
// an answer with the records quietly missing.
func TestAnAnswerWithNothingLeftBecomesTheConfiguredEmptyAction(t *testing.T) {
	for _, tc := range []struct {
		action rebind.EmptyAction
		rcode  int
	}{
		{rebind.EmptyNoData, dns.RcodeSuccess},
		{rebind.EmptyNXDOMAIN, dns.RcodeNameError},
		{rebind.EmptyRefused, dns.RcodeRefused},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			h := newHarnessAgainstUpstream(t, rebindingUpstream(t), func(o *HandlerOptions) {
				o.Rebinding = filtering(t, tc.action)
			})
			// AAAA: the stub answers with a ULA and nothing else, so every
			// address is filtered.
			resp := h.handler.Handle(context.Background(), query("rebind.example", dns.TypeAAAA), clientMeta("10.0.4.1"))
			if resp == nil {
				t.Fatal("no response at all; a filtered answer must not be a dropped packet")
			}
			if resp.Rcode != tc.rcode {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.rcode])
			}
			if len(resp.Answer) != 0 {
				t.Errorf("records survived: %v", answerAddrs(resp))
			}
			if _, emptied := h.handler.RebindingStats(); emptied != 1 {
				t.Errorf("emptied counter = %d, want 1", emptied)
			}
		})
	}
}

// TestTwoNetworksNeverReceiveEachOthersView is the load-bearing test of this
// PR.
//
// The answer cache is keyed by question alone, so one entry is shared by every
// network on the resolver. If the filter ran on the way into the cache, the
// first network to ask would decide what every later network sees — an
// exempted network would poison the cache with a private address for everyone,
// and a non-exempt one would hide a legitimate answer from the network that is
// allowed it. Both directions are checked, and in both orders, because a
// cache bug that only shows up when the exempt client asks first is still a
// cache bug.
func TestTwoNetworksNeverReceiveEachOthersView(t *testing.T) {
	for _, order := range []string{"exempt first", "filtered first"} {
		t.Run(order, func(t *testing.T) {
			// A caching resolver, deliberately: with the cache off this test
			// would exercise per-policy exemptions and prove nothing at all
			// about the cache, which is the half that can leak one network's
			// answer to another.
			h := newHarnessWithCache(t, rebindingUpstream(t), func(o *HandlerOptions) {
				o.Rebinding = filtering(t, rebind.EmptyNoData)
			})
			ctx := context.Background()

			// An office policy that legitimately receives 10/8, and a network
			// on it. Everything else stays on the default policy, which has no
			// exemption.
			office, err := h.store.CreatePolicy(ctx, store.PolicyInput{
				Name:                ptrString("Office"),
				RebindingExemptions: &[]string{"10.0.0.0/8"},
			})
			if err != nil {
				t.Fatalf("CreatePolicy: %v", err)
			}
			if _, err := h.store.CreateNetwork(ctx, store.NetworkInput{
				Name:     ptrString("Office LAN"),
				PolicyID: ptrString(office.ID),
				CIDRs:    &[]string{"192.168.50.0/24"},
			}); err != nil {
				t.Fatalf("CreateNetwork: %v", err)
			}
			if err := h.engine.Reload(ctx); err != nil {
				t.Fatalf("Reload: %v", err)
			}

			exempt := func() []string {
				return answerAddrs(h.handler.Handle(ctx, query("shared.example", dns.TypeA), clientMeta("192.168.50.9")))
			}
			plain := func() []string {
				return answerAddrs(h.handler.Handle(ctx, query("shared.example", dns.TypeA), clientMeta("10.9.9.9")))
			}

			var first, second []string
			if order == "exempt first" {
				first, second = exempt(), plain()
			} else {
				first, second = plain(), exempt()
			}
			exemptView, plainView := first, second
			if order == "filtered first" {
				exemptView, plainView = second, first
			}

			if len(exemptView) != 2 {
				t.Errorf("the exempt network received %v, want both addresses", exemptView)
			}
			if len(plainView) != 1 || plainView[0] != "93.184.216.34" {
				t.Errorf("the non-exempt network received %v, want only the public address", plainView)
			}
		})
	}
}

// TestACachedPrivateAnswerIsFilteredOnEveryServe is the same property with a
// private address actually present, which is the case that matters.
func TestACachedPrivateAnswerIsFilteredOnEveryServe(t *testing.T) {
	h := newHarnessWithCache(t, rebindingUpstream(t), func(o *HandlerOptions) {
		o.Rebinding = filtering(t, rebind.EmptyNoData)
	})
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		got := answerAddrs(h.handler.Handle(ctx, query("cached.example", dns.TypeA), clientMeta("10.0.5.2")))
		if len(got) != 1 || got[0] != "93.184.216.34" {
			t.Fatalf("lookup %d returned %v, want only the public address", i, got)
		}
	}
	if filtered, _ := h.handler.RebindingStats(); filtered != 5 {
		t.Errorf("filtered %d of 5 serves; a cache hit skipped the filter", filtered)
	}
}

// TestTheCachedAnswerIsNeverMutated. The filter edits the message in place,
// which is only safe because the resolver hands out a private copy. If that
// ever stopped being true the filter would corrupt the shared cache entry —
// silently, and for every client — so the assumption is pinned here rather
// than left as a comment.
func TestTheCachedAnswerIsNeverMutated(t *testing.T) {
	h := newHarnessWithCache(t, rebindingUpstream(t), func(o *HandlerOptions) {
		o.Rebinding = filtering(t, rebind.EmptyNoData)
	})
	ctx := context.Background()

	// Populate the cache through a client whose answer is filtered.
	h.handler.Handle(ctx, query("shared.example", dns.TypeA), clientMeta("10.0.6.1"))

	// Now serve the same name to an exempt policy. If the first serve had
	// mutated the cache, the private address would be gone for good and this
	// client would receive one address instead of two.
	office, err := h.store.CreatePolicy(ctx, store.PolicyInput{
		Name:                ptrString("Office"),
		RebindingExemptions: &[]string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := h.store.CreateNetwork(ctx, store.NetworkInput{
		Name: ptrString("Office"), PolicyID: ptrString(office.ID), CIDRs: &[]string{"192.168.60.0/24"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	got := answerAddrs(h.handler.Handle(ctx, query("shared.example", dns.TypeA), clientMeta("192.168.60.5")))
	if len(got) != 2 {
		t.Errorf("the exempt client received %v; an earlier filtered serve appears to have mutated the cache", got)
	}
}

// TestATokenIdentifiedClientUsesItsOwnNetworksExemptions. A roaming DoH client
// is identified by its token, so its exemptions must come from that network
// rather than from whatever policy its coffee-shop IP would have matched.
func TestATokenIdentifiedClientUsesItsOwnNetworksExemptions(t *testing.T) {
	h := newHarnessAgainstUpstream(t, rebindingUpstream(t), func(o *HandlerOptions) {
		o.Rebinding = filtering(t, rebind.EmptyNoData)
	})
	ctx := context.Background()

	office, err := h.store.CreatePolicy(ctx, store.PolicyInput{
		Name:                ptrString("Office"),
		RebindingExemptions: &[]string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	roaming, err := h.store.CreateNetwork(ctx, store.NetworkInput{
		Name: ptrString("Roaming"), PolicyID: ptrString(office.ID),
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Same source address, once without the token and once with it.
	plain := answerAddrs(h.handler.Handle(ctx, query("split.example", dns.TypeA), clientMeta("203.0.113.7")))
	if len(plain) != 1 {
		t.Errorf("without a token the client received %v, want only the public address", plain)
	}

	withToken := answerAddrs(h.handler.Handle(ctx, query("split.example", dns.TypeA), requestMeta{
		clientAddr: netip.MustParseAddr("203.0.113.7"),
		proto:      "doh",
		networkID:  roaming.ID,
	}))
	if len(withToken) != 2 {
		t.Errorf("with its network's token the client received %v, want both addresses", withToken)
	}
}

// TestTheQueryLogSaysWhichAddressAndWhichPolicy. An operator whose intranet
// stopped working needs to be told what was withheld and where to exempt it.
func TestTheQueryLogSaysWhichAddressAndWhichPolicy(t *testing.T) {
	h := newHarnessAgainstUpstream(t, rebindingUpstream(t), func(o *HandlerOptions) {
		o.Rebinding = filtering(t, rebind.EmptyNoData)
	})
	ctx := context.Background()
	h.handler.Handle(ctx, query("rebind.example", dns.TypeA), clientMeta("10.0.7.1"))

	rows := waitForQueryRows(t, h, 1)
	if len(rows) == 0 {
		t.Fatal("no query-log row was written")
	}
	reason := rows[0].Reason
	for _, want := range []string{"10.0.0.1", "10.0.0.0/8"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not mention %q", reason, want)
		}
	}
}

// TestAnACLRefusedClientNeverReachesTheFilter. Order is ACL, then rate limit,
// then resolution, then this. A source that may not use the resolver at all
// must not be able to make it resolve a name and run an answer policy, and
// must still write no query-log row.
func TestAnACLRefusedClientNeverReachesTheFilter(t *testing.T) {
	acl := clientacl.Compute([]string{"10.0.0.0/8"}, false, nil)
	h := newHarnessAgainstUpstream(t, rebindingUpstream(t), func(o *HandlerOptions) {
		o.Rebinding = filtering(t, rebind.EmptyNoData)
		o.ClientACL = acl
		o.RateLimiter = ratelimit.New(ratelimit.Config{Rate: 1000, Burst: 1000, MaxClients: 64})
	})
	ctx := context.Background()

	for i := 0; i < 25; i++ {
		resp := h.handler.Handle(ctx, query("rebind.example", dns.TypeA), clientMeta("203.0.113.9"))
		if resp.Rcode != dns.RcodeRefused {
			t.Fatalf("an unauthorised client got %s", dns.RcodeToString[resp.Rcode])
		}
	}
	if filtered, emptied := h.handler.RebindingStats(); filtered != 0 || emptied != 0 {
		t.Errorf("the filter ran for an ACL-refused client (filtered %d, emptied %d)", filtered, emptied)
	}
	if h.handler.RefusedClients() != 25 {
		t.Errorf("RefusedClients() = %d, want 25", h.handler.RefusedClients())
	}
}

// TestARateLimitedClientNeverReachesTheFilter, for the same reason: the query
// is refused before anything is resolved.
func TestARateLimitedClientNeverReachesTheFilter(t *testing.T) {
	h := newHarnessAgainstUpstream(t, rebindingUpstream(t), func(o *HandlerOptions) {
		o.Rebinding = filtering(t, rebind.EmptyNoData)
		o.RateLimiter = ratelimit.New(ratelimit.Config{Rate: 0.001, Burst: 1, MaxClients: 64})
	})
	ctx := context.Background()

	h.handler.Handle(ctx, query("rebind.example", dns.TypeA), clientMeta("10.0.8.1"))
	before, _ := h.handler.RebindingStats()
	for i := 0; i < 20; i++ {
		h.handler.Handle(ctx, query("rebind.example", dns.TypeA), clientMeta("10.0.8.1"))
	}
	if after, _ := h.handler.RebindingStats(); after != before {
		t.Errorf("the filter ran %d times for rate-limited queries", after-before)
	}
}

// TestAFilterlessHandlerReturnsTheAnswerUnchanged. The upgrade path: an
// installation that has not turned this on must see exactly what it saw
// before, private addresses included.
func TestAFilterlessHandlerReturnsTheAnswerUnchanged(t *testing.T) {
	h := newHarnessAgainstUpstream(t, rebindingUpstream(t), func(o *HandlerOptions) {
		o.Rebinding = nil
	})

	got := answerAddrs(h.handler.Handle(context.Background(), query("rebind.example", dns.TypeA), clientMeta("10.0.9.1")))
	if len(got) != 2 {
		t.Fatalf("an unfiltered handler returned %v, want both addresses", got)
	}
	if filtered, emptied := h.handler.RebindingStats(); filtered != 0 || emptied != 0 {
		t.Error("a handler with no filter reported filtering")
	}
	if h.handler.RebindingFilter() != nil {
		t.Error("RebindingFilter() is not nil on a handler with no filter")
	}
}

// TestClassesAreCountedForMetrics, and stay inside the closed label set.
func TestClassesAreCountedForMetrics(t *testing.T) {
	h := newHarnessAgainstUpstream(t, rebindingUpstream(t), func(o *HandlerOptions) {
		o.Rebinding = filtering(t, rebind.EmptyNoData)
	})
	ctx := context.Background()
	h.handler.Handle(ctx, query("rebind.example", dns.TypeA), clientMeta("10.1.1.1"))
	h.handler.Handle(ctx, query("rebind.example", dns.TypeAAAA), clientMeta("10.1.1.1"))

	counts := h.handler.RebindingClasses()
	if counts[rebind.ClassPrivate] != 1 {
		t.Errorf("private = %d, want 1", counts[rebind.ClassPrivate])
	}
	if counts[rebind.ClassULA] != 1 {
		t.Errorf("ula = %d, want 1", counts[rebind.ClassULA])
	}
	if len(counts) != len(rebind.Classes()) {
		t.Errorf("%d classes reported, want the closed set of %d", len(counts), len(rebind.Classes()))
	}
}

// TestConcurrentClientsWithDifferentExemptions runs the split-horizon case
// under -race, because the exemption set is read from an atomic snapshot that
// a dashboard edit can swap underneath a query.
func TestConcurrentClientsWithDifferentExemptions(t *testing.T) {
	h := newHarnessWithCache(t, rebindingUpstream(t), func(o *HandlerOptions) {
		o.Rebinding = filtering(t, rebind.EmptyNoData)
	})
	ctx := context.Background()

	office, err := h.store.CreatePolicy(ctx, store.PolicyInput{
		Name: ptrString("Office"), RebindingExemptions: &[]string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := h.store.CreateNetwork(ctx, store.NetworkInput{
		Name: ptrString("Office"), PolicyID: ptrString(office.ID), CIDRs: &[]string{"192.168.70.0/24"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				var got []string
				var want int
				if g%2 == 0 {
					got, want = answerAddrs(h.handler.Handle(ctx, query("race.example", dns.TypeA), clientMeta("192.168.70.5"))), 2
				} else {
					got, want = answerAddrs(h.handler.Handle(ctx, query("race.example", dns.TypeA), clientMeta("10.2.2.2"))), 1
				}
				if len(got) != want {
					select {
					case errs <- "goroutine saw the wrong view":
					default:
					}
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// newHarnessWithCache is newHarnessAgainstUpstream with the answer cache on,
// which is what the cache-isolation tests need: without it every lookup is a
// fresh upstream query and the property under test cannot fail.
func newHarnessWithCache(t *testing.T, addr string, opts ...func(*HandlerOptions)) *testHarness {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	holder := blocklist.NewHolder()
	holder.Store(blocklist.NewBuilder(0).Build())
	engine := policy.NewEngine(st, holder)
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("engine.Reload: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	res, err := resolver.New(config.DNS{
		Upstreams:    []string{"udp://" + addr},
		UpstreamMode: "failover",
		Timeout:      config.Duration(2 * time.Second),
	}, config.Cache{Enabled: true, MaxEntries: 100, MinTTL: 30, MaxTTL: 300, NegativeTTL: 30}, log)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}
	t.Cleanup(res.Close)

	qlog := querylog.New(st, querylog.Options{BufferSize: 128, FlushIntervalMS: 20}, log)
	ctx, cancel := context.WithCancel(context.Background())
	go qlog.Run(ctx)
	t.Cleanup(func() { cancel(); qlog.Wait() })

	ho := HandlerOptions{QueryLogEnabled: true, Timeout: 3 * time.Second}
	for _, o := range opts {
		o(&ho)
	}
	return &testHarness{
		handler: NewHandler(engine, res, holder, qlog, log, ho),
		store:   st, engine: engine, qlog: qlog,
	}
}

// waitForQueryRows waits for the batching query logger to flush at least n
// rows.
func waitForQueryRows(t *testing.T, h *testHarness, n int) []store.QueryEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rows, _, err := h.store.ListQueries(context.Background(), store.QueryFilter{Limit: 50})
		if err != nil {
			t.Fatalf("ListQueries: %v", err)
		}
		if len(rows) >= n {
			return rows
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}
