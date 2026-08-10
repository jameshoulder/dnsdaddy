package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/querylog"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// testUpstream runs a throwaway DNS server that answers everything with a
// fixed A record, so handler tests never touch the real internet.
func testUpstream(t *testing.T) string {
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
			if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
				m.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name: req.Question[0].Name, Rrtype: dns.TypeA,
						Class: dns.ClassINET, Ttl: 60,
					},
					A: net.IPv4(203, 0, 113, 10),
				}}
			}
			_ = w.WriteMsg(m)
		}),
	}

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go srv.ActivateAndServe()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("test upstream did not start")
	}
	t.Cleanup(func() { srv.Shutdown() })

	return pc.LocalAddr().String()
}

type testHarness struct {
	handler *Handler
	store   *store.Store
	engine  *policy.Engine
	qlog    *querylog.Logger
}

func newHarness(t *testing.T, lists map[string]string) *testHarness {
	t.Helper()
	return newHarnessWithQueryLog(t, lists, true)
}

// newHarnessWithQueryLog is newHarness with the instance-wide query_log
// switch (config.Logging.QueryLog) exposed, for tests that need it off.
func newHarnessWithQueryLog(t *testing.T, lists map[string]string, queryLogEnabled bool, opts ...func(*HandlerOptions)) *testHarness {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	holder := blocklist.NewHolder()
	b := blocklist.NewBuilder(len(lists))
	for domain, cat := range lists {
		b.Add(domain, blocklist.Entry{Category: cat, FeedID: "f_test", FeedName: "Test feed"})
	}
	holder.Store(b.Build())

	engine := policy.NewEngine(st, holder)
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("engine.Reload: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	res, err := resolver.New(config.DNS{
		Upstreams:    []string{"udp://" + testUpstream(t)},
		UpstreamMode: "failover",
		Timeout:      config.Duration(2 * time.Second),
	}, config.Cache{Enabled: true, MaxEntries: 100, MinTTL: 1, MaxTTL: 60, NegativeTTL: 10}, log)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}
	t.Cleanup(res.Close)

	qlog := querylog.New(st, querylog.Options{BufferSize: 128, FlushIntervalMS: 20}, log)
	ctx, cancel := context.WithCancel(context.Background())
	go qlog.Run(ctx)
	t.Cleanup(func() {
		cancel()
		qlog.Wait()
	})

	ho := HandlerOptions{
		LogClientIP:     true,
		QueryLogEnabled: queryLogEnabled,
		Timeout:         3 * time.Second,
	}
	for _, o := range opts {
		o(&ho)
	}
	h := NewHandler(engine, res, holder, qlog, log, ho)

	return &testHarness{handler: h, store: st, engine: engine, qlog: qlog}
}

// newHarnessWithOptions is newHarness with the security-relevant handler
// options (client ACL, ANY handling) exposed.
func newHarnessWithOptions(t *testing.T, lists map[string]string, opts ...func(*HandlerOptions)) *testHarness {
	t.Helper()
	return newHarnessWithQueryLog(t, lists, true, opts...)
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

func clientMeta(ip string) requestMeta {
	return requestMeta{clientAddr: netip.MustParseAddr(ip), proto: "udp"}
}

func TestHandlerResolvesCleanDomain(t *testing.T) {
	h := newHarness(t, nil)

	resp := h.handler.Handle(context.Background(), query("example.com", dns.TypeA), clientMeta("10.0.0.5"))
	if resp == nil {
		t.Fatal("no response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1 from the upstream", len(resp.Answer))
	}
	if !resp.RecursionAvailable {
		t.Error("RA flag not set; clients treat that as a non-recursive server")
	}
}

func TestHandlerBlocksListedDomain(t *testing.T) {
	h := newHarness(t, map[string]string{"evil.com": "malware"})

	resp := h.handler.Handle(context.Background(), query("evil.com", dns.TypeA), clientMeta("10.0.0.5"))
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Error("a blocked query returned an answer")
	}

	_, blocked, _ := h.handler.Stats()
	if blocked != 1 {
		t.Errorf("blocked counter = %d, want 1", blocked)
	}
}

func TestHandlerBlocksSubdomainOfListedDomain(t *testing.T) {
	h := newHarness(t, map[string]string{"evil.com": "malware"})

	resp := h.handler.Handle(context.Background(), query("login.evil.com", dns.TypeA), clientMeta("10.0.0.5"))
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN for a subdomain of a blocked name", dns.RcodeToString[resp.Rcode])
	}
}

func TestHandlerPreservesMessageID(t *testing.T) {
	h := newHarness(t, nil)

	req := query("example.com", dns.TypeA)
	req.Id = 4242

	resp := h.handler.Handle(context.Background(), req, clientMeta("10.0.0.5"))
	if resp.Id != 4242 {
		t.Errorf("response ID = %d, want the request's 4242 — clients drop mismatched IDs", resp.Id)
	}
	if len(resp.Question) != 1 || resp.Question[0].Name != "example.com." {
		t.Errorf("question section = %+v, want it echoed back", resp.Question)
	}
}

func TestBlockModeZeroIP(t *testing.T) {
	h := newHarness(t, map[string]string{"evil.com": "malware"})
	ctx := context.Background()

	if _, err := h.store.UpdatePolicy(ctx, "p_standard", store.PolicyInput{
		BlockMode: ptrBlockMode(store.BlockZeroIP),
	}); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resp := h.handler.Handle(ctx, query("evil.com", dns.TypeA), clientMeta("10.0.0.5"))
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR in zeroip mode", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want a single 0.0.0.0 record", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.IPv4zero) {
		t.Errorf("answer = %v, want 0.0.0.0", resp.Answer[0])
	}
	if ttl := a.Hdr.Ttl; ttl > 60 {
		t.Errorf("block TTL = %d; a long TTL means an allow-listing takes hours to apply", ttl)
	}
}

func TestBlockModeRefused(t *testing.T) {
	h := newHarness(t, map[string]string{"evil.com": "malware"})
	ctx := context.Background()

	if _, err := h.store.UpdatePolicy(ctx, "p_standard", store.PolicyInput{
		BlockMode: ptrBlockMode(store.BlockRefused),
	}); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resp := h.handler.Handle(ctx, query("evil.com", dns.TypeA), clientMeta("10.0.0.5"))
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

func TestZeroIPModeAnswersAAAA(t *testing.T) {
	h := newHarness(t, map[string]string{"evil.com": "malware"})
	ctx := context.Background()

	if _, err := h.store.UpdatePolicy(ctx, "p_standard", store.PolicyInput{
		BlockMode: ptrBlockMode(store.BlockZeroIP),
	}); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resp := h.handler.Handle(ctx, query("evil.com", dns.TypeAAAA), clientMeta("10.0.0.5"))
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers for AAAA, want 1", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.AAAA); !ok {
		t.Errorf("answer type = %T, want *dns.AAAA", resp.Answer[0])
	}
}

func TestHandlerRejectsNonQueryOpcode(t *testing.T) {
	h := newHarness(t, nil)

	req := query("example.com", dns.TypeA)
	req.Opcode = dns.OpcodeUpdate

	resp := h.handler.Handle(context.Background(), req, clientMeta("10.0.0.5"))
	if resp.Rcode != dns.RcodeNotImplemented {
		t.Errorf("rcode = %s, want NOTIMP", dns.RcodeToString[resp.Rcode])
	}
}

func TestHandlerRejectsEmptyQuestion(t *testing.T) {
	h := newHarness(t, nil)

	resp := h.handler.Handle(context.Background(), new(dns.Msg), clientMeta("10.0.0.5"))
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("rcode = %s, want FORMERR", dns.RcodeToString[resp.Rcode])
	}
}

func TestHandlerRejectsMultipleQuestions(t *testing.T) {
	// Policy only ever evaluates Question[0]. If the whole message still went
	// upstream, a second question could ride along unevaluated — reject the
	// message outright instead.
	h := newHarness(t, map[string]string{"evil.com": "malware"})

	req := query("example.com", dns.TypeA)
	req.Question = append(req.Question, dns.Question{
		Name: dns.Fqdn("evil.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET,
	})

	resp := h.handler.Handle(context.Background(), req, clientMeta("10.0.0.5"))
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("rcode = %s, want FORMERR for a multi-question message", dns.RcodeToString[resp.Rcode])
	}
}

func TestHandlerRejectsNonInternetClass(t *testing.T) {
	h := newHarness(t, nil)

	req := query("example.com", dns.TypeA)
	req.Question[0].Qclass = dns.ClassCHAOS

	resp := h.handler.Handle(context.Background(), req, clientMeta("10.0.0.5"))
	if resp.Rcode != dns.RcodeNotImplemented {
		t.Errorf("rcode = %s, want NOTIMP for a non-IN query class", dns.RcodeToString[resp.Rcode])
	}
}

func TestHandlerServesFromCacheOnRepeat(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	h.handler.Handle(ctx, query("example.com", dns.TypeA), clientMeta("10.0.0.5"))
	resp := h.handler.Handle(ctx, query("example.com", dns.TypeA), clientMeta("10.0.0.5"))

	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("second lookup failed: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
}

func TestHandlerLogsBlockReason(t *testing.T) {
	h := newHarness(t, map[string]string{"evil.com": "malware"})
	ctx := context.Background()

	h.handler.Handle(ctx, query("evil.com", dns.TypeA), clientMeta("10.0.4.23"))

	// Give the batching logger a moment to flush.
	deadline := time.Now().Add(3 * time.Second)
	var rows []store.QueryEvent
	for time.Now().Before(deadline) {
		var err error
		rows, _, err = h.store.ListQueries(ctx, store.QueryFilter{Limit: 10})
		if err != nil {
			t.Fatalf("ListQueries: %v", err)
		}
		if len(rows) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if len(rows) == 0 {
		t.Fatal("the blocked query was never written to the query log")
	}
	row := rows[0]
	if row.Action != store.ActionBlocked {
		t.Errorf("action = %q, want blocked", row.Action)
	}
	if row.Reason == "" {
		t.Error("no reason recorded; the operator cannot explain the block to a user")
	}
	if row.Category != "malware" {
		t.Errorf("category = %q, want malware", row.Category)
	}
	if row.ClientIP != "10.0.4.23" {
		t.Errorf("clientIp = %q, want 10.0.4.23", row.ClientIP)
	}
	if row.Source != "Test feed" {
		t.Errorf("source = %q, want the feed that matched", row.Source)
	}
}

func TestGlobalQueryLogDisabledSkipsPersistButKeepsStats(t *testing.T) {
	// The instance-wide query_log switch must actually gate persistence, not
	// just be read back on the settings page. Statistics — which drive the
	// dashboard and reports — must still increase either way.
	h := newHarnessWithQueryLog(t, map[string]string{"evil.com": "malware"}, false)
	ctx := context.Background()

	h.handler.Handle(ctx, query("evil.com", dns.TypeA), clientMeta("10.0.4.23"))

	deadline := time.Now().Add(3 * time.Second)
	var totals store.Totals
	for time.Now().Before(deadline) {
		var err error
		totals, err = h.store.TotalsSince(ctx, time.Now().Add(-time.Hour))
		if err != nil {
			t.Fatalf("TotalsSince: %v", err)
		}
		if totals.Blocked > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if totals.Blocked == 0 {
		t.Fatal("rollup statistics did not increase with query logging disabled")
	}

	rows, _, err := h.store.ListQueries(ctx, store.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListQueries: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("got %d stored query-log rows, want 0 with the global switch off", len(rows))
	}
}

func TestHandlerAttributesDoHTokenToNetwork(t *testing.T) {
	h := newHarness(t, map[string]string{"adult.example": "adult"})
	ctx := context.Background()

	// A roaming network on the strict policy. Its clients arrive from arbitrary
	// IPs, so only the token can identify them.
	roaming, err := h.store.CreateNetwork(ctx, store.NetworkInput{
		Name: ptrString("Roaming"), PolicyID: ptrString("p_strict"),
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// From a coffee-shop IP with no token, the catch-all standard policy applies
	// and adult content is not blocked.
	plain := h.handler.Handle(ctx, query("adult.example", dns.TypeA), clientMeta("203.0.113.7"))
	if plain.Rcode == dns.RcodeNameError {
		t.Error("the default policy blocked adult content, which it does not enable")
	}

	// With the roaming network's token, the strict policy applies.
	withToken := h.handler.Handle(ctx, query("adult.example", dns.TypeA), requestMeta{
		clientAddr: netip.MustParseAddr("203.0.113.7"),
		proto:      "doh",
		networkID:  roaming.ID,
	})
	if withToken.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN — the token should have applied the strict policy",
			dns.RcodeToString[withToken.Rcode])
	}
}

func TestHandlerAppliesPerNetworkPolicy(t *testing.T) {
	h := newHarness(t, map[string]string{"gambling.example": "gambling"})
	ctx := context.Background()

	if _, err := h.store.CreateNetwork(ctx, store.NetworkInput{
		Name:     ptrString("Production floor"),
		PolicyID: ptrString("p_strict"),
		CIDRs:    &[]string{"10.4.9.0/24"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	strict := h.handler.Handle(ctx, query("gambling.example", dns.TypeA), clientMeta("10.4.9.15"))
	if strict.Rcode != dns.RcodeNameError {
		t.Error("the strict network did not block gambling")
	}

	standard := h.handler.Handle(ctx, query("gambling.example", dns.TypeA), clientMeta("192.168.1.20"))
	if standard.Rcode == dns.RcodeNameError {
		t.Error("a client outside the strict network had gambling blocked")
	}
}

func ptrBlockMode(m store.BlockMode) *store.BlockMode { return &m }
func ptrString(s string) *string                      { return &s }
