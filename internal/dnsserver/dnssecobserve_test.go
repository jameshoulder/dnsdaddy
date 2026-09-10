package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/querylog"
	"github.com/jameshoulder/dnsdaddy/internal/resolution"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// recordingObserver stands in for the real one and does whatever a test needs,
// including things a real observer will not do on demand.
type recordingObserver struct {
	mu       sync.Mutex
	requests []observe.Request
	accept   bool
	// block, when set, makes Observe wait — which a real observer never does,
	// so a test can prove the handler would notice if it did.
	block time.Duration
	// panics makes Observe panic, to check the handler's own robustness at
	// the seam rather than the observer's.
	panics bool
}

func (r *recordingObserver) Observe(req observe.Request) bool {
	if r.panics {
		panic("deliberate observer panic")
	}
	if r.block > 0 {
		time.Sleep(r.block)
	}
	r.mu.Lock()
	r.requests = append(r.requests, req)
	r.mu.Unlock()
	return r.accept
}

func (r *recordingObserver) seen() []observe.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]observe.Request(nil), r.requests...)
}

func withObserver(o DNSSECObserver) func(*HandlerOptions) {
	return func(h *HandlerOptions) { h.DNSSEC = o }
}

// answerBytes packs a response so two of them can be compared as the client
// would see them, rather than field by field with something forgotten.
func answerBytes(t *testing.T, m *dns.Msg) []byte {
	t.Helper()
	if m == nil {
		return nil
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("packing the response: %v", err)
	}
	return b
}

// TestObservationCannotChangeTheAnswer is the central safety property of
// observe mode, and the reason the milestone is allowed to exist at all.
//
// The observer is made to behave in every way a hostile zone or a broken
// validator could make it behave — accepting, refusing, hanging, panicking —
// and the bytes the client receives must be identical every time, and
// identical to a run with no observer at all.
//
// Comparing packed messages rather than fields is deliberate: a test that
// checked RCODE and the answer section would pass while observe mode quietly
// set AD, changed a TTL, or dropped the authority section.
func TestObservationCannotChangeTheAnswer(t *testing.T) {
	req := query("example.com.", dns.TypeA)

	baseline := newHarness(t, nil)
	want := answerBytes(t, baseline.handler.Handle(context.Background(), req.Copy(), requestMeta{proto: "udp"}))
	if len(want) == 0 {
		t.Fatal("the baseline produced no response")
	}

	for _, tc := range []struct {
		name string
		obs  *recordingObserver
	}{
		{"accepts", &recordingObserver{accept: true}},
		{"refuses because its queue is full", &recordingObserver{accept: false}},
		{"is slow", &recordingObserver{accept: true, block: 50 * time.Millisecond}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarnessWithOptions(t, nil, withObserver(tc.obs))
			got := answerBytes(t, h.handler.Handle(context.Background(), req.Copy(), requestMeta{proto: "udp"}))

			if string(got) != string(want) {
				t.Fatalf("the response changed when an observer was attached\n got: %x\nwant: %x", got, want)
			}
			if len(tc.obs.seen()) != 1 {
				t.Errorf("the observer saw %d queries, want 1", len(tc.obs.seen()))
			}
		})
	}
}

// TestEveryVerdictProducesTheSameAnswer is the same property stated the way
// the brief asks for it: with Secure, Insecure, Bogus and Indeterminate.
//
// The handler never sees a verdict — that is the design — so this drives the
// real observer with a stub validator and checks the answer through the whole
// path. A design in which the verdict came back to the handler would fail
// here rather than in review.
func TestEveryVerdictProducesTheSameAnswer(t *testing.T) {
	req := query("example.com.", dns.TypeA)

	baseline := newHarness(t, nil)
	want := answerBytes(t, baseline.handler.Handle(context.Background(), req.Copy(), requestMeta{proto: "udp"}))

	for _, name := range []string{"secure", "insecure", "bogus", "indeterminate", "timeout", "panic"} {
		t.Run(name, func(t *testing.T) {
			v := verdictValidator(name)
			o := observe.New(v, nil, observe.Options{Workers: 1, Timeout: 50 * time.Millisecond})
			ctx, cancel := context.WithCancel(context.Background())
			go o.Run(ctx)
			t.Cleanup(func() { cancel(); o.Wait() })

			h := newHarnessWithOptions(t, nil, withObserver(o))
			got := answerBytes(t, h.handler.Handle(context.Background(), req.Copy(), requestMeta{proto: "udp"}))
			if string(got) != string(want) {
				t.Fatalf("a %s verdict changed the client's answer", name)
			}
		})
	}
}

// TestTheHandlerSurvivesAnObserverPanic covers the seam itself.
//
// The observer contains its own panics, and a test in that package proves it.
// This checks the other half: that the handler does not acquire a new way to
// die if something at the seam misbehaves anyway. A panic here would run on
// the goroutine serving a client's query.
func TestTheHandlerSurvivesAnObserverPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("an observer panic reached the query path: %v", r)
		}
	}()

	// One request, copied, so the two responses differ only in what this test
	// is about. dns.SetQuestion picks a random message id, and comparing two
	// separately built queries would fail on that alone.
	req := query("example.com.", dns.TypeA)

	h := newHarnessWithOptions(t, nil, withObserver(&recordingObserver{panics: true}))
	resp := h.handler.Handle(context.Background(), req.Copy(), requestMeta{proto: "udp"})
	if resp == nil {
		t.Fatal("no response was produced")
	}
	// Contained, not absorbed: the count is what turns this from a silent
	// swallow into something an operator and a maintainer can see.
	if n := h.handler.DNSSECObserverPanics(); n != 1 {
		t.Errorf("contained panics = %d, want 1", n)
	}

	// And the answer is still the one the resolver produced.
	baseline := newHarness(t, nil)
	want := answerBytes(t, baseline.handler.Handle(context.Background(),
		req.Copy(), requestMeta{proto: "udp"}))
	if string(answerBytes(t, resp)) != string(want) {
		t.Error("a contained panic changed the client's answer")
	}
}

// TestBlockedAndFailedQueriesAreNotObserved is ADR 0002 §7.
//
// A blocked name has no upstream answer to reason about, and observing it
// would send queries upstream for a name the operator chose to block — a
// behaviour change, and one that leaks the blocked lookup to the upstream.
func TestBlockedAndFailedQueriesAreNotObserved(t *testing.T) {
	obs := &recordingObserver{accept: true}
	h := newHarnessWithOptions(t, map[string]string{"blocked.example": "malware"}, withObserver(obs))

	resp := h.handler.Handle(context.Background(), query("blocked.example.", dns.TypeA), requestMeta{proto: "udp"})
	if resp == nil {
		t.Fatal("no response for the blocked name")
	}
	if n := len(obs.seen()); n != 0 {
		t.Fatalf("a blocked query was observed (%d times); that sends the lookup upstream anyway", n)
	}

	// And a resolved one still is, so the check above is not passing because
	// nothing is ever observed.
	h.handler.Handle(context.Background(), query("allowed.example.", dns.TypeA), requestMeta{proto: "udp"})
	if n := len(obs.seen()); n != 1 {
		t.Fatalf("a resolved query was observed %d times, want 1", n)
	}
}

// TestAnANYRefusalIsNotObserved: RFC 8482 answers are synthesised locally, so
// there is no upstream answer to validate.
func TestAnANYRefusalIsNotObserved(t *testing.T) {
	obs := &recordingObserver{accept: true}
	h := newHarnessWithOptions(t, nil,
		func(o *HandlerOptions) { o.RefuseANY = true },
		withObserver(obs))

	h.handler.Handle(context.Background(), query("example.com.", dns.TypeANY), requestMeta{proto: "udp"})
	if n := len(obs.seen()); n != 0 {
		t.Fatalf("a locally synthesised ANY refusal was observed %d times", n)
	}
}

// TestTheObservationCarriesTheUpstreamVerdictWithoutMergingIt is ADR 0002 §9.
//
// Both facts travel together and stay separate. The query event keeps the
// upstream's conclusion in its own field; the observation carries a copy so
// its row is self-contained. Neither is derived from the other.
func TestTheObservationCarriesTheUpstreamVerdictWithoutMergingIt(t *testing.T) {
	obs := &recordingObserver{accept: true}
	h := newHarnessWithOptions(t, nil, withObserver(obs))

	h.handler.Handle(context.Background(), query("example.com.", dns.TypeA), requestMeta{proto: "udp"})
	seen := obs.seen()
	if len(seen) != 1 {
		t.Fatalf("observed %d queries, want 1", len(seen))
	}
	req := seen[0]
	if req.Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", req.Domain)
	}
	if req.QType != dns.TypeA {
		t.Errorf("qtype = %d, want %d", req.QType, dns.TypeA)
	}
	// The test upstream does not set AD, so the upstream status is
	// "unvalidated" — carried as-is rather than reinterpreted.
	if req.UpstreamStatus != store.DNSSECUnvalidated {
		t.Errorf("upstream status = %q, want %q", req.UpstreamStatus, store.DNSSECUnvalidated)
	}
	if req.ID == "" {
		t.Error("no correlation id was assigned")
	}
}

// TestADroppedObservationLeavesNoCorrelationID stops the query log claiming a
// verdict that will never be written.
func TestADroppedObservationLeavesNoCorrelationID(t *testing.T) {
	h := newHarnessWithOptions(t, nil, withObserver(&recordingObserver{accept: false}))

	// Reach into the handler's own bookkeeping the same way Handle does, so
	// the assertion is about the value that would be stored.
	event := store.QueryEvent{Domain: "example.com", DNSSEC: store.DNSSECUnvalidated}
	got := h.handler.observeDNSSEC(event, dns.Question{Name: "example.com.", Qtype: dns.TypeA}, true)
	if got != "" {
		t.Fatalf("a refused observation still produced a correlation id %q", got)
	}
}

// TestObservationIsOffByDefault: a handler built without the option must not
// acquire the behaviour, and must not pay for it either.
func TestObservationIsOffByDefault(t *testing.T) {
	h := newHarness(t, nil)
	if h.handler.dnssec != nil {
		t.Fatal("a handler built without the option has an observer attached")
	}
	event := store.QueryEvent{Domain: "example.com"}
	if id := h.handler.observeDNSSEC(event, dns.Question{Name: "example.com.", Qtype: dns.TypeA}, true); id != "" {
		t.Fatalf("observation happened with no observer configured: %q", id)
	}
}

// verdictValidator returns a validator that always reaches one outcome.
//
// Test-only, and the reason this file may import the engine at all: the
// isolation test reads non-test files only, so a stub here cannot widen the
// import graph the production build is checked against.
func verdictValidator(kind string) observe.Validator {
	return validatorFunc(func(ctx context.Context, qname string, rrtype uint16) dnssec.ValidationResult {
		switch kind {
		case "panic":
			panic("deliberate")
		case "timeout":
			<-ctx.Done()
			return dnssec.ValidationResult{Status: dnssec.StatusIndeterminate, Reason: dnssec.ReasonCancelled}
		case "secure":
			return dnssec.ValidationResult{Status: dnssec.StatusSecure, Reason: dnssec.ReasonVerified}
		case "insecure":
			return dnssec.ValidationResult{Status: dnssec.StatusInsecure, Reason: dnssec.ReasonVerified}
		case "bogus":
			return dnssec.ValidationResult{Status: dnssec.StatusBogus, Reason: dnssec.ReasonSignatureCryptoFailed}
		default:
			return dnssec.ValidationResult{Status: dnssec.StatusIndeterminate, Reason: dnssec.ReasonNoTrustAnchor}
		}
	})
}

type validatorFunc func(context.Context, string, uint16) dnssec.ValidationResult

func (f validatorFunc) Validate(ctx context.Context, qname string, rrtype uint16) dnssec.ValidationResult {
	return f(ctx, qname, rrtype)
}

// TestClientDNSSECFlagsAreUnchangedByObservation is Phase 15 of the brief.
//
// Observe mode must not give DNS Daddy a new opinion about AD, DO or CD. The
// AD bit in particular is the one an enforcing resolver would eventually set,
// and setting it here — on the strength of a verdict from an engine that has
// never run in production — would assert an end-to-end guarantee DNS Daddy
// cannot yet make.
//
// Each client shape is asked twice, once with an observer attached and once
// without, and the packed responses must match. Byte comparison catches the AD
// bit, the DO bit in the echoed OPT, and anything else that moved.
func TestClientDNSSECFlagsAreUnchangedByObservation(t *testing.T) {
	shapes := map[string]func(*dns.Msg){
		"plain": func(*dns.Msg) {},
		"DO set": func(m *dns.Msg) {
			m.SetEdns0(4096, true)
		},
		"AD requested": func(m *dns.Msg) {
			m.AuthenticatedData = true
		},
		"CD set": func(m *dns.Msg) {
			m.CheckingDisabled = true
		},
		"DO and CD": func(m *dns.Msg) {
			m.SetEdns0(4096, true)
			m.CheckingDisabled = true
		},
	}

	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			req := query("example.com.", dns.TypeA)
			shape(req)

			off := newHarness(t, nil)
			want := off.handler.Handle(context.Background(), req.Copy(), requestMeta{proto: "udp"})

			on := newHarnessWithOptions(t, nil, withObserver(&recordingObserver{accept: true}))
			got := on.handler.Handle(context.Background(), req.Copy(), requestMeta{proto: "udp"})

			if string(answerBytes(t, got)) != string(answerBytes(t, want)) {
				t.Fatalf("observation changed the response for a %s client\n got AD=%v CD=%v\nwant AD=%v CD=%v",
					name, got.AuthenticatedData, got.CheckingDisabled,
					want.AuthenticatedData, want.CheckingDisabled)
			}

			// Stated separately as well, because this is the bit that would
			// matter most if it ever moved and the one a reader will look for.
			if got.AuthenticatedData {
				t.Error("observe mode set the AD bit; local validation is not authoritative and must not claim to be")
			}
		})
	}
}

// TestObservationDoesNotChangeWhatIsSentUpstream keeps observe mode from
// altering the client's own resolution.
//
// The supporting DNSSEC queries go through their own Source and their own
// upstream calls. The query the resolver sends on the client's behalf must be
// untouched — in particular it must not acquire DO, which would enlarge every
// response DNS Daddy handles for clients that never asked for one.
func TestObservationDoesNotChangeWhatIsSentUpstream(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []*dns.Msg
	)
	addr := recordingUpstream(t, &mu, &seen)

	newRecorded := func(withObs bool) {
		opts := []func(*HandlerOptions){}
		if withObs {
			opts = append(opts, withObserver(&recordingObserver{accept: true}))
		}
		h := newHarnessAgainstUpstream(t, addr, opts...)
		h.handler.Handle(context.Background(), query("example.com.", dns.TypeA), requestMeta{proto: "udp"})
	}

	newRecorded(false)
	mu.Lock()
	baseline := len(seen)
	var baselineMsg *dns.Msg
	if baseline > 0 {
		baselineMsg = seen[0].Copy()
	}
	seen = nil
	mu.Unlock()
	if baseline == 0 {
		t.Fatal("the baseline sent nothing upstream")
	}

	newRecorded(true)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != baseline {
		t.Fatalf("observation changed how many queries the resolver sent: %d, want %d", len(seen), baseline)
	}
	got := seen[0]
	if got.CheckingDisabled != baselineMsg.CheckingDisabled {
		t.Error("observation changed the CD bit on the client's own upstream query")
	}
	gotOpt, wantOpt := got.IsEdns0(), baselineMsg.IsEdns0()
	if (gotOpt == nil) != (wantOpt == nil) {
		t.Fatal("observation changed whether the client's upstream query carried EDNS0")
	}
	if gotOpt != nil && gotOpt.Do() != wantOpt.Do() {
		t.Error("observation set DO on the client's own upstream query; every response would grow")
	}
}

// TestSupportingQueriesAreDistinguishableFromClientTraffic is Phase 16 of the
// brief, checked end to end with a real observer and a real Source rather than
// a stub.
//
// Two things have to be true at once. The query the resolver sends on the
// client's behalf must be untouched — no DO, no CD, so responses do not grow
// for clients that never asked. And the observer's own supporting queries must
// be recognisable as internal activity, which they are precisely because they
// carry DO and CD: no client query from DNS Daddy's resolver ever sets CD.
func TestSupportingQueriesAreDistinguishableFromClientTraffic(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []*dns.Msg
	)
	addr := recordingUpstream(t, &mu, &seen)

	src := observe.NewSource([]observe.Exchanger{upstreamAt(t, addr)}, observe.SourceOptions{})
	o := observe.New(sourceProbingValidator{src}, nil, observe.Options{Workers: 1, Timeout: 2 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	go o.Run(ctx)
	t.Cleanup(func() { cancel(); o.Wait() })

	h := newHarnessAgainstUpstream(t, addr, withObserver(o))
	h.handler.Handle(context.Background(), query("example.com.", dns.TypeA), requestMeta{proto: "udp"})

	// Wait for the observation to have run.
	deadline := time.Now().Add(3 * time.Second)
	for o.Stats().Observed == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if o.Stats().Observed == 0 {
		t.Fatal("no observation completed")
	}

	mu.Lock()
	defer mu.Unlock()

	var client, supporting int
	for _, m := range seen {
		opt := m.IsEdns0()
		internal := m.CheckingDisabled && opt != nil && opt.Do()
		if internal {
			supporting++
			continue
		}
		client++
		if m.CheckingDisabled {
			t.Error("the client's own upstream query carried CD")
		}
		if opt != nil && opt.Do() {
			t.Error("the client's own upstream query carried DO; every response would grow")
		}
	}
	if client != 1 {
		t.Errorf("the resolver sent %d client queries, want 1", client)
	}
	if supporting == 0 {
		t.Error("no supporting query was sent, so this test proved nothing about them")
	}
}

// sourceProbingValidator asks the Source one question, which is enough to make
// supporting traffic appear without needing a signed hierarchy.
type sourceProbingValidator struct{ src *observe.Source }

func (v sourceProbingValidator) Validate(ctx context.Context, qname string, rrtype uint16) dnssec.ValidationResult {
	if _, err := v.src.Lookup(ctx, qname, rrtype); err != nil {
		return dnssec.ValidationResult{Status: dnssec.StatusIndeterminate, Reason: dnssec.ReasonCancelled}
	}
	return dnssec.ValidationResult{Status: dnssec.StatusIndeterminate, Reason: dnssec.ReasonNoTrustAnchor}
}

func upstreamAt(t *testing.T, addr string) observe.Exchanger {
	t.Helper()
	u, err := resolver.ParseUpstream("udp://"+addr, 2*time.Second)
	if err != nil {
		t.Fatalf("ParseUpstream: %v", err)
	}
	t.Cleanup(u.Close)
	return u
}

// TestQueryLoggingOffWithholdsTheObservationRow is a privacy defect this
// milestone introduced and a hostile review of the seam found.
//
// An observation row names the queried domain. An operator switches the query
// log off for exactly one reason — they do not want a record of which names
// were asked for — and a validator they enabled to measure DNSSEC must not
// quietly reinstate that record under a different table name.
//
// The verdict is still counted, because the counters and metrics are aggregate
// and name nothing. What is withheld is the row.
func TestQueryLoggingOffWithholdsTheObservationRow(t *testing.T) {
	obs := &recordingObserver{accept: true}
	// The instance-wide query-log switch off, which is the operator's privacy
	// setting.
	h := newHarnessWithQueryLog(t, nil, false, withObserver(obs))

	h.handler.Handle(context.Background(), query("private.example.", dns.TypeA), requestMeta{proto: "udp"})

	seen := obs.seen()
	if len(seen) != 1 {
		t.Fatalf("observed %d queries, want 1: the verdict should still be counted", len(seen))
	}
	if seen[0].Store {
		t.Fatal("a query the operator asked not to log would have had its domain written to the observations table")
	}

	// And with logging on, the row is permitted — or the check above passes
	// because nothing is ever stored.
	on := newHarnessWithQueryLog(t, nil, true, withObserver(obs))
	on.handler.Handle(context.Background(), query("logged.example.", dns.TypeA), requestMeta{proto: "udp"})
	seen = obs.seen()
	if len(seen) != 2 {
		t.Fatalf("observed %d queries, want 2", len(seen))
	}
	if !seen[1].Store {
		t.Fatal("query logging is on and the observation row is still withheld")
	}
}

// cachingHarnessAgainstUpstream is newHarnessWithQueryLog with the resolver
// cache on and pointed at an upstream the test can watch, which is the
// combination the cache properties below need: without the counter there is no
// way to tell a served cache entry from a silently repeated upstream query.
func cachingHarnessAgainstUpstream(t *testing.T, addr string, opts ...func(*HandlerOptions)) *testHarness {
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
	}, config.Cache{Enabled: true, MaxEntries: 100, MinTTL: 1, MaxTTL: 60, NegativeTTL: 10}, log)
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
		handler: NewHandler(engine, resolution.NewForward(res, nil), holder, qlog, log, ho),
		store:   st, engine: engine, qlog: qlog,
	}
}

// TestAVerdictCannotPoisonOrEvictTheResolverCache.
//
// Observe mode's whole safety argument is that a verdict is a row in a table.
// The cache is where that argument is easiest to break by accident, and in the
// most damaging direction: an implementation that "helpfully" dropped a cache
// entry on Bogus would hand any attacker who can make validation fail — a
// truncated response, a slow signer, a zone mid-rollover — a way to force
// every subsequent query for that name back to the upstream. That is a
// behaviour change caused by a verdict, which is the one thing this milestone
// forbids, and it is also a request amplifier.
//
// So: ask twice, with each verdict in turn, and require both the cached answer
// and the number of questions that left the process to match a run with no
// observer attached at all.
func TestAVerdictCannotPoisonOrEvictTheResolverCache(t *testing.T) {
	// One request, copied: two separately built queries differ in their random
	// message id, and the response echoes it.
	req := query("example.com.", dns.TypeA)

	ask := func(t *testing.T, verdict string) (second []byte, ttl uint32, upstreamQuestions int) {
		t.Helper()

		var (
			mu   sync.Mutex
			seen []*dns.Msg
		)
		addr := recordingUpstream(t, &mu, &seen)

		opts := []func(*HandlerOptions){}
		if verdict != "" {
			o := observe.New(verdictValidator(verdict), nil,
				observe.Options{Workers: 1, Timeout: 50 * time.Millisecond})
			ctx, cancel := context.WithCancel(context.Background())
			go o.Run(ctx)
			t.Cleanup(func() { cancel(); o.Wait() })
			opts = append(opts, withObserver(o))
		}

		h := cachingHarnessAgainstUpstream(t, addr, opts...)

		h.handler.Handle(context.Background(), req.Copy(), requestMeta{proto: "udp"})
		resp := h.handler.Handle(context.Background(), req.Copy(), requestMeta{proto: "udp"})
		if resp == nil || len(resp.Answer) == 0 {
			t.Fatal("the second query produced no answer record")
		}

		// The remaining TTL of a cached entry counts down in real time, so it
		// is checked as a number below rather than compared as bytes — which
		// would fail whenever a run straddled a second boundary and would say
		// nothing about verdicts. Everything else, flags included, is compared
		// exactly.
		got := resp.Copy()
		ttl = got.Answer[0].Header().Ttl
		for _, rr := range append(append([]dns.RR{}, got.Answer...), got.Ns...) {
			rr.Header().Ttl = 0
		}

		mu.Lock()
		defer mu.Unlock()
		return answerBytes(t, got), ttl, len(seen)
	}

	wantBytes, wantTTL, wantQuestions := ask(t, "")
	if wantQuestions != 1 {
		t.Fatalf("the baseline sent %d questions upstream for two identical queries; "+
			"without a cache hit here this test proves nothing", wantQuestions)
	}

	for _, verdict := range []string{"secure", "insecure", "bogus", "indeterminate", "timeout", "panic"} {
		t.Run(verdict, func(t *testing.T) {
			got, ttl, questions := ask(t, verdict)
			if questions != wantQuestions {
				t.Errorf("a %s verdict sent %d questions upstream, want %d: the cache entry did not survive it",
					verdict, questions, wantQuestions)
			}
			if string(got) != string(wantBytes) {
				t.Errorf("a %s verdict changed the answer served from cache", verdict)
			}
			if ttl+1 < wantTTL || ttl > wantTTL+1 {
				t.Errorf("a %s verdict changed the cached TTL: %d, want about %d", verdict, ttl, wantTTL)
			}
		})
	}
}
