package apiprovider

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeProvider is a reputation provider whose latency and answer the test
// controls. Real adapters are tested against httptest in the adapters package;
// what the engine needs is something that can be made slow on demand.
type fakeProvider struct {
	verdict Verdict
	err     error
	delay   time.Duration
	calls   atomic.Int32
	// block, when non-nil, holds the call until it is closed.
	block chan struct{}
}

func (f *fakeProvider) Descriptor() Descriptor {
	return Descriptor{Kind: "fake", DisplayName: "Fake", PrivacyNote: "none"}
}

func (f *fakeProvider) Reputation(ctx context.Context, _ Subject) (Verdict, error) {
	f.calls.Add(1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return Verdict{}, ctx.Err()
		}
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return Verdict{}, ctx.Err()
		}
	}
	return f.verdict, f.err
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func engineWith(t *testing.T, o Options, providers ...*Instance) *Engine {
	t.Helper()
	if o.Log == nil {
		o.Log = quietLog()
	}
	e := NewEngine(o)
	e.SetInstances(providers)
	e.Start(context.Background())
	t.Cleanup(e.Stop)
	return e
}

func fakeInstance(id string, p Provider, caps ...Capability) *Instance {
	if len(caps) == 0 {
		caps = []Capability{CapReputation}
	}
	return &Instance{
		ID: id, Name: id, Kind: "fake",
		Provider: p, Capabilities: caps, CacheTTL: time.Hour,
	}
}

// ---------------------------------------------------------------------------
// The property everything else is subordinate to
// ---------------------------------------------------------------------------

// The default configuration must do no work at all on the resolution path.
// Not "a little work" — none. A deployment that never opens the Integrations
// page pays one atomic load per query.
func TestModeOffTouchesNothing(t *testing.T) {
	p := &fakeProvider{verdict: Verdict{Disposition: DispositionMalicious, Score: 1}}
	e := engineWith(t, Options{Mode: ModeOff}, fakeInstance("apr_1", p))

	for i := 0; i < 1000; i++ {
		v, ok := e.Consult(context.Background(), "pol_1", "evil.example")
		if ok {
			t.Fatal("mode off returned a verdict")
		}
		if v.Disposition != DispositionUnknown {
			t.Fatalf("mode off returned disposition %s", v.Disposition)
		}
	}

	if n := p.calls.Load(); n != 0 {
		t.Errorf("mode off called the provider %d times", n)
	}
	s := e.Stats()
	if s.Enqueued != 0 {
		t.Errorf("mode off enqueued %d lookups", s.Enqueued)
	}
	if s.CacheHits+s.CacheMisses != 0 {
		t.Errorf("mode off touched the cache %d times", s.CacheHits+s.CacheMisses)
	}
}

// Cache-only must never wait, whatever the provider is doing. This is the
// mode an operator picks when they want live intelligence and are not willing
// to put a third party's latency in front of their DNS.
func TestCacheOnlyNeverWaitsOnAHungProvider(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)

	p := &fakeProvider{
		verdict: Verdict{Disposition: DispositionMalicious, Score: 1},
		block:   blocked, // never answers while the test runs
	}
	e := engineWith(t, Options{Mode: ModeCacheOnly, Workers: 1}, fakeInstance("apr_1", p))

	start := time.Now()
	for i := 0; i < 100; i++ {
		if _, ok := e.Consult(context.Background(), "pol_1", "evil.example"); ok {
			t.Fatal("cache-only returned a verdict from a provider that has not answered")
		}
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Errorf("100 cache-only lookups against a hung provider took %s", elapsed)
	}
}

// Blocking mode is bounded by the budget. The budget is a ceiling, not a
// target, and there must be no path through Consult that exceeds it.
func TestBlockingModeRespectsItsBudget(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)

	p := &fakeProvider{verdict: Verdict{Disposition: DispositionMalicious}, block: blocked}
	e := engineWith(t, Options{
		Mode: ModeBlocking, Budget: 40 * time.Millisecond, Workers: 2,
	}, fakeInstance("apr_1", p))

	for i := 0; i < 5; i++ {
		start := time.Now()
		v, ok := e.Consult(context.Background(), "pol_1", "evil.example")
		elapsed := time.Since(start)

		if elapsed > 400*time.Millisecond {
			t.Fatalf("a 40ms budget took %s", elapsed)
		}
		// And it fails open. A provider that has not answered has not said
		// the domain is bad.
		if ok || v.Disposition != DispositionUnknown {
			t.Errorf("a timed-out lookup returned (%v, %v), want unknown and false", v.Disposition, ok)
		}
	}
}

// The whole point of blocking mode: when the provider is quick, its answer is
// used. A mode that never returns a verdict would be indistinguishable from
// cache-only.
func TestBlockingModeUsesAFastAnswer(t *testing.T) {
	p := &fakeProvider{
		verdict: Verdict{Disposition: DispositionMalicious, Score: 0.95},
		delay:   time.Millisecond,
	}
	e := engineWith(t, Options{
		Mode: ModeBlocking, Budget: 2 * time.Second, Workers: 2,
	}, fakeInstance("apr_1", p))

	v, ok := e.Consult(context.Background(), "pol_1", "evil.example")
	if !ok {
		t.Fatal("a fast provider's answer was not used")
	}
	if v.Disposition != DispositionMalicious {
		t.Errorf("disposition = %s, want malicious", v.Disposition)
	}
}

// A timed-out lookup keeps running and warms the cache, so the answer is there
// for the next query. Without this, blocking mode against a provider slower
// than the budget would never populate anything and would be permanently
// useless.
func TestATimedOutLookupStillWarmsTheCache(t *testing.T) {
	p := &fakeProvider{
		verdict: Verdict{Disposition: DispositionMalicious, Score: 1},
		delay:   60 * time.Millisecond,
	}
	e := engineWith(t, Options{
		Mode: ModeBlocking, Budget: 5 * time.Millisecond, Workers: 2,
	}, fakeInstance("apr_1", p))

	// First query times out.
	if _, ok := e.Consult(context.Background(), "pol_1", "evil.example"); ok {
		t.Fatal("the first lookup should have exceeded its budget")
	}

	// The lookup finished in the background.
	waitFor(t, time.Second, func() bool {
		_, ok := e.cache.Get("evil.example", "apr_1", time.Now())
		return ok
	})

	v, ok := e.Consult(context.Background(), "pol_1", "evil.example")
	if !ok || v.Disposition != DispositionMalicious {
		t.Errorf("the warmed cache was not used: (%v, %v)", v.Disposition, ok)
	}
}

// A worker that answers after the caller gave up must not block forever
// writing to a channel nobody is reading. That leak costs one worker per
// timed-out query, and with two workers a busy resolver loses the pool in
// seconds.
func TestSlowAnswersDoNotLeakWorkers(t *testing.T) {
	release := make(chan struct{})
	p := &fakeProvider{verdict: Verdict{Disposition: DispositionBenign}, block: release}

	e := engineWith(t, Options{
		Mode: ModeBlocking, Budget: time.Millisecond, Workers: 2, QueueSize: 256,
	}, fakeInstance("apr_1", p))

	// Twenty queries, each timing out, each leaving a worker mid-call.
	for i := 0; i < 20; i++ {
		e.Consult(context.Background(), "pol_1", "evil.example")
	}
	// Let them all answer into channels nobody is reading.
	close(release)

	// If the workers were leaking, they would be blocked on those sends and
	// this would never complete.
	waitFor(t, 5*time.Second, func() bool {
		return e.Stats().Completed >= 1
	})

	// And the pool still works.
	p2 := &fakeProvider{verdict: Verdict{Disposition: DispositionMalicious, Score: 1}}
	e.SetInstances([]*Instance{fakeInstance("apr_2", p2)})
	waitFor(t, 5*time.Second, func() bool {
		e.Consult(context.Background(), "pol_1", "later.example")
		_, ok := e.cache.Get("later.example", "apr_2", time.Now())
		return ok
	})
}

// A full queue must drop and count, never block. A blocking send here would
// put the queue's depth into the DNS path.
func TestAFullQueueDropsRatherThanBlocking(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)

	p := &fakeProvider{block: blocked}
	e := engineWith(t, Options{
		Mode: ModeCacheOnly, Workers: 1, QueueSize: 4,
	}, fakeInstance("apr_1", p))

	start := time.Now()
	for i := 0; i < 500; i++ {
		e.Consult(context.Background(), "pol_1", uniqueDomain(i))
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("500 lookups against a queue of 4 took %s — the send blocks", elapsed)
	}

	s := e.Stats()
	if s.Dropped == 0 {
		t.Error("a saturated queue dropped nothing, so either the queue grew or the count is wrong")
	}
	if s.Enqueued+s.Dropped < 500 {
		t.Errorf("enqueued %d + dropped %d, want at least 500 accounted for", s.Enqueued, s.Dropped)
	}
}

// ---------------------------------------------------------------------------
// Correctness of the answer
// ---------------------------------------------------------------------------

func TestUnknownNeverBlocks(t *testing.T) {
	for _, v := range []Verdict{
		{Disposition: DispositionUnknown},
		{Disposition: DispositionUnknown, Score: 0.99}, // a score without a judgement
	} {
		p := &fakeProvider{verdict: v}
		e := engineWith(t, Options{Mode: ModeBlocking, Budget: time.Second, Workers: 2},
			fakeInstance("apr_1", p))

		got, ok := e.Consult(context.Background(), "pol_1", "x.example")
		if ok && got.Disposition == DispositionMalicious {
			t.Errorf("an unknown verdict produced a blocking answer: %+v", got)
		}
	}
}

// A provider that errors is a provider with nothing to say, not a provider
// saying the domain is bad.
func TestAFailingProviderProducesUnknown(t *testing.T) {
	p := &fakeProvider{err: ErrUnauthorised}
	e := engineWith(t, Options{Mode: ModeBlocking, Budget: time.Second, Workers: 2},
		fakeInstance("apr_1", p))

	v, ok := e.Consult(context.Background(), "pol_1", "x.example")
	if ok {
		t.Errorf("a failing provider produced a verdict: %+v", v)
	}
	if v.Disposition != DispositionUnknown {
		t.Errorf("disposition = %s, want unknown", v.Disposition)
	}
}

// A provider scoped to one policy must not be consulted for another. This is
// how a guest VLAN gets live reputation while a finance VLAN does not, and a
// scope that leaks is a privacy commitment that is not kept.
func TestPolicyScopeIsHonoured(t *testing.T) {
	p := &fakeProvider{verdict: Verdict{Disposition: DispositionMalicious, Score: 1}}
	inst := fakeInstance("apr_1", p)
	inst.PolicyScope = []string{"pol_guest"}

	e := engineWith(t, Options{Mode: ModeBlocking, Budget: 200 * time.Millisecond, Workers: 2}, inst)

	if _, ok := e.Consult(context.Background(), "pol_finance", "evil.example"); ok {
		t.Error("an out-of-scope policy got a verdict from a scoped provider")
	}
	if n := p.calls.Load(); n != 0 {
		t.Errorf("a scoped provider was called %d times for an out-of-scope policy", n)
	}

	if _, ok := e.Consult(context.Background(), "pol_guest", "evil.example"); !ok {
		t.Error("the in-scope policy got no verdict")
	}
}

// A capability the operator did not enable must not be exercised, even when
// the adapter implements it. Enabling a provider and letting it influence
// resolution are separate decisions.
func TestADisabledCapabilityIsNotUsed(t *testing.T) {
	p := &fakeProvider{verdict: Verdict{Disposition: DispositionMalicious, Score: 1}}
	inst := fakeInstance("apr_1", p, CapEnrichment) // reputation NOT enabled

	e := engineWith(t, Options{Mode: ModeBlocking, Budget: 200 * time.Millisecond, Workers: 2}, inst)

	if _, ok := e.Consult(context.Background(), "pol_1", "evil.example"); ok {
		t.Error("a provider with reputation disabled produced a verdict")
	}
	if n := p.calls.Load(); n != 0 {
		t.Errorf("a provider with reputation disabled was called %d times", n)
	}
}

// A cached malicious verdict short-circuits: nothing a second provider could
// say improves on it, and waiting is latency spent to change nothing.
func TestACachedMaliciousVerdictShortCircuits(t *testing.T) {
	slow := &fakeProvider{verdict: Verdict{Disposition: DispositionBenign}, delay: time.Hour}
	fast := &fakeProvider{verdict: Verdict{Disposition: DispositionMalicious, Score: 1}}

	e := engineWith(t, Options{Mode: ModeBlocking, Budget: 5 * time.Second, Workers: 2},
		fakeInstance("apr_fast", fast), fakeInstance("apr_slow", slow))

	// Prime the fast provider's answer.
	e.cache.Put("evil.example", CachedVerdict{
		Verdict:    Verdict{Disposition: DispositionMalicious, Score: 1},
		ProviderID: "apr_fast",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	start := time.Now()
	v, ok := e.Consult(context.Background(), "pol_1", "evil.example")
	elapsed := time.Since(start)

	if !ok || v.Disposition != DispositionMalicious {
		t.Fatalf("got (%v, %v), want a malicious verdict", v.Disposition, ok)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("a cached malicious verdict waited %s for a second opinion", elapsed)
	}
}

func TestDeletingAProviderForgetsItsCachedAnswers(t *testing.T) {
	p := &fakeProvider{verdict: Verdict{Disposition: DispositionMalicious, Score: 1}}
	e := engineWith(t, Options{Mode: ModeCacheOnly}, fakeInstance("apr_1", p))

	e.cache.Put("evil.example", CachedVerdict{
		Verdict:    Verdict{Disposition: DispositionMalicious},
		ProviderID: "apr_1",
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if _, ok := e.cache.Get("evil.example", "apr_1", time.Now()); !ok {
		t.Fatal("the cache was not primed")
	}

	e.SetInstances(nil) // provider deleted

	if _, ok := e.cache.Get("evil.example", "apr_1", time.Now()); ok {
		t.Error("a deleted provider's cached verdict survived — an answer with no traceable source")
	}
}

func TestConsultIsSafeUnderConcurrency(t *testing.T) {
	p := &fakeProvider{verdict: Verdict{Disposition: DispositionBenign}, delay: time.Millisecond}
	e := engineWith(t, Options{
		Mode: ModeBlocking, Budget: 20 * time.Millisecond, Workers: 4, QueueSize: 512,
	}, fakeInstance("apr_1", p))

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				e.Consult(context.Background(), "pol_1", uniqueDomain(n*100+j))
				_ = e.Stats()
			}
		}(i)
	}
	// Reconfiguration racing lookups is the realistic case: an operator saves
	// a provider while the resolver is serving.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			e.SetInstances([]*Instance{fakeInstance("apr_1", p)})
			time.Sleep(time.Millisecond)
		}
	}()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

func TestCacheExpiresEntries(t *testing.T) {
	c := NewMemoryCache(64)
	now := time.Now()
	c.Put("a.example", CachedVerdict{ProviderID: "p1", ExpiresAt: now.Add(time.Minute)})

	if _, ok := c.Get("a.example", "p1", now); !ok {
		t.Error("a fresh entry was not returned")
	}
	if _, ok := c.Get("a.example", "p1", now.Add(2*time.Minute)); ok {
		t.Error("an expired entry was returned")
	}
}

func TestCacheKeepsProvidersApart(t *testing.T) {
	// Two providers disagreeing about one domain is normal, and both answers
	// are worth keeping.
	c := NewMemoryCache(64)
	now := time.Now()
	c.Put("x.example", CachedVerdict{ProviderID: "p1", ExpiresAt: now.Add(time.Hour),
		Verdict: Verdict{Disposition: DispositionMalicious}})
	c.Put("x.example", CachedVerdict{ProviderID: "p2", ExpiresAt: now.Add(time.Hour),
		Verdict: Verdict{Disposition: DispositionBenign}})

	a, _ := c.Get("x.example", "p1", now)
	b, _ := c.Get("x.example", "p2", now)
	if a.Verdict.Disposition != DispositionMalicious || b.Verdict.Disposition != DispositionBenign {
		t.Errorf("providers were conflated: p1=%v p2=%v", a.Verdict.Disposition, b.Verdict.Disposition)
	}
}

// An unbounded cache keyed on domain names grows at the rate the network
// resolves new names: a slow leak that looks fine for a week.
func TestCacheIsBounded(t *testing.T) {
	const max = 256
	c := NewMemoryCache(max)
	now := time.Now()

	for i := 0; i < 20000; i++ {
		c.Put(uniqueDomain(i), CachedVerdict{ProviderID: "p1", ExpiresAt: now.Add(time.Hour)})
	}
	// Sharding means the bound is approximate; what matters is that it is a
	// bound at all rather than 20,000 entries.
	if n := c.Len(); n > max*2 {
		t.Errorf("cache holds %d entries for a limit of %d", n, max)
	}
}

func TestCacheForgetsOneProviderOnly(t *testing.T) {
	c := NewMemoryCache(256)
	now := time.Now()
	c.Put("a.example", CachedVerdict{ProviderID: "p1", ExpiresAt: now.Add(time.Hour)})
	c.Put("a.example", CachedVerdict{ProviderID: "p2", ExpiresAt: now.Add(time.Hour)})

	c.Forget("p1")

	if _, ok := c.Get("a.example", "p1", now); ok {
		t.Error("Forget left the target provider's entry")
	}
	if _, ok := c.Get("a.example", "p2", now); !ok {
		t.Error("Forget removed another provider's entry")
	}
}

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

func TestParseReputationModeDefaultsToOff(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want ReputationMode
	}{
		{"off", ModeOff},
		{"cache_only", ModeCacheOnly},
		{"blocking", ModeBlocking},
		{"", ModeOff},
		{"nonsense", ModeOff},
		// The typo an operator would actually make. It must not fall through
		// to something that puts a network call in the resolution path.
		{"blockingg", ModeOff},
		{"BLOCKING", ModeOff},
	} {
		if got := ParseReputationMode(tc.in); got != tc.want {
			t.Errorf("ParseReputationMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func uniqueDomain(i int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	var b [8]byte
	for j := range b {
		b[j] = alphabet[(i/(j+1))%26]
	}
	return string(b[:]) + ".example"
}

func waitFor(t *testing.T, limit time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", limit)
}
