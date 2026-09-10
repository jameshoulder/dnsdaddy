package observe_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
)

// fakeResolver stands in for a Daddybound that fetches what it validates. A
// fake here rather than the real engine because these tests are about what the
// observer does with an outcome, not about resolution — the real engine is
// exercised end to end in internal/daddybound/native.
type fakeResolver struct {
	out observe.Outcome
	// block, when set, stalls until the context is done.
	block bool
	// panicNow makes it panic, to test the containment boundary.
	panicNow bool

	mu    sync.Mutex
	calls int
}

func (f *fakeResolver) ResolveAndValidate(ctx context.Context, qname string, rrtype uint16) observe.Outcome {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.panicNow {
		panic("resolution exploded")
	}
	if f.block {
		<-ctx.Done()
	}
	return f.out
}

func (f *fakeResolver) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// runNative starts a native observer and returns it with its sink.
func runNative(t *testing.T, r observe.Resolver, o observe.Options) (*observe.Observer, *collector) {
	t.Helper()
	o.Log = quietLog()
	sink := &collector{}
	obs := observe.NewNative(r, sink, o)
	ctx, cancel := context.WithCancel(context.Background())
	go obs.Run(ctx)
	t.Cleanup(func() {
		cancel()
		obs.Wait()
	})
	return obs, sink
}

// oneNative drives a single request through a native observer and returns the
// row it produced.
func oneNative(t *testing.T, r observe.Resolver) observe.Observation {
	t.Helper()
	obs, sink := runNative(t, r, observe.Options{Workers: 1, Queue: 4, Timeout: time.Second})
	if !obs.Observe(request("www.example.com.")) {
		t.Fatal("the observation was dropped by an empty queue")
	}
	if !waitFor(t, 5*time.Second, func() bool { return len(sink.all()) == 1 }) {
		t.Fatalf("no observation was recorded within the deadline")
	}
	return sink.all()[0]
}

// Learn mode drives the resolver, and the row says so.
//
// A Secure reached through somebody else's recursive resolver and a Secure
// reached by asking the authoritative servers are different claims. A dataset
// that mixed them without saying which was which could not be read at all, and
// an operator judging readiness for Live needs to know the evidence came from
// the code path Live would run.
func TestLearnRecordsThatTheVerdictCameFromNativeResolution(t *testing.T) {
	r := &fakeResolver{out: observe.Outcome{
		Result:      dnssec.ValidationResult{Status: dnssec.StatusSecure, Reason: dnssec.ReasonVerified},
		Queries:     9,
		Delegations: 2,
		Lookups:     6,
	}}
	got := oneNative(t, r)

	if got.Status != observe.StatusSecure {
		t.Errorf("status = %s, want secure", got.Status)
	}
	if got.Resolution != observe.ResolutionNative {
		t.Errorf("resolution = %q, want %q", got.Resolution, observe.ResolutionNative)
	}
	if got.Queries != 9 || got.Delegations != 2 || got.Lookups != 6 {
		t.Errorf("cost recorded as queries=%d delegations=%d lookups=%d, want 9/2/6",
			got.Queries, got.Delegations, got.Lookups)
	}
	if r.count() != 1 {
		t.Errorf("the resolver was called %d times for one query", r.count())
	}
}

// A failure to obtain records must never be recorded as a fact about them.
//
// This is the single most abusable confusion in a validating resolver. An
// attacker who can drop packets can cause any resolution to fail; if that were
// recorded as Bogus they could condemn any zone in the operator's report, and if
// it were recorded as Insecure they could downgrade one. So every failure class
// is operational, and the table below is the whole set.
func TestAFailedResolutionIsNeverASecurityState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure observe.Status
		code    string
	}{
		{"no authoritative server answered", observe.StatusUnreachable, "no_authoritative_server"},
		{"the deadline expired", observe.StatusTimeout, "resolution_deadline"},
		{"a resolver bound was reached", observe.StatusResourceLimit, "resolution_limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeResolver{out: observe.Outcome{
				Failure:       tc.failure,
				FailureCode:   tc.code,
				FailureReason: tc.name,
				// A verdict left in the outcome alongside the failure, as a
				// careless implementation would. It must not be promoted.
				Result: dnssec.ValidationResult{Status: dnssec.StatusBogus, Reason: dnssec.ReasonVerified},
			}}
			got := oneNative(t, r)

			if got.Status.IsSecurityState() {
				t.Fatalf("a failed resolution was recorded as %s, one of RFC 4033's four states", got.Status)
			}
			if got.Status != tc.failure {
				t.Errorf("status = %s, want %s", got.Status, tc.failure)
			}
			if got.ReasonCode != tc.code {
				t.Errorf("reason code = %q, want %q", got.ReasonCode, tc.code)
			}
		})
	}
}

// An implementation that classified its own failure as a security state must
// not be believed.
//
// The observer is the last thing between a mistake like that and the operator's
// evidence, and it costs one comparison. Without the guard the row below would
// read "secure" for a resolution that never happened.
func TestAMisclassifiedFailureIsRefusedRatherThanRecorded(t *testing.T) {
	r := &fakeResolver{out: observe.Outcome{
		Failure:       observe.StatusSecure,
		FailureCode:   "wrong",
		FailureReason: "an implementation that got its own taxonomy wrong",
	}}
	got := oneNative(t, r)

	if got.Status == observe.StatusSecure {
		t.Fatal("a failure claiming to be Secure was recorded as Secure")
	}
	if got.Status != observe.StatusInternalError {
		t.Errorf("status = %s, want internal_error", got.Status)
	}
}

// A panic inside resolution is contained and counted, not fatal.
//
// This runs on a background worker inside the DNS server process, where an
// unrecovered panic takes down every client's DNS rather than one observation.
// The counter is exposed so it reads as a bug report rather than being absorbed.
func TestAPanicDuringNativeResolutionIsContained(t *testing.T) {
	r := &fakeResolver{panicNow: true}
	got := oneNative(t, r)

	if got.Status != observe.StatusInternalError {
		t.Errorf("status = %s, want internal_error", got.Status)
	}
	if got.Status.IsSecurityState() {
		t.Error("a panic produced a DNSSEC verdict")
	}
}

// The answer path must not wait for resolution, however slow it is.
//
// Native recursion is slower than the forwarding path it replaced — several
// round trips in series rather than one — so this property matters more now
// than it did, not less. Observe is a non-blocking send and nothing else.
func TestObserveNeverWaitsForNativeResolution(t *testing.T) {
	r := &fakeResolver{block: true}
	obs, _ := runNative(t, r, observe.Options{Workers: 1, Queue: 2, Timeout: time.Minute})

	// Fill the queue and then some. Every call must return promptly whether
	// it was accepted or dropped; a blocked worker must never become a
	// blocked client.
	start := time.Now()
	accepted, dropped := 0, 0
	for i := 0; i < 50; i++ {
		if obs.Observe(request("www.example.com.")) {
			accepted++
		} else {
			dropped++
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("50 non-blocking sends took %s; the answer path waited on resolution", elapsed)
	}
	if dropped == 0 {
		t.Fatalf("nothing was dropped with a queue of 2 and a stalled worker (%d accepted); "+
			"this test did not exercise a full queue", accepted)
	}
	if s := obs.Stats(); s.Dropped != uint64(dropped) {
		t.Errorf("Stats().Dropped = %d, want %d — a dropped observation must be visible, "+
			"or a reader draws conclusions the sample cannot support", s.Dropped, dropped)
	}
}

// The aggregate counters say what Learn cost.
//
// Learn sends real DNS traffic a deployment would not otherwise send, and an
// operator deciding whether to leave it on is entitled to see how much.
func TestLearnReportsWhatItCostUpstream(t *testing.T) {
	r := &fakeResolver{out: observe.Outcome{
		Result:      dnssec.ValidationResult{Status: dnssec.StatusSecure, Reason: dnssec.ReasonVerified},
		Queries:     7,
		Delegations: 3,
	}}
	obs, sink := runNative(t, r, observe.Options{Workers: 1, Queue: 8, Timeout: time.Second})

	const n = 3
	for i := 0; i < n; i++ {
		if !obs.Observe(request("www.example.com.")) {
			t.Fatal("dropped")
		}
	}
	if !waitFor(t, 5*time.Second, func() bool { return len(sink.all()) == n }) {
		t.Fatalf("only %d of %d observations were recorded", len(sink.all()), n)
	}

	s := obs.Stats()
	if s.Resolution != observe.ResolutionNative {
		t.Errorf("Stats().Resolution = %q, want %q", s.Resolution, observe.ResolutionNative)
	}
	if s.Queries != uint64(n*7) {
		t.Errorf("Stats().Queries = %d, want %d", s.Queries, n*7)
	}
	if s.Delegations != uint64(n*3) {
		t.Errorf("Stats().Delegations = %d, want %d", s.Delegations, n*3)
	}
}

// A forwarding observer still says so, and reports no native cost.
func TestAForwardingObserverIsLabelledAsOne(t *testing.T) {
	v := validatorFunc(func(context.Context, string, uint16) dnssec.ValidationResult {
		return dnssec.ValidationResult{Status: dnssec.StatusInsecure, Reason: dnssec.ReasonDenialOptOutSpan}
	})
	sink := &collector{}
	obs := run(t, v, sink, observe.Options{Workers: 1, Queue: 4, Timeout: time.Second})
	if !obs.Observe(request("www.example.com.")) {
		t.Fatal("dropped")
	}
	if !waitFor(t, 5*time.Second, func() bool { return len(sink.all()) == 1 }) {
		t.Fatal("no observation was recorded")
	}

	got := sink.all()[0]
	if got.Resolution != observe.ResolutionForwarded {
		t.Errorf("resolution = %q, want %q", got.Resolution, observe.ResolutionForwarded)
	}
	if got.Queries != 0 || got.Delegations != 0 {
		t.Errorf("a forwarded verdict reported native cost: queries=%d delegations=%d",
			got.Queries, got.Delegations)
	}
}

type validatorFunc func(context.Context, string, uint16) dnssec.ValidationResult

func (f validatorFunc) Validate(ctx context.Context, n string, t uint16) dnssec.ValidationResult {
	return f(ctx, n, t)
}
