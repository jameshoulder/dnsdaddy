package observe_test

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
)

// stubValidator does whatever a test needs, including things a real validator
// will not do on demand.
type stubValidator struct {
	result dnssec.ValidationResult
	block  time.Duration
	panics bool
	calls  int64
	mu     sync.Mutex
}

func (s *stubValidator) Validate(ctx context.Context, qname string, rrtype uint16) dnssec.ValidationResult {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.panics {
		panic("deliberate validator panic")
	}
	if s.block > 0 {
		select {
		case <-time.After(s.block):
		case <-ctx.Done():
			return dnssec.ValidationResult{
				Status: dnssec.StatusIndeterminate,
				Reason: dnssec.ReasonCancelled,
			}
		}
	}
	return s.result
}

type collector struct {
	mu   sync.Mutex
	rows []observe.Observation
}

func (c *collector) Record(o observe.Observation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows = append(c.rows, o)
}

func (c *collector) all() []observe.Observation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]observe.Observation(nil), c.rows...)
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// waitFor polls until cond holds or the deadline passes.
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

func run(t *testing.T, v observe.Validator, sink observe.Sink, o observe.Options) *observe.Observer {
	t.Helper()
	o.Log = quietLog()
	obs := observe.New(v, sink, o)
	ctx, cancel := context.WithCancel(context.Background())
	go obs.Run(ctx)
	t.Cleanup(func() {
		cancel()
		obs.Wait()
	})
	return obs
}

func request(name string) observe.Request {
	return observe.Request{
		ID: observe.NewID(), Domain: strings.TrimSuffix(name, "."),
		QName: name, QType: dns.TypeA, UpstreamStatus: "validated",
		// Store is what the handler sets from the operator's query-log
		// decision. Most tests here want the sink to see the row.
		Store: true,
	}
}

// TestEachVerdictIsRecordedAsItself walks the four RFC 4033 states through the
// observer and checks none is quietly folded into another.
func TestEachVerdictIsRecordedAsItself(t *testing.T) {
	for _, tc := range []struct {
		engine dnssec.ValidationStatus
		reason dnssec.Reason
		want   observe.Status
	}{
		{dnssec.StatusSecure, dnssec.ReasonVerified, observe.StatusSecure},
		{dnssec.StatusInsecure, dnssec.ReasonVerified, observe.StatusInsecure},
		{dnssec.StatusBogus, dnssec.ReasonSignatureCryptoFailed, observe.StatusBogus},
		{dnssec.StatusIndeterminate, dnssec.ReasonNoTrustAnchor, observe.StatusIndeterminate},
	} {
		t.Run(string(tc.want), func(t *testing.T) {
			sink := &collector{}
			v := &stubValidator{result: dnssec.ValidationResult{Status: tc.engine, Reason: tc.reason}}
			o := run(t, v, sink, observe.Options{Workers: 1})

			if !o.Observe(request("example.test.")) {
				t.Fatal("the request was dropped")
			}
			if !waitFor(t, 2*time.Second, func() bool { return len(sink.all()) == 1 }) {
				t.Fatal("no observation was recorded")
			}
			got := sink.all()[0]
			if got.Status != tc.want {
				t.Fatalf("status = %q, want %q", got.Status, tc.want)
			}
			if got.ReasonCode != string(tc.reason) {
				t.Errorf("reason code = %q, want %q", got.ReasonCode, tc.reason)
			}
		})
	}
}

// TestAnInabilityToValidateIsNotADNSSECState is ADR 0002 §8.
//
// A timeout and a resource limit are statements about the validator. Recording
// either as Insecure would let anyone who can drop packets or inflate a proof
// manufacture a DNSSEC state — which is the cheapest possible downgrade
// attack, needing no forgery at all.
func TestAnInabilityToValidateIsNotADNSSECState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason dnssec.Reason
		want   observe.Status
	}{
		{"deadline", dnssec.ReasonCancelled, observe.StatusTimeout},
		{"bound", dnssec.ReasonResourceLimit, observe.StatusResourceLimit},
		{"algorithm", dnssec.ReasonUnsupportedAlgorithm, observe.StatusUnsupported},
		{"digest", dnssec.ReasonUnsupportedDigest, observe.StatusUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &collector{}
			// The engine reports these as Indeterminate. The observer must
			// separate them out by reason, not repeat the engine's status.
			v := &stubValidator{result: dnssec.ValidationResult{
				Status: dnssec.StatusIndeterminate, Reason: tc.reason,
			}}
			o := run(t, v, sink, observe.Options{Workers: 1})
			o.Observe(request("example.test."))

			if !waitFor(t, 2*time.Second, func() bool { return len(sink.all()) == 1 }) {
				t.Fatal("no observation was recorded")
			}
			got := sink.all()[0].Status
			if got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
			if got.IsSecurityState() {
				t.Fatalf("%q was recorded as an RFC 4033 security state", got)
			}
		})
	}
}

// TestAValidatorPanicDoesNotTakeTheProcessDown is the containment boundary.
//
// Daddybound is fuzzed and written not to panic, and a panic here is a defect.
// But observation runs on a background goroutine inside the DNS server
// process, where an unrecovered panic ends every client's DNS rather than one
// observation. The recover is not an excuse for a defect; it is a bound on its
// blast radius, and the counter is what stops it being absorbed silently.
func TestAValidatorPanicDoesNotTakeTheProcessDown(t *testing.T) {
	sink := &collector{}
	v := &stubValidator{panics: true}
	o := run(t, v, sink, observe.Options{Workers: 1})

	o.Observe(request("boom.test."))
	if !waitFor(t, 2*time.Second, func() bool { return len(sink.all()) == 1 }) {
		t.Fatal("a panicking validator produced no observation; the worker probably died")
	}
	got := sink.all()[0]
	if got.Status != observe.StatusInternalError {
		t.Fatalf("status = %q, want %q", got.Status, observe.StatusInternalError)
	}
	if s := o.Stats(); s.Panics != 1 {
		t.Errorf("panics counted = %d, want 1: a panic must be visible, not absorbed", s.Panics)
	}

	// And the worker must still be alive afterwards.
	v.panics = false
	v.result = dnssec.ValidationResult{Status: dnssec.StatusSecure, Reason: dnssec.ReasonVerified}
	o.Observe(request("after.test."))
	if !waitFor(t, 2*time.Second, func() bool { return len(sink.all()) == 2 }) {
		t.Fatal("the worker did not survive the panic")
	}
}

// TestObserveNeverBlocks is the property the answer path depends on.
//
// With every worker wedged and the queue full, Observe must still return
// promptly. If it could block, a hostile zone that makes validation slow would
// add that latency to every client's answer.
func TestObserveNeverBlocks(t *testing.T) {
	v := &stubValidator{block: time.Hour}
	o := run(t, v, nil, observe.Options{Workers: 1, Queue: 2, Timeout: time.Hour})

	// Fill the worker and the queue, then keep going well past capacity.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			o.Observe(request("slow.test."))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe blocked; the answer path can be stalled by a slow validation")
	}
	if s := o.Stats(); s.Dropped == 0 {
		t.Error("nothing was dropped, so the queue bound was not exercised")
	}
}

// TestRepeatedTimeoutsDoNotLeakWork covers the denial-of-service shape the
// brief asks about: an attacker who can make validation hang.
//
// The pool and the queue are both fixed-size, so the goroutine count must be
// flat regardless of how many observations time out. A design that started a
// goroutine per observation would pass every functional test above and fail
// this one.
func TestRepeatedTimeoutsDoNotLeakWork(t *testing.T) {
	v := &stubValidator{block: time.Hour}
	o := run(t, v, nil, observe.Options{Workers: 2, Queue: 8, Timeout: 5 * time.Millisecond})

	settle := func() int {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		return runtime.NumGoroutine()
	}

	// Fed continuously rather than in a burst: the queue is deliberately
	// small, so a burst is mostly dropped and would exercise the drop path
	// instead of the timeout path this test is about.
	feed := func(until uint64, budget time.Duration) {
		t.Helper()
		deadline := time.Now().Add(budget)
		for o.Stats().Observed < until {
			if time.Now().After(deadline) {
				t.Fatalf("only %d observations completed; the deadline is not firing", o.Stats().Observed)
			}
			o.Observe(request("hang.test."))
		}
	}

	feed(50, 15*time.Second)
	before := settle()

	feed(1000, 60*time.Second)
	after := settle()

	// A small band, not equality: the test binary has its own goroutines and
	// the runtime's are not fully deterministic. A leak would be linear in the
	// two thousand requests above, so anything of that shape lands far outside.
	if after > before+8 {
		t.Fatalf("goroutines grew from %d to %d across 2000 timed-out observations", before, after)
	}
	if s := o.Stats(); s.ByStatus[observe.StatusTimeout] == 0 {
		t.Error("no observation was recorded as a timeout")
	}
}

// TestShutdownStopsTheWorkers checks Run returns when its context is
// cancelled, so a validation in flight cannot hold up process exit.
func TestShutdownStopsTheWorkers(t *testing.T) {
	v := &stubValidator{block: time.Hour}
	o := observe.New(v, nil, observe.Options{Workers: 2, Timeout: time.Hour, Log: quietLog()})
	ctx, cancel := context.WithCancel(context.Background())

	stopped := make(chan struct{})
	go func() { o.Run(ctx); close(stopped) }()

	o.Observe(request("slow.test."))
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

// TestTheDeadlineCancelsTheValidator checks the observation timeout actually
// reaches the engine rather than only being recorded around it.
func TestTheDeadlineCancelsTheValidator(t *testing.T) {
	sink := &collector{}
	v := &stubValidator{block: 10 * time.Second}
	o := run(t, v, sink, observe.Options{Workers: 1, Timeout: 20 * time.Millisecond})

	start := time.Now()
	o.Observe(request("slow.test."))
	if !waitFor(t, 3*time.Second, func() bool { return len(sink.all()) == 1 }) {
		t.Fatal("the observation never completed; the deadline did not reach the validator")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("the observation took %s, far past its 20ms deadline", elapsed)
	}
	if got := sink.all()[0].Status; got != observe.StatusTimeout {
		t.Fatalf("status = %q, want %q", got, observe.StatusTimeout)
	}
}

// TestDisagreementClassesAreClosedAndMeaningful pins the label set and the one
// combination that looks like a disagreement and is not.
func TestDisagreementClassesAreClosedAndMeaningful(t *testing.T) {
	cases := []struct {
		upstream string
		local    observe.Status
		want     string
	}{
		{"validated", observe.StatusSecure, ""},
		{"validated", observe.StatusBogus, observe.DisagreeLocalBogusUpstreamValidated},
		{"validated", observe.StatusInsecure, observe.DisagreeLocalInsecureUpstreamValidated},
		{"validated", observe.StatusIndeterminate, observe.DisagreeLocalIndeterminateUpstreamValid},
		{"unvalidated", observe.StatusSecure, observe.DisagreeLocalSecureUpstreamUnvalidated},
		{"unvalidated", observe.StatusBogus, observe.DisagreeLocalBogusUpstreamUnvalidated},

		// The combination that is not a disagreement. "unvalidated" means no
		// AD bit came back, which covers an unsigned zone and an upstream that
		// does not validate equally; local Insecure against it is the expected
		// reading of an unsigned name, not a conflict.
		{"unvalidated", observe.StatusInsecure, ""},

		// Operational outcomes are never a disagreement with anything. Filing
		// a timeout against the upstream's verdict would put network weather
		// into a security metric.
		{"validated", observe.StatusTimeout, ""},
		{"validated", observe.StatusResourceLimit, ""},
		{"unvalidated", observe.StatusInternalError, ""},
		{"servfail", observe.StatusBogus, ""},
	}
	for _, tc := range cases {
		if got := observe.DisagreementClass(tc.upstream, tc.local); got != tc.want {
			t.Errorf("DisagreementClass(%q, %q) = %q, want %q", tc.upstream, tc.local, got, tc.want)
		}
	}

	// Every class the function can return must be in the published list, or a
	// metric will sprout a series nobody declared.
	declared := map[string]bool{}
	for _, c := range observe.DisagreementClasses() {
		declared[c] = true
	}
	for _, tc := range cases {
		if tc.want != "" && !declared[tc.want] {
			t.Errorf("class %q is returned but not declared in DisagreementClasses()", tc.want)
		}
	}
}

// TestTheObserverNeverConsultsUpstreamAD is ADR 0002 §9.
//
// The same records must produce the same verdict whatever the upstream
// claimed. If the observation could be swayed by the AD bit it would be
// restating the upstream's opinion, and the disagreement matrix — the entire
// output of this milestone — would be measuring nothing.
func TestTheObserverNeverConsultsUpstreamAD(t *testing.T) {
	var got []observe.Status
	for _, upstream := range []string{"validated", "unvalidated", "servfail", ""} {
		sink := &collector{}
		v := &stubValidator{result: dnssec.ValidationResult{
			Status: dnssec.StatusBogus, Reason: dnssec.ReasonSignatureCryptoFailed,
		}}
		o := run(t, v, sink, observe.Options{Workers: 1})

		req := request("example.test.")
		req.UpstreamStatus = upstream
		o.Observe(req)
		if !waitFor(t, 2*time.Second, func() bool { return len(sink.all()) == 1 }) {
			t.Fatalf("no observation for upstream=%q", upstream)
		}
		got = append(got, sink.all()[0].Status)
	}
	for _, s := range got {
		if s != observe.StatusBogus {
			t.Fatalf("verdicts varied with the upstream's claim: %v", got)
		}
	}
}

// TestReasonTextIsBoundedAndSanitised keeps a diagnostic string from becoming
// a way to write into a log, a dashboard or a disk.
func TestReasonTextIsBoundedAndSanitised(t *testing.T) {
	sink := &collector{}
	// A reason the engine does not know produces its raw code as the
	// explanation, which is the widest path attacker-influenced text has into
	// this field.
	nasty := dnssec.Reason(strings.Repeat("A", 5000) + "\n\x1b[2Jinjected\r")
	v := &stubValidator{result: dnssec.ValidationResult{
		Status: dnssec.StatusBogus, Reason: nasty,
	}}
	o := run(t, v, sink, observe.Options{Workers: 1})
	o.Observe(request("long.test."))

	if !waitFor(t, 2*time.Second, func() bool { return len(sink.all()) == 1 }) {
		t.Fatal("no observation was recorded")
	}
	got := sink.all()[0].Reason
	if len(got) > 400 {
		t.Errorf("reason is %d bytes; an unbounded row is a way to fill a disk", len(got))
	}
	for _, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Errorf("reason carries control character %q; it can forge a log line", r)
			break
		}
	}
}

// TestNewIDsAreDistinct checks the correlation identifier is usable as one.
func TestNewIDsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := observe.NewID()
		if id == "" {
			t.Fatal("NewID returned empty")
		}
		if seen[id] {
			t.Fatalf("duplicate id %q after %d draws", id, i)
		}
		seen[id] = true
	}
}

// TestAnUnstoredObservationIsStillCounted is the other half of the privacy
// rule.
//
// Withholding the row must not withhold the evidence. The counters and metrics
// name nothing — they are totals per status — so an operator who switched
// query logging off still gets the measurement this milestone exists to
// produce, without a record of which names were asked for.
func TestAnUnstoredObservationIsStillCounted(t *testing.T) {
	sink := &collector{}
	v := &stubValidator{result: dnssec.ValidationResult{
		Status: dnssec.StatusSecure, Reason: dnssec.ReasonVerified,
	}}
	o := run(t, v, sink, observe.Options{Workers: 1})

	req := request("private.test.")
	req.Store = false
	o.Observe(req)

	if !waitFor(t, 2*time.Second, func() bool { return o.Stats().Observed == 1 }) {
		t.Fatal("the observation was not counted")
	}
	if got := o.Stats().ByStatus[observe.StatusSecure]; got != 1 {
		t.Errorf("secure count = %d, want 1: the aggregate must survive the privacy setting", got)
	}
	if rows := sink.all(); len(rows) != 0 {
		t.Fatalf("a row naming %q was stored despite Store=false", rows[0].Domain)
	}
}
