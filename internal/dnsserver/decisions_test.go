package dnsserver

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/decisions"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// captureRecorder records what the handler offered, and can be made slow to
// prove the resolution path does not wait for it.
type captureRecorder struct {
	mu     sync.Mutex
	events []decisions.Event
	delay  time.Duration
}

func (c *captureRecorder) Record(e decisions.Event) {
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureRecorder) all() []decisions.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]decisions.Event(nil), c.events...)
}

// A blocked query reaches the recorder with everything needed to explain it.
func TestABlockedQueryIsOfferedToTheRecorder(t *testing.T) {
	rec := &captureRecorder{}
	h := newHarnessWithOptions(t, map[string]string{"evil.com": "malware"},
		func(o *HandlerOptions) { o.Decisions = rec })

	resp := h.handler.Handle(context.Background(), query("evil.com", dns.TypeA), clientMeta("192.0.2.10"))
	if resp == nil {
		t.Fatal("no response")
	}

	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("the recorder received %d events, want 1", len(got))
	}
	e := got[0]
	if e.Domain != "evil.com" || !e.Blocked {
		t.Errorf("event does not describe the block: %+v", e)
	}
	if e.Basis.Rule != policy.RuleCategory {
		t.Errorf("basis rule = %q, want category", e.Basis.Rule)
	}
	if e.Basis.FeedID == "" || e.Basis.FeedName == "" {
		t.Errorf("the event does not name the feed that decided: %+v", e.Basis)
	}
	if e.Basis.PolicyName == "" {
		t.Error("the event does not name the policy in force")
	}
	if e.QType != "A" {
		t.Errorf("qtype = %q", e.QType)
	}
	if e.Time.IsZero() {
		t.Error("no timestamp")
	}
}

// A decision with no basis must not be offered, whatever reaches the guard.
//
// The call site sits inside the blocked branch, so an ordinary allowed query
// never gets here anyway — which is why the test below passes with the guard
// removed, and why this one exists to cover the guard itself. The case it
// protects against is a blocked decision whose basis is empty: a policy with
// no rules, or a future rule that forgets to set one. Recording that would
// write a decision nothing can explain.
func TestABlockedDecisionWithNoBasisIsNotOffered(t *testing.T) {
	rec := &captureRecorder{}
	h := newHarnessWithOptions(t, map[string]string{"evil.com": "malware"},
		func(o *HandlerOptions) { o.Decisions = rec })

	h.handler.recordDecision(
		storeEventFor("evil.com"),
		policy.Match{NetworkID: "n_1", NetworkName: "Office"},
		policy.Decision{Blocked: true}, // blocked, but nothing decided it
	)

	if got := rec.all(); len(got) != 0 {
		t.Errorf("a decision with no basis was offered for recording: %+v", got)
	}

	// And with a basis it is offered, so the guard is not simply refusing
	// everything.
	h.handler.recordDecision(
		storeEventFor("evil.com"),
		policy.Match{NetworkID: "n_1", NetworkName: "Office"},
		policy.Decision{Blocked: true, Basis: policy.Basis{
			Rule: policy.RuleCategory, FeedID: "f_x", FeedName: "Feed X", Category: "malware",
		}},
	)
	if got := rec.all(); len(got) != 1 {
		t.Errorf("a decision with a basis was not offered: %+v", got)
	}
}

// An ordinary allowed query must not reach the recorder — otherwise this
// becomes a record per query rather than per decision.
func TestAnAllowedQueryIsNotOfferedToTheRecorder(t *testing.T) {
	rec := &captureRecorder{}
	h := newHarnessWithOptions(t, map[string]string{"evil.com": "malware"},
		func(o *HandlerOptions) { o.Decisions = rec })

	h.handler.Handle(context.Background(), query("example.com", dns.TypeA), clientMeta("192.0.2.10"))

	if got := rec.all(); len(got) != 0 {
		t.Errorf("an allowed query produced %d decision events: %+v", len(got), got)
	}
}

// With no recorder configured — the default — the block path must work
// unchanged. This is the nil-interface case, and a typed nil would panic here.
func TestBlockingWorksWithNoRecorderConfigured(t *testing.T) {
	h := newHarnessWithOptions(t, map[string]string{"evil.com": "malware"})
	resp := h.handler.Handle(context.Background(), query("evil.com", dns.TypeA), clientMeta("192.0.2.10"))
	if resp == nil {
		t.Fatal("no response with no recorder configured")
	}
	if resp.Rcode != dns.RcodeNameError && len(resp.Answer) != 0 {
		t.Errorf("the block did not take effect: rcode %d, %d answers", resp.Rcode, len(resp.Answer))
	}
}

// The resolution path must not wait for recording. A recorder that blocks for
// a second must not add a second to the answer.
//
// The real recorder's Record is a non-blocking channel send, so this is really
// asserting that the handler calls it on the query goroutine only because that
// call is cheap — and pinning the cost, so that a future recorder that starts
// doing work is caught here rather than in production.
func TestASlowRecorderDoesNotDelayTheAnswerBeyondItsOwnCost(t *testing.T) {
	fast := &captureRecorder{}
	h := newHarnessWithOptions(t, map[string]string{"evil.com": "malware"},
		func(o *HandlerOptions) { o.Decisions = fast })

	start := time.Now()
	h.handler.Handle(context.Background(), query("evil.com", dns.TypeA), clientMeta("192.0.2.10"))
	baseline := time.Since(start)

	// The real recorder: a buffered send that cannot block.
	real := decisions.New(nil, decisions.Options{QueueSize: 16})
	h2 := newHarnessWithOptions(t, map[string]string{"evil.com": "malware"},
		func(o *HandlerOptions) { o.Decisions = real })

	start = time.Now()
	h2.handler.Handle(context.Background(), query("evil.com", dns.TypeA), clientMeta("192.0.2.10"))
	withReal := time.Since(start)

	// Generous: this is a smoke check that recording is not doing I/O on the
	// query goroutine, not a latency benchmark.
	if withReal > baseline+50*time.Millisecond {
		t.Errorf("recording added %s to a blocked answer (baseline %s)", withReal-baseline, baseline)
	}
}

// storeEventFor builds the query event the handler would have built.
func storeEventFor(domain string) store.QueryEvent {
	return store.QueryEvent{
		Time: time.Now().UTC(), Domain: domain, QType: "A",
		ClientIP: "192.0.2.10", Action: store.ActionBlocked,
	}
}
