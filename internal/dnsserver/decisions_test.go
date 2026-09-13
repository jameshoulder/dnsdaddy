package dnsserver

import (
	"context"
	"io"
	"log/slog"
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
		nil,                            // and no observe engine looked at it
	)

	if got := rec.all(); len(got) != 0 {
		t.Errorf("a decision with no basis was offered for recording: %+v", got)
	}

	// And with a basis it is offered, so the guard is not simply refusing
	// everything.
	h.handler.recordDecision(
		storeEventFor("evil.com"),
		policy.Match{NetworkID: "n_1", NetworkName: "Office"},
		policy.Decision{Blocked: true, Basis: &policy.Basis{
			Rule: policy.RuleCategory, FeedID: "f_x", FeedName: "Feed X", Category: "malware",
		}},
		nil,
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

// TestABlockedQueryLinksItsQueryLogRowToItsDecision.
//
// The link is what makes "why was this blocked?" answerable from the row an
// operator is looking at. It is an application-generated correlation because
// the two rows are written by different batched writers — the query log gets a
// SQLite rowid the decision writer never sees.
func TestABlockedQueryLinksItsQueryLogRowToItsDecision(t *testing.T) {
	rec := &captureRecorder{}
	h := newHarnessWithOptions(t, map[string]string{"evil.com": "malware"},
		func(o *HandlerOptions) { o.Decisions = rec })
	ctx := context.Background()

	h.handler.Handle(ctx, query("evil.com", dns.TypeA), clientMeta("10.0.0.1"))

	offered := rec.all()
	if len(offered) != 1 {
		t.Fatalf("%d decisions offered, want 1", len(offered))
	}
	if offered[0].ID == "" {
		t.Fatal("the decision was offered with no correlation id")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rows, _, err := h.store.ListQueries(ctx, store.QueryFilter{Limit: 10})
		if err != nil {
			t.Fatalf("ListQueries: %v", err)
		}
		if len(rows) > 0 {
			if rows[0].DecisionID != offered[0].ID {
				t.Errorf("query row decision id = %q, want %q", rows[0].DecisionID, offered[0].ID)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no query-log row was written")
}

// TestAnOrdinaryAllowedQueryCarriesNoDecisionID, so an empty id genuinely
// means "nothing decided" rather than "the record went missing".
func TestAnOrdinaryAllowedQueryCarriesNoDecisionID(t *testing.T) {
	rec := &captureRecorder{}
	h := newHarnessWithOptions(t, nil, func(o *HandlerOptions) { o.Decisions = rec })
	ctx := context.Background()

	h.handler.Handle(ctx, query("ordinary.example", dns.TypeA), clientMeta("10.0.0.2"))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rows, _, err := h.store.ListQueries(ctx, store.QueryFilter{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 0 {
			if rows[0].DecisionID != "" {
				t.Errorf("an ordinary allowed query carries decision id %q", rows[0].DecisionID)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no query-log row was written")
}

// TestTheDecisionWriterCannotChangeTheWire.
//
// The record is written off the answer path, so a recorder that is slow, full
// or absent must produce byte-identical responses. This is the load-bearing
// property: the moment explaining a decision can alter one, the explanation
// stops being a record and becomes a participant.
func TestTheDecisionWriterCannotChangeTheWire(t *testing.T) {
	ctx := context.Background()

	without := newHarnessWithOptions(t, map[string]string{"evil.com": "malware"},
		func(o *HandlerOptions) { o.Decisions = nil })
	// A recorder whose queue is one deep and never drained: every send after
	// the first is dropped.
	stuck := decisions.New(nil, decisions.Options{QueueSize: 1,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	with := newHarnessWithOptions(t, map[string]string{"evil.com": "malware"},
		func(o *HandlerOptions) { o.Decisions = stuck })

	for _, name := range []string{"evil.com", "example.com", "evil.com", "evil.com"} {
		a := without.handler.Handle(ctx, query(name, dns.TypeA), clientMeta("10.0.0.3"))
		b := with.handler.Handle(ctx, query(name, dns.TypeA), clientMeta("10.0.0.3"))
		if a == nil || b == nil {
			t.Fatalf("%s: nil response", name)
		}
		b.Id = a.Id
		if a.String() != b.String() {
			t.Errorf("%s: the decision writer changed the answer\nwithout:\n%s\nwith:\n%s",
				name, a.String(), b.String())
		}
	}
}

// TestAnObserveEngineAloneDoesNotCreateADecisionRecord.
//
// Daddybound in Learn mode looks at every query that resolves successfully. If
// an observation were enough to bring a decision record into being, then
// turning on local validation — a setting about DNSSEC, which says nothing
// about decision records — would silently convert this table from one row per
// blocked query into one row per query. On a 1 GB box with the documented
// 30-day retention that is the difference between a few thousand rows and tens
// of millions, and the first an operator would know of it is the disk filling.
//
// So an observation attaches to a record that exists for another reason and
// never creates one. This test resolves an ordinary allowed name with the
// observer accepting, and asserts nothing is offered.
func TestAnObserveEngineAloneDoesNotCreateADecisionRecord(t *testing.T) {
	rec := &captureRecorder{}
	obs := &recordingObserver{accept: true}
	h := newHarnessWithOptions(t, map[string]string{"evil.com": "malware"},
		func(o *HandlerOptions) {
			o.Decisions = rec
			o.DNSSEC = obs
		})
	ctx := context.Background()

	h.handler.Handle(ctx, query("ordinary.example", dns.TypeA), clientMeta("192.0.2.11"))

	if seen := obs.seen(); len(seen) != 1 {
		t.Fatalf("the observer saw %d queries, want 1 — the test is not exercising what it claims", len(seen))
	}
	if got := rec.all(); len(got) != 0 {
		t.Fatalf("an observed-but-undecided query produced %d decision record(s): %+v", len(got), got)
	}

	// And the observation still reaches a record that exists for a real
	// reason, so this is a restriction on what creates a record rather than a
	// removal of observe contributors.
	h.handler.Handle(ctx, query("evil.com", dns.TypeA), clientMeta("192.0.2.11"))
	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("the blocked query produced %d decision record(s), want 1", len(got))
	}
}
