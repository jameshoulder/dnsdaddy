package dnsserver

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/protection"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/miekg/dns"
)

func TestLiveActivityCountsAnswersBlocksAndEarlyRejectionsWithoutQueryLogging(t *testing.T) {
	acl := clientacl.Compute([]string{"127.0.0.0/8"}, false, nil)
	h := newHarnessWithQueryLog(t, map[string]string{"evil.com": "malware"}, false, func(o *HandlerOptions) {
		o.ClientACL, o.RefuseANY = acl, true
	})
	fresh := h.handler.LiveActivity()
	if !fresh.Available || fresh.Status != "waiting" || fresh.LastQueryAt != nil || fresh.LastResponseAt != nil {
		t.Fatalf("fresh handler claims traffic: %+v", fresh)
	}
	ctx := context.Background()
	meta := clientMeta("127.0.0.1")
	for _, name := range []string{"private-name.example", "private-name.example", "evil.com"} {
		h.handler.Handle(ctx, query(name, dns.TypeA), meta)
	}
	h.handler.Handle(ctx, query("refused.example", dns.TypeA), clientMeta("203.0.113.9"))
	h.handler.Handle(ctx, nil, meta)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	h.handler.Handle(cancelled, query("cancelled.example", dns.TypeA), meta)
	h.handler.Handle(ctx, query("anything.example", dns.TypeANY), meta)

	live := h.handler.LiveActivity()
	want := ActivityCounts{Received: 7, Completed: 7, Answered: 3, Blocked: 1, Cached: 1, Errors: 1, Refused: 1, Invalid: 1}
	if live.SinceStart != want || live.Recent.ActivityCounts != want || live.Inflight != 0 {
		t.Fatalf("missing or misclassified DNS activity: %+v; want %+v", live, want)
	}
	if live.Status != "degraded" || live.LastOutcome != "answered" || live.LastRcode != "NOERROR" || live.LastQueryAt == nil || live.LastResponseAt == nil {
		t.Fatalf("incorrect current activity: %+v", live)
	}
	if live.Recent.WindowSeconds != 60 || live.Recent.QueriesPerSecond != 7.0/60 {
		t.Fatalf("incorrect measured rate: %+v", live.Recent)
	}

	// No log flush is needed to see activity. The snapshot itself must not
	// disclose the names or addresses it counted.
	raw, err := json.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-name", "evil.com", "refused.example", "203.0.113.9", "127.0.0.1"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("anonymous activity exposed %q", secret)
		}
	}
	if rows, _, err := h.store.ListQueries(ctx, store.QueryFilter{Limit: 10}); err != nil || len(rows) != 0 {
		t.Fatalf("activity enabled private query logging: rows=%d error=%v", len(rows), err)
	}
}

func TestLiveActivityReportsNativeFailuresAndLocalProtections(t *testing.T) {
	t.Run("native validation failure", func(t *testing.T) {
		n := &nativeRuntimeStub{address: "9.9.9.9", fail: true}
		h := newHarnessWithQueryLog(t, nil, false, func(o *HandlerOptions) { o.Native = n })
		h.handler.Handle(context.Background(), query("example.test", dns.TypeA), clientMeta("127.0.0.1"))
		got := h.handler.LiveActivity()
		if got.Status != "failing" || got.SinceStart.Errors != 1 || got.LastRcode != "SERVFAIL" {
			t.Fatalf("native failure looked successful: %+v", got)
		}
	})
	t.Run("rebinding block", func(t *testing.T) {
		c, err := protection.New(protection.Default(), nil)
		if err != nil {
			t.Fatal(err)
		}
		n := &nativeRuntimeStub{address: "10.1.2.3"}
		h := newHarnessWithQueryLog(t, nil, false, func(o *HandlerOptions) { o.Native, o.Protection = n, c })
		h.handler.Handle(context.Background(), query("public.test", dns.TypeA), clientMeta("127.0.0.1"))
		got := h.handler.LiveActivity()
		if got.SinceStart.Blocked != 1 || got.SinceStart.Refused != 0 || got.SinceStart.Errors != 0 {
			t.Fatalf("rebinding block confused with access refusal: %+v", got)
		}
	})
	t.Run("rate limit", func(t *testing.T) {
		cfg := protection.Default()
		cfg.RateLimit.QPS, cfg.RateLimit.Burst = 1, 1
		c, err := protection.New(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		n := &nativeRuntimeStub{address: "9.9.9.9"}
		h := newHarnessWithQueryLog(t, nil, false, func(o *HandlerOptions) { o.Native, o.Protection = n, c })
		for range 2 {
			h.handler.Handle(context.Background(), query("example.test", dns.TypeA), clientMeta("127.0.0.1"))
		}
		got := h.handler.LiveActivity()
		if got.SinceStart.RateLimited != 1 || got.SinceStart.Answered != 1 || got.SinceStart.Received != 2 || got.SinceStart.Refused != 0 {
			t.Fatalf("rate-limited arrival disappeared: %+v", got)
		}
	})
}

func TestLiveActivityAgesOutFailuresAndRecognizesIdle(t *testing.T) {
	// Control time without a minute-long sleep. Use the actual handler to
	// produce the rejection, then take snapshots across the window boundary.
	acl := clientacl.Compute([]string{"127.0.0.0/8"}, false, nil)
	h := newHarnessWithQueryLog(t, nil, false, func(o *HandlerOptions) { o.ClientACL = acl })
	h.handler.Handle(context.Background(), query("example.test", dns.TypeA), clientMeta("203.0.113.9"))
	refused := h.handler.LiveActivity()
	if refused.Status != "refused" || refused.SinceStart.Refused != 1 {
		t.Fatalf("access failure hidden: %+v", refused)
	}
	later := h.handler.activity.snapshot(refused.MeasuredAt.Add(61 * time.Second))
	if later.Status != "idle" || later.Recent.Received != 0 || later.Recent.Refused != 0 || later.SinceStart.Refused != 1 {
		t.Fatalf("old refusal presented as current traffic: %+v", later)
	}
	if later.LastQueryAt == nil || !later.LastQueryAt.Equal(*refused.LastQueryAt) {
		t.Fatal("aging the window forgot the last actual arrival")
	}
}

func TestLiveActivityPreservesUnassignedRcodeForDiagnostics(t *testing.T) {
	var tracker activityTracker
	now := time.Now()
	tracker.begin(now)
	tracker.finish(now, activityError, false, &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: 12}})
	got := tracker.snapshot(now)
	if got.LastRcode != "RCODE12" || got.SinceStart.Errors != 1 {
		t.Fatalf("unassigned response code disappeared: %+v", got)
	}
}

func TestLiveActivityKeepsNewestTimestampsAcrossConcurrentCompletionOrder(t *testing.T) {
	var tracker activityTracker
	now := time.Now()
	// Simulate a goroutine paused between sampling its event time and
	// acquiring the tracker lock while another query gets there first.
	tracker.begin(now.Add(2 * time.Second))
	tracker.begin(now.Add(time.Second))
	tracker.finish(now.Add(4*time.Second), activityAnswered, false, &dns.Msg{})
	tracker.finish(now.Add(3*time.Second), activityError, false, &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})
	got := tracker.snapshot(now.Add(5 * time.Second))
	if got.LastQueryAt == nil || !got.LastQueryAt.Equal(now.Add(2*time.Second)) ||
		got.LastResponseAt == nil || !got.LastResponseAt.Equal(now.Add(4*time.Second)) ||
		got.LastOutcome != "answered" || got.LastRcode != "NOERROR" {
		t.Fatalf("older goroutine replaced the last actual event: %+v", got)
	}
	if got.SinceStart.Received != 2 || got.SinceStart.Completed != 2 || got.SinceStart.Errors != 1 || got.Inflight != 0 {
		t.Fatalf("retaining the newest event lost a completion: %+v", got)
	}
}

type activityGatedNative struct {
	started chan struct{}
	release chan struct{}
}

func (n *activityGatedNative) NativeClient() NativeResolver { return n }
func (n *activityGatedNative) ResolveClient(ctx context.Context, q *dns.Msg) native.ClientResult {
	n.started <- struct{}{}
	select {
	case <-n.release:
	case <-ctx.Done():
	}
	response := new(dns.Msg)
	response.SetReply(q)
	response.Rcode = dns.RcodeNameError
	return native.ClientResult{Msg: response}
}

func TestLiveActivityTracksConcurrentQueriesBeforeTheyComplete(t *testing.T) {
	const clients = 24
	n := &activityGatedNative{started: make(chan struct{}, clients), release: make(chan struct{})}
	h := newHarnessWithQueryLog(t, nil, false, func(o *HandlerOptions) { o.Native = n })
	var done sync.WaitGroup
	var release sync.Once
	unblock := func() { release.Do(func() { close(n.release) }) }
	for range clients {
		done.Go(func() {
			h.handler.Handle(context.Background(), query("absent.example", dns.TypeA), clientMeta("127.0.0.1"))
		})
	}
	t.Cleanup(func() { unblock(); done.Wait() })
	for range clients {
		select {
		case <-n.started:
		case <-time.After(2 * time.Second):
			t.Fatal("queries did not reach the resolver")
		}
	}
	live := h.handler.LiveActivity()
	if live.SinceStart.Received != clients || live.SinceStart.Completed != 0 || live.Inflight != clients || live.LastResponseAt != nil {
		t.Fatalf("pending work is not visible: %+v", live)
	}
	unblock()
	done.Wait()
	live = h.handler.LiveActivity()
	if live.SinceStart.Completed != clients || live.SinceStart.Answered != clients || live.Inflight != 0 || live.LastRcode != "NXDOMAIN" {
		t.Fatalf("concurrent NXDOMAIN answers were lost or counted as failures: %+v", live)
	}
}
