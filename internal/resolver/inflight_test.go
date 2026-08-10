package resolver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

// slowUpstream answers only once a test unblocks it, so tests can control
// exactly how many upstream exchanges are in flight at once.
func slowUpstream(t *testing.T, release <-chan struct{}) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			<-release
			m := new(dns.Msg)
			m.SetReply(req)
			if len(req.Question) > 0 {
				m.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(203, 0, 113, 20),
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
		t.Fatal("slow test upstream did not start")
	}
	t.Cleanup(func() { srv.Shutdown() })

	return pc.LocalAddr().String()
}

func TestMaxInflightBoundsConcurrentUpstreamExchanges(t *testing.T) {
	release := make(chan struct{})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	r, err := New(config.DNS{
		Upstreams:    []string{"udp://" + slowUpstream(t, release)},
		UpstreamMode: "failover",
		Timeout:      config.Duration(5 * time.Second),
		MaxInflight:  2,
	}, config.Cache{Enabled: true, MaxEntries: 100, MinTTL: 1, MaxTTL: 60, NegativeTTL: 10}, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(r.Close)

	// Five distinct questions (distinct so none collapse onto a shared
	// in-flight call — this test is about the concurrency limit, not
	// de-duplication) all block on the slow upstream at once.
	const n = 5
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := new(dns.Msg)
			req.SetQuestion(dns.Fqdn(randomName(1000+i)), dns.TypeA)
			_, _ = r.Resolve(context.Background(), req, 1)
		}(i)
	}

	// Give every goroutine a moment to reach the semaphore.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cur, _, _ := r.InflightStats()
		if cur == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cur, peak, _ := r.InflightStats()
	if cur != 2 {
		t.Fatalf("current in-flight = %d, want exactly 2 (max_inflight=2) with %d queries parked", cur, n)
	}
	if peak < 2 {
		t.Errorf("peak in-flight = %d, want at least 2", peak)
	}

	close(release)
	wg.Wait()

	cur, _, _ = r.InflightStats()
	if cur != 0 {
		t.Errorf("current in-flight after completion = %d, want 0 — a slot leaked", cur)
	}
}

func TestMaxInflightTimesOutRatherThanQueueingForever(t *testing.T) {
	release := make(chan struct{})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// The resolver's own per-exchange timeout is generous here on purpose: the
	// "holder" request must not time out and free its slot on its own, or it
	// would defeat the point of the test. What is actually under test is the
	// *waiter*'s own short-lived context giving up on the semaphore wait —
	// that is asserted via an explicit per-call context below, independent of
	// this resolver-wide value.
	r, err := New(config.DNS{
		Upstreams:    []string{"udp://" + slowUpstream(t, release)},
		UpstreamMode: "failover",
		Timeout:      config.Duration(10 * time.Second),
		MaxInflight:  1,
	}, config.Cache{Enabled: true, MaxEntries: 100, MinTTL: 1, MaxTTL: 60, NegativeTTL: 10}, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(r.Close)

	// Occupy the single slot until the test explicitly frees it below.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn("holder.example"), dns.TypeA)
		_, _ = r.Resolve(context.Background(), req, 1)
	}()
	t.Cleanup(func() {
		close(release)
		wg.Wait()
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cur, _, _ := r.InflightStats(); cur == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cur, _, _ := r.InflightStats(); cur != 1 {
		t.Fatalf("current in-flight = %d, want 1 (the holder) before testing the waiter", cur)
	}

	// A second, distinct question, bounded by its own short deadline, cannot
	// get a slot and must give up at that deadline — never touching the
	// network — rather than blocking until the holder eventually finishes.
	waitCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("waiter.example"), dns.TypeA)

	start := time.Now()
	_, err = r.Resolve(waitCtx, req, 1)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Resolve succeeded despite the concurrency limit being held")
	}
	if elapsed > time.Second {
		t.Errorf("Resolve took %v to give up; it should bail at its own deadline (150ms), not hang", elapsed)
	}

	_, _, timeouts := r.InflightStats()
	if timeouts == 0 {
		t.Error("no limit-timeout was counted for the request that could not get a slot")
	}
}

func TestMaxInflightDefaultsWhenUnset(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r, err := New(config.DNS{
		Upstreams:    []string{"udp://127.0.0.1:1"}, // unreachable; only checking construction
		UpstreamMode: "failover",
		Timeout:      config.Duration(time.Second),
		// MaxInflight left at zero.
	}, config.Cache{}, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(r.Close)

	if cap(r.sem) <= 0 {
		t.Errorf("semaphore capacity = %d, want a positive default", cap(r.sem))
	}
}
