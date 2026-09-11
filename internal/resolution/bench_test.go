package resolution_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive/reclab"
	"github.com/jameshoulder/dnsdaddy/internal/resolution"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
)

// Forward against native, cold and warm.
//
// Hermetic on purpose. Both backends talk to servers on loopback in this
// process, so the numbers are about the resolver's own work rather than about
// whoever's network the benchmark happened to run on. That makes them
// reproducible and comparable, and it makes them an underestimate of real
// latency in both cases by exactly the round-trip time each would spend on the
// Internet — which is the honest way round, because the thing being compared is
// the cost DNS Daddy adds.
//
// What this cannot measure: CPU time as a percentage, and resident memory of a
// running process. Go's benchmark framework reports nanoseconds and allocations
// per operation, which is the portable equivalent, and the allocation figures
// are the ones that matter on the reference deployment — one vCPU and a
// gigabyte, where garbage collection is the thing that bites first. The
// document records what was measured and says what was not.

// benchForward builds a forwarding backend over a stub upstream that answers
// instantly, so the measurement is DNS Daddy's overhead rather than Quad9's
// distance.
func benchForward(b testing.TB) (resolution.Backend, func()) {
	b.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(
		func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(req)
			if len(req.Question) > 0 {
				rr, _ := dns.NewRR(req.Question[0].Name + " 300 IN A 203.0.113.5")
				if rr != nil {
					m.Answer = append(m.Answer, rr)
				}
			}
			_ = w.WriteMsg(m)
		})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started

	res, err := resolver.New(config.DNS{
		Upstreams:    []string{"udp://" + pc.LocalAddr().String()},
		UpstreamMode: "failover",
		Timeout:      config.Duration(2 * time.Second),
	}, config.Cache{Enabled: true, MaxEntries: 10000, MaxTTL: 3600}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatalf("resolver.New: %v", err)
	}
	return resolution.NewForward(res, nil), func() {
		res.Close()
		_ = srv.Shutdown()
	}
}

// benchNative builds a native backend over the signed reference hierarchy,
// served as separate authoritative servers.
//
// Signed, and validated on every answer. Measuring native resolution with
// DNSSEC switched off would produce a better number and a meaningless one: the
// validation is the reason to run it.
func benchNative(b testing.TB) resolution.Backend {
	b.Helper()

	h, err := lab.Standard()
	if err != nil {
		b.Fatalf("lab: %v", err)
	}
	servers := reclab.Signed(b, h)
	res := recursive.New(recursive.Config{
		RootHints: []recursive.RootHint{{
			Name: "ns.", Addr: []netip.Addr{servers.Addr(".").Addr()},
		}},
		AllowNonGlobalTargets: true,
		Exchange:              servers.Exchanger(recursive.NewNetExchanger(2*time.Second, 4096, true)),
		UDPSize:               4096,
	})

	spec := lab.StandardSpec()
	at := spec.Inception.Add(spec.Expiration.Sub(spec.Inception) / 2)
	cfg, err := h.Config(at)
	if err != nil {
		b.Fatalf("lab config: %v", err)
	}
	engine, err := native.New(native.Config{
		Resolver: res, Anchors: cfg.Anchors, Policy: cfg.Policy,
		Clock: cfg.Clock, Verifier: cfg.Verifier, Limits: cfg.Limits,
	})
	if err != nil {
		b.Fatalf("engine: %v", err)
	}
	backend, err := resolution.NewNative(engine, resolution.NativeOptions{})
	if err != nil {
		b.Fatalf("backend: %v", err)
	}
	return backend
}

func BenchmarkForward(b *testing.B) {
	backend, stop := benchForward(b)
	defer stop()
	runBench(b, backend, func(i int) string { return fmt.Sprintf("host%d.example.com.", i%64) })
}

// BenchmarkNativeWarm resolves one name repeatedly, so every query after the
// first is served from the recursive cache. The common case on a real
// deployment, where a handful of names account for most traffic.
func BenchmarkNativeWarm(b *testing.B) {
	backend := benchNative(b)
	// Warm it before the timer starts: the first query's walk from the root is
	// what BenchmarkNativeCold measures and would otherwise be amortised
	// invisibly into this one.
	warm(b, backend, lab.AnswerName)
	runBench(b, backend, func(int) string { return lab.AnswerName })
}

// BenchmarkNativeCold flushes between queries, so every one walks from the root
// and validates the whole chain. The worst case, and the one that decides
// whether a deployment can bear native mode on a cold start.
func BenchmarkNativeCold(b *testing.B) {
	backend := benchNative(b)
	req := query(lab.AnswerName, dns.TypeA, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		backend.Purge()
		b.StartTimer()
		if _, err := backend.Resolve(context.Background(), req, 1); err != nil {
			b.Fatalf("resolve: %v", err)
		}
	}
}

func warm(b testing.TB, backend resolution.Backend, name string) {
	b.Helper()
	if _, err := backend.Resolve(context.Background(), query(name, dns.TypeA, true), 1); err != nil {
		b.Fatalf("warm-up: %v", err)
	}
}

func runBench(b *testing.B, backend resolution.Backend, name func(int) string) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := backend.Resolve(context.Background(), query(name(i), dns.TypeA, true), 1); err != nil {
			b.Fatalf("resolve: %v", err)
		}
	}
}

// TestBenchmarkProfile measures the percentiles a benchmark's mean hides, and
// the memory a benchmark's allocation count does not.
//
// A test rather than a benchmark because Go's framework reports a mean and this
// milestone asks for p50, p95 and p99 — and because the numbers wanted are per
// backend under a fixed load, not per iteration. Skipped unless -run names it,
// since it takes seconds and measures rather than asserts.
func TestBenchmarkProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement, not an assertion")
	}

	forward, stop := benchForward(t)
	defer stop()
	native := benchNative(t)

	const queries = 2000
	for _, tc := range []struct {
		name    string
		backend resolution.Backend
		name_   func(int) string
		purge   bool
	}{
		{"forward", forward, func(i int) string { return fmt.Sprintf("host%d.example.com.", i%64) }, false},
		{"native-warm", native, func(int) string { return lab.AnswerName }, false},
	} {
		var (
			latencies = make([]time.Duration, 0, queries)
			before    runtime.MemStats
			after     runtime.MemStats
		)
		runtime.GC()
		runtime.ReadMemStats(&before)

		start := time.Now()
		for i := 0; i < queries; i++ {
			at := time.Now()
			if _, err := tc.backend.Resolve(context.Background(),
				query(tc.name_(i), dns.TypeA, true), 1); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			latencies = append(latencies, time.Since(at))
		}
		wall := time.Since(start)
		runtime.ReadMemStats(&after)

		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		h := tc.backend.Health()
		hit := "not measured"
		if h.CacheHitRate >= 0 {
			hit = fmt.Sprintf("%.1f%%", h.CacheHitRate*100)
		}
		t.Logf("%-12s qps=%.0f p50=%s p95=%s p99=%s heap=%+dKiB cache-hit=%s",
			tc.name,
			float64(queries)/wall.Seconds(),
			latencies[queries/2].Round(time.Microsecond),
			latencies[queries*95/100].Round(time.Microsecond),
			latencies[queries*99/100].Round(time.Microsecond),
			(int64(after.HeapAlloc)-int64(before.HeapAlloc))/1024,
			hit)
	}
}
