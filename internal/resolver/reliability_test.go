package resolver

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

func startSilentUpstream(t *testing.T, network string) (string, <-chan struct{}) {
	t.Helper()
	entered := make(chan struct{}, 1)
	server := &dns.Server{Handler: dns.HandlerFunc(func(_ dns.ResponseWriter, _ *dns.Msg) {
		select {
		case entered <- struct{}{}:
		default:
		}
	})}
	var address string
	if network == "udp" {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.PacketConn, address = conn, conn.LocalAddr().String()
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.Listener, address = listener, listener.Addr().String()
	}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("silent upstream did not start")
	}
	t.Cleanup(func() { _ = server.Shutdown() })
	return address, entered
}

func TestResolverFailoverReservesTimeForHealthyBackup(t *testing.T) {
	primary, entered := startSilentUpstream(t, "udp")
	backup := &recordingUpstream{}
	r := newRouteTestResolver(t, []string{"udp://" + primary, "udp://" + startRecordingUpstream(t, backup)}, false, "failover")
	r.timeout = 800 * time.Millisecond
	result, err := r.Resolve(context.Background(), encryptedFixtureQuery(), 1)
	if err != nil || result.Msg == nil || len(result.Msg.Answer) != 1 {
		t.Fatalf("unresponsive primary prevented healthy backup from answering: result=%+v, err=%v", result, err)
	}
	select {
	case <-entered:
	default:
		t.Fatal("test did not exercise an unresponsive primary")
	}
	if len(backup.queries()) != 1 {
		t.Fatalf("backup received %d questions, want 1", len(backup.queries()))
	}
}

func TestResolverCancellationInterruptsLegacyNetworkRead(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			address, entered := startSilentUpstream(t, network)
			r := newRouteTestResolver(t, []string{network + "://" + address}, false, "failover")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				_, err := r.Resolve(ctx, encryptedFixtureQuery(), 1)
				finished <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("query never reached the upstream")
			}
			cancel()
			select {
			case err := <-finished:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled exchange = %v", err)
				}
			case <-time.After(500 * time.Millisecond):
				t.Error("cancelled exchange still waits for the full upstream timeout")
				<-finished
			}
		})
	}
}

func TestResolverEncryptedCacheCannotDisableValidationForAnotherClient(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	var received atomic.Int32
	endpoint := encryptedFixtureServer(t, "doh2", ca.issue(t, "dns.test", false), func(_ context.Context, query *dns.Msg) []byte {
		received.Add(1)
		if query.CheckingDisabled {
			return encryptedFixtureReply(t, query)
		}
		reply := new(dns.Msg)
		reply.SetRcode(query, dns.RcodeServerFailure)
		wire, err := reply.Pack()
		if err != nil {
			t.Error(err)
		}
		return wire
	})
	client := encryptedFixtureClient(t, ca.roots, endpoint)
	route := NewForwardRoute(1, client)
	defer route.Close()
	r := newRouteTestResolver(t, []string{"udp://127.0.0.1:1"}, true, "failover")
	r.SetRouteProvider(func() *ForwardRoute { return route })
	query := encryptedFixtureQuery()
	first, err := r.Resolve(context.Background(), query, 1)
	if err != nil || first.Msg == nil || len(first.Msg.Answer) != 1 {
		t.Fatalf("checking-disabled query = %+v, %v", first, err)
	}
	query.CheckingDisabled = false
	second, err := r.Resolve(context.Background(), query, 1)
	if err != nil || second.Msg == nil || second.Cached || second.Rcode != dns.RcodeServerFailure || second.Msg.CheckingDisabled || len(second.Msg.Answer) != 0 || received.Load() != 2 {
		t.Fatalf("unchecked cached data crossed into a validating client's query: %+v, err=%v, upstream queries=%d", second, err, received.Load())
	}
}

func TestResolverCheckingDisabledQueriesDoNotShareInflightWork(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseFirst := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseFirst)
	upstream := routeFixtureHTTPUpstream(func(query *dns.Msg) (*dns.Msg, error) {
		reply := new(dns.Msg)
		if query.CheckingDisabled {
			close(entered)
			<-release
			reply.SetReply(query)
		} else {
			reply.SetRcode(query, dns.RcodeServerFailure)
		}
		return reply, nil
	})
	r := newRouteTestResolver(t, []string{"udp://127.0.0.1:1"}, false, "failover")
	r.upstreams = []*Upstream{upstream}
	firstDone := make(chan error, 1)
	first := encryptedFixtureQuery()
	go func() { _, err := r.Resolve(context.Background(), first, 1); firstDone <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("checking-disabled question did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	second := first.Copy()
	second.CheckingDisabled = false
	result, err := r.Resolve(ctx, second, 1)
	releaseFirst()
	if firstErr := <-firstDone; firstErr != nil {
		t.Fatal(firstErr)
	}
	if err != nil || result.Msg == nil || result.Rcode != dns.RcodeServerFailure {
		t.Fatalf("validating question joined another client's checking-disabled work: %+v, %v", result, err)
	}
}

func TestCacheSeparatesUnknownQuestionTypesAndClasses(t *testing.T) {
	for _, changeType := range []bool{true, false} {
		q1 := dns.Question{Name: "private-type.test.", Qtype: 65000, Qclass: 65000}
		q2 := q1
		if changeType {
			q2.Qtype++
		} else {
			q2.Qclass++
		}
		cache := testCache(64)
		reply := answer(q1.Name, 300)
		reply.Question = []dns.Question{q1}
		cache.Put(Key(q1, false), reply, 1)
		if got := cache.Get(Key(q2, false), 1); got != nil {
			t.Fatalf("cached answer for type/class %d/%d was served to %d/%d", q1.Qtype, q1.Qclass, q2.Qtype, q2.Qclass)
		}
	}
}

func TestResolverEncryptedOnlyNeedsNoLegacyUpstreams(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	endpoint := encryptedFixtureServer(t, "doh2", ca.issue(t, "dns.test", false), nil)
	client := encryptedFixtureClient(t, ca.roots, endpoint)
	r, err := New(config.DNS{ResolutionTransport: config.ResolutionEncrypted}, config.Cache{}, nil)
	if err != nil {
		t.Fatalf("encrypted-only resolver required unused legacy upstreams: %v", err)
	}
	defer r.Close()
	query := encryptedFixtureQuery()
	if _, err := r.Resolve(context.Background(), query, 1); err == nil {
		t.Fatal("missing encrypted selection was accepted without a configured legacy route")
	}
	route := NewForwardRoute(1, client)
	defer route.Close()
	r.SetRouteProvider(func() *ForwardRoute { return route })
	result, err := r.Resolve(context.Background(), query, 1)
	if err != nil || result.Msg == nil || len(result.Msg.Answer) != 1 || result.Upstream != "doh2" {
		t.Fatalf("encrypted-only resolver did not answer through approved endpoint: %+v, %v", result, err)
	}
	for _, transport := range []string{"", config.ResolutionNative} {
		if _, err := New(config.DNS{ResolutionTransport: transport}, config.Cache{}, nil); err == nil {
			t.Fatalf("transport %q accepted no forwarding upstreams", transport)
		}
	}
}
