package resolver

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func exchangeRouteSystem(t *testing.T, r *net.Resolver, ctx context.Context, network, server string, query *dns.Msg) (*dns.Msg, error) {
	t.Helper()
	conn, err := r.Dial(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, ok := conn.(net.PacketConn); ok {
		t.Fatal("bridge must use stream DNS framing regardless of requested network")
	}
	client := &dns.Client{Timeout: time.Second}
	reply, _, err := client.ExchangeWithConnContext(ctx, query, &dns.Conn{Conn: conn})
	return reply, err
}

func TestSystemResolverNativeUsesOnlySuppliedLiteralServer(t *testing.T) {
	plain := &recordingUpstream{}
	address := startRecordingUpstream(t, plain)
	route := NewForwardRoute(1, nil)
	defer route.Close()
	r := NewSystemResolver(func() *ForwardRoute { return route }, time.Second)
	query := encryptedFixtureQuery()
	reply, err := exchangeRouteSystem(t, r, context.Background(), "udp", address, query)
	if err != nil || !systemDNSAnswerMatches(reply, query) || len(plain.queries()) != 1 {
		t.Fatalf("framed native lookup = %v, %v; queries=%d", reply, err, len(plain.queries()))
	}
	if _, err := r.Dial(context.Background(), "udp", "recursive-bootstrap.invalid:53"); err == nil {
		t.Fatal("OS DNS hostname could recursively bootstrap through itself")
	}
}

func TestSystemResolverEncryptedIgnoresOSDNSAndPreservesFraming(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	endpoint := encryptedFixtureServer(t, "doh2", ca.issue(t, "dns.test", false), nil)
	client := encryptedFixtureClient(t, ca.roots, endpoint)
	route := NewForwardRoute(1, client)
	defer route.Close()
	r := NewSystemResolver(func() *ForwardRoute { return route }, time.Second)
	query := encryptedFixtureQuery()
	// Even an unusable OS nameserver cannot cause encrypted bootstrapping to
	// depend on plaintext DNS, or turn an encrypted success into a fallback.
	for _, network := range []string{"udp", "tcp"} {
		reply, err := exchangeRouteSystem(t, r, context.Background(), network, "not-an-os-server", query)
		if err != nil || !systemDNSAnswerMatches(reply, query) || reply.Answer[0].(*dns.A).A.String() != "203.0.113.7" {
			t.Fatalf("%s encrypted bridge = %v, %v", network, reply, err)
		}
	}
}

func TestSystemResolverLookupIPUsesEncryptedWire(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	var queries atomic.Int64
	endpoint := encryptedFixtureServer(t, "doh2", ca.issue(t, "dns.test", false), func(_ context.Context, query *dns.Msg) []byte {
		queries.Add(1)
		if query.Question[0].Qtype == dns.TypeA {
			return encryptedFixtureReply(t, query)
		}
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.RecursionAvailable = true
		wire, err := reply.Pack()
		if err != nil {
			t.Error(err)
		}
		return wire
	})
	client := encryptedFixtureClient(t, ca.roots, endpoint)
	route := NewForwardRoute(1, client)
	defer route.Close()
	r := NewSystemResolver(func() *ForwardRoute { return route }, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addresses, err := r.LookupIPAddr(ctx, "route-system-fixture.invalid.")
	if err != nil || len(addresses) != 1 || addresses[0].IP.String() != "203.0.113.7" || queries.Load() == 0 {
		t.Fatalf("Go hostname resolver did not use encrypted bridge: %+v, %v, queries=%d", addresses, err, queries.Load())
	}
}

func TestSystemResolverTLSFailureNeverReachesOSDNS(t *testing.T) {
	plain := &recordingUpstream{}
	address := startRecordingUpstream(t, plain)
	ca := newEncryptedFixtureCA(t)
	endpoint := encryptedFixtureServer(t, "doh2", ca.issue(t, "wrong.test", false), nil)
	client := encryptedFixtureClient(t, ca.roots, endpoint)
	route := NewForwardRoute(1, client)
	defer route.Close()
	r := NewSystemResolver(func() *ForwardRoute { return route }, time.Second)
	if reply, err := exchangeRouteSystem(t, r, context.Background(), "udp", address, encryptedFixtureQuery()); err == nil || reply != nil {
		t.Fatalf("TLS failure accepted: %v, %v", reply, err)
	}
	if len(plain.queries()) != 0 {
		t.Fatal("encrypted failure leaked a query to the OS nameserver")
	}
}

func TestSystemResolverRouteSwapStopsPlaintextImmediatelyAfterDrain(t *testing.T) {
	plain := &recordingUpstream{}
	address := startRecordingUpstream(t, plain)
	ca := newEncryptedFixtureCA(t)
	endpoint := encryptedFixtureServer(t, "doh2", ca.issue(t, "dns.test", false), nil)
	client := encryptedFixtureClient(t, ca.roots, endpoint)
	first, second := NewForwardRoute(1, nil), NewForwardRoute(2, client)
	var current atomic.Pointer[ForwardRoute]
	current.Store(first)
	r := NewSystemResolver(current.Load, time.Second)
	// Capture a native selection, then leave the frame unsent until retirement.
	oldConn, err := r.Dial(context.Background(), "udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer oldConn.Close()
	current.Store(second)
	first.Close()
	defer second.Close()
	if _, err := oldConn.Write([]byte{0, 12}); err == nil {
		t.Fatal("retired unsent native bridge still accepts work")
	}
	if reply, err := exchangeRouteSystem(t, r, context.Background(), "udp", address, encryptedFixtureQuery()); err != nil || reply == nil {
		t.Fatalf("new encrypted bridge = %v, %v", reply, err)
	}
	if len(plain.queries()) != 0 {
		t.Fatal("retired or new route emitted plaintext DNS")
	}
}

func TestSystemResolverBoundsIdleBridgesAndDrainsOnRetirement(t *testing.T) {
	route := NewForwardRoute(1, nil)
	r := NewSystemResolver(func() *ForwardRoute { return route }, time.Second)
	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
		route.Close()
	}()
	for i := 0; i < maxSystemDNSBridges; i++ {
		conn, err := r.Dial(context.Background(), "udp", "127.0.0.1:1")
		if err != nil {
			t.Fatalf("admit bridge %d: %v", i, err)
		}
		connections = append(connections, conn)
	}
	if _, err := r.Dial(context.Background(), "udp", "127.0.0.1:1"); !errors.Is(err, errSystemDNSBusy) {
		t.Fatalf("overflow admission = %v", err)
	}
	closed := make(chan struct{})
	go func() { route.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("idle bridges held route retirement open")
	}
}

func TestSystemResolverMalformedAndAbandonedFramesNeverSend(t *testing.T) {
	plain := &recordingUpstream{}
	address := startRecordingUpstream(t, plain)
	route := NewForwardRoute(1, nil)
	r := NewSystemResolver(func() *ForwardRoute { return route }, time.Second)
	for _, wire := range [][]byte{{0, 1}, {0, 12, 0, 0, 0}} {
		conn, err := r.Dial(context.Background(), "udp", address)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = conn.Write(wire)
		_ = conn.Close()
	}
	route.Close()
	if len(plain.queries()) != 0 {
		t.Fatal("incomplete or invalid frame sent a DNS query")
	}
}

func TestSystemResolverCallerCancellationStopsEncryptedExchange(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	entered := make(chan struct{}, 1)
	endpoint := encryptedFixtureServer(t, "doh2", ca.issue(t, "dns.test", false), func(ctx context.Context, _ *dns.Msg) []byte {
		entered <- struct{}{}
		<-ctx.Done()
		return nil
	})
	client := encryptedFixtureClient(t, ca.roots, endpoint)
	route := NewForwardRoute(1, client)
	r := NewSystemResolver(func() *ForwardRoute { return route }, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := exchangeRouteSystem(t, r, ctx, "udp", "unused", encryptedFixtureQuery())
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("encrypted request did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled DNS bridge succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("caller cancellation left bridge running")
	}
	route.Close()
	if client.Stats().InFlight != 0 {
		t.Fatal("retired route retained an active encrypted lookup")
	}
}

func TestSystemResolverDeadlineClosesUnsentFrame(t *testing.T) {
	route := NewForwardRoute(1, nil)
	defer route.Close()
	r := NewSystemResolver(func() *ForwardRoute { return route }, 30*time.Millisecond)
	conn, err := r.Dial(context.Background(), "udp", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	finished := make(chan error, 1)
	go func() { var b [1]byte; _, err := io.ReadFull(conn, b[:]); finished <- err }()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("idle bridge returned data without a query")
		}
	case <-time.After(time.Second):
		t.Fatal("idle bridge exceeded its process DNS deadline")
	}
}
