package resolver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/config"
)

func TestForwardRouteRetirementCancelsAndDrains(t *testing.T) {
	route := NewForwardRoute(17, nil)
	ctx, done, err := route.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { route.Close(); close(closed) }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("retirement did not cancel admitted work")
	}
	if !errors.Is(context.Cause(ctx), ErrForwardRouteRetired) {
		t.Fatalf("retirement cause = %v", context.Cause(ctx))
	}
	select {
	case <-closed:
		t.Fatal("retirement returned before admitted work drained")
	default:
	}
	if _, _, err := route.Begin(context.Background()); !errors.Is(err, ErrForwardRouteRetired) {
		t.Fatalf("late admission = %v", err)
	}
	done()
	done() // A deferred cleanup and an explicit abort may both release.
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("retirement did not finish after release")
	}
	route.Close()
}

func TestForwardRouteParentCancellationDoesNotRetireSelection(t *testing.T) {
	route := NewForwardRoute(1, nil)
	defer route.Close()
	parent, cancel := context.WithCancel(context.Background())
	ctx, done, err := route.Begin(parent)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("parent cancellation = %v", ctx.Err())
	}
	done()
	_, again, err := route.Begin(context.Background())
	if err != nil {
		t.Fatalf("one cancelled request retired the whole selection: %v", err)
	}
	again()
}

func newRouteTestResolver(t *testing.T, addresses []string, cache bool, mode string) *Resolver {
	t.Helper()
	r, err := New(config.DNS{Upstreams: addresses, UpstreamMode: mode,
		Timeout: config.Duration(2 * time.Second), MaxInflight: 16, DNSSECTelemetry: true},
		config.Cache{Enabled: cache, MaxEntries: 64, MaxTTL: 300},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestResolverRouteGenerationSeparatesCache(t *testing.T) {
	plain := &recordingUpstream{setAD: true}
	r := newRouteTestResolver(t, []string{"udp://" + startRecordingUpstream(t, plain)}, true, "failover")
	var current atomic.Pointer[ForwardRoute]
	first := NewForwardRoute(1, nil)
	current.Store(first)
	r.SetRouteProvider(current.Load)
	query := encryptedFixtureQuery()
	query.CheckingDisabled = false
	query.SetEdns0(1232, false)
	query.AuthenticatedData = false
	result, err := r.Resolve(context.Background(), query, 1)
	if err != nil || !result.Validated || result.Msg.AuthenticatedData {
		t.Fatalf("initial result lost AD telemetry/wire separation: %+v, %v", result, err)
	}
	cached, err := r.Resolve(context.Background(), query, 1)
	if err != nil || !cached.Cached {
		t.Fatalf("same route cache result = %+v, %v", cached, err)
	}
	second := NewForwardRoute(2, nil)
	current.Store(second)
	first.Close()
	defer second.Close()
	result, err = r.Resolve(context.Background(), query, 1)
	if err != nil || result.Cached || len(plain.queries()) != 2 {
		t.Fatalf("new generation reused old cache: %+v, %v, queries=%d", result, err, len(plain.queries()))
	}
}

func TestResolverRouteGenerationSeparatesInflight(t *testing.T) {
	firstEntered, releaseFirst := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseFirst) }) })
	var calls atomic.Int32
	upstream := routeFixtureHTTPUpstream(func(req *dns.Msg) (*dns.Msg, error) {
		n := calls.Add(1)
		if n == 1 {
			close(firstEntered)
			<-releaseFirst
		}
		reply := new(dns.Msg)
		reply.SetReply(req)
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name,
			Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, byte(n))}}
		return reply, nil
	})
	r := newRouteTestResolver(t, []string{"udp://127.0.0.1:1"}, true, "failover")
	r.upstreams = []*Upstream{upstream}
	var current atomic.Pointer[ForwardRoute]
	first, second := NewForwardRoute(100, nil), NewForwardRoute(101, nil)
	current.Store(first)
	r.SetRouteProvider(current.Load)
	firstResult := make(chan error, 1)
	query := encryptedFixtureQuery()
	go func() { _, err := r.Resolve(context.Background(), query, 3); firstResult <- err }()
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first flight never started")
	}
	current.Store(second)
	result, err := r.Resolve(context.Background(), query, 3)
	if err != nil || result.Msg.Answer[0].(*dns.A).A.String() != "203.0.113.2" {
		t.Fatalf("new generation joined old flight: %+v, %v", result, err)
	}
	releaseOnce.Do(func() { close(releaseFirst) })
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	first.Close()
	defer second.Close()
	cached, err := r.Resolve(context.Background(), query, 3)
	if err != nil || !cached.Cached || cached.Msg.Answer[0].(*dns.A).A.String() != "203.0.113.2" || calls.Load() != 2 {
		t.Fatalf("late old completion replaced the current answer: %+v, %v, calls=%d", cached, err, calls.Load())
	}
}

func TestResolverRetiredOrMissingRouteCannotServeOrSend(t *testing.T) {
	plain := &recordingUpstream{}
	r := newRouteTestResolver(t, []string{"udp://" + startRecordingUpstream(t, plain)}, true, "failover")
	var current atomic.Pointer[ForwardRoute]
	route := NewForwardRoute(3, nil)
	current.Store(route)
	r.SetRouteProvider(current.Load)
	query := encryptedFixtureQuery()
	if _, err := r.Resolve(context.Background(), query, 1); err != nil {
		t.Fatal(err)
	}
	route.Close()
	if _, err := r.Resolve(context.Background(), query, 1); !errors.Is(err, ErrForwardRouteRetired) {
		t.Fatalf("retired route served cached data: %v", err)
	}
	current.Store(nil)
	if _, err := r.Resolve(context.Background(), query, 1); !errors.Is(err, ErrForwardRouteUnavailable) {
		t.Fatalf("missing selection enabled legacy forwarding: %v", err)
	}
	if len(plain.queries()) != 1 {
		t.Fatal("a refused route sent a plaintext query")
	}
}

func TestResolverEncryptedRouteUsesRealTransportAndNeverLegacyFallback(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	plain := &recordingUpstream{}
	r := newRouteTestResolver(t, []string{"udp://" + startRecordingUpstream(t, plain)}, false, "failover")
	good := encryptedFixtureServer(t, "doh2", ca.issue(t, "dns.test", false), nil)
	bad := encryptedFixtureServer(t, "doh2", ca.issue(t, "wrong.test", false), nil)
	goodClient := encryptedFixtureClient(t, ca.roots, good)
	badClient := encryptedFixtureClient(t, ca.roots, bad)
	first, second := NewForwardRoute(1, goodClient), NewForwardRoute(2, badClient)
	var current atomic.Pointer[ForwardRoute]
	current.Store(first)
	r.SetRouteProvider(current.Load)
	result, err := r.Resolve(context.Background(), encryptedFixtureQuery(), 1)
	if err != nil || result.Upstream != "doh2" || result.Msg.Answer[0].(*dns.A).A.String() != "203.0.113.7" {
		t.Fatalf("encrypted route result = %+v, %v", result, err)
	}
	current.Store(second)
	first.Close()
	defer second.Close()
	if _, err := r.Resolve(context.Background(), encryptedFixtureQuery(), 1); err == nil {
		t.Fatal("failed TLS identity was accepted or bypassed")
	}
	if len(plain.queries()) != 0 {
		t.Fatal("encrypted success or failure reached a legacy plaintext forwarder")
	}
}

func TestResolverRouteRetirementWaitsForLosingRaceParticipants(t *testing.T) {
	loserEntered, releaseLoser := make(chan struct{}), make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(releaseLoser) }) })
	loser := routeFixtureHTTPUpstream(func(req *dns.Msg) (*dns.Msg, error) {
		close(loserEntered)
		<-releaseLoser // deliberately models a transport still unwinding cancellation
		reply := new(dns.Msg)
		reply.SetReply(req)
		return reply, nil
	})
	winner := routeFixtureHTTPUpstream(func(req *dns.Msg) (*dns.Msg, error) {
		<-loserEntered
		reply := new(dns.Msg)
		reply.SetReply(req)
		return reply, nil
	})
	r := newRouteTestResolver(t, []string{"udp://127.0.0.1:1"}, false, "race")
	r.upstreams = []*Upstream{winner, loser}
	route := NewForwardRoute(1, nil)
	r.SetRouteProvider(func() *ForwardRoute { return route })
	if _, err := r.Resolve(context.Background(), encryptedFixtureQuery(), 1); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { route.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("route retired while a losing transport was still running")
	case <-time.After(30 * time.Millisecond):
	}
	release.Do(func() { close(releaseLoser) })
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("route failed to drain the losing race")
	}
}

type routeFixtureRoundTripper func(*http.Request) (*http.Response, error)

func (f routeFixtureRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func routeFixtureHTTPUpstream(answer func(*dns.Msg) (*dns.Msg, error)) *Upstream {
	return &Upstream{Spec: "fixture://in-process", Protocol: "https", url: "https://fixture.invalid/dns-query",
		httpc: &http.Client{Transport: routeFixtureRoundTripper(func(r *http.Request) (*http.Response, error) {
			wire, err := io.ReadAll(io.LimitReader(r.Body, dns.MaxMsgSize))
			if err != nil {
				return nil, err
			}
			query := new(dns.Msg)
			if err := query.Unpack(wire); err != nil {
				return nil, err
			}
			reply, err := answer(query)
			if err != nil {
				return nil, err
			}
			wire, err = reply.Pack()
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/dns-message"}},
				Body: io.NopCloser(bytes.NewReader(wire))}, nil
		})}}
}
