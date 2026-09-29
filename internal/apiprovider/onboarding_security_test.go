package apiprovider

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestPrivateDestinationConsentNeverAllowsMetadataOrSpecialRanges(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "::1", "169.254.169.254", "::ffff:169.254.169.254", "fd00:ec2::254", "0.0.0.0", "100.64.0.1", "224.0.0.1", "ff02::1", "198.18.0.1", "2001:db8::1", "2002:7f00:1::", "64:ff9b::7f00:1"} {
		addr := netip.MustParseAddr(value)
		if !errors.Is(CheckDestinationAddress(addr, true), ErrBlockedAddress) {
			t.Errorf("private consent permitted forbidden %s", value)
		}
	}
	for _, value := range []string{"10.0.0.5", "192.168.1.5", "172.16.0.5", "fd12:3456::5"} {
		addr := netip.MustParseAddr(value)
		if CheckDestinationAddress(addr, false) == nil {
			t.Errorf("private %s worked without consent", value)
		}
		if err := CheckDestinationAddress(addr, true); err != nil {
			t.Errorf("approved internal %s refused: %v", value, err)
		}
	}
	if NewTransport(false).Proxy != nil || NewTransport(true).Proxy != nil {
		t.Fatal("environment proxy can bypass destination DNS checks")
	}
}

type securityTransport func(*http.Request) (*http.Response, error)

func (f securityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProviderTransportErrorsNeverExposeCredentialURLs(t *testing.T) {
	const secret = "credential-that-must-not-appear-123456"
	c := NewClient(ClientOptions{Timeout: time.Second, Transport: securityTransport(func(r *http.Request) (*http.Response, error) {
		// net/http additionally wraps this in url.Error, including r.URL.
		return nil, errors.New("failed request " + r.URL.String() + " " + secret)
	})})
	req, _ := http.NewRequest(http.MethodGet, "https://fixture-provider.example/lookup?apikey="+secret, nil)
	_, err := c.Do(context.Background(), req)
	if err == nil {
		t.Fatal("positive control did not fail")
	}
	for _, value := range []string{err.Error(), c.Stats().LastError} {
		if strings.Contains(value, secret) || strings.Contains(value, "apikey=") || strings.Contains(value, "https://") {
			t.Fatalf("credential-bearing transport URL exposed: %q", value)
		}
	}
}

func TestProviderBreakerDenialsHaveASeparateDenominator(t *testing.T) {
	c := NewClient(ClientOptions{Breaker: BreakerOptions{Threshold: 1, Cooldown: time.Hour}, Transport: securityTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("forbidden"))}, nil
	})})
	req, _ := http.NewRequest(http.MethodGet, "https://fixture-provider.example/lookup", nil)
	for i := 0; i < 11; i++ {
		_, _ = c.Do(context.Background(), req)
	}
	s := c.Stats()
	if s.Calls != 1 || s.Failures != 1 || s.Rejected != 10 || s.ErrorRate != 1 {
		t.Fatalf("inconsistent call denominator: %+v", s)
	}
}

type generationProvider struct {
	started chan context.Context
	release chan struct{}
	client  *Client
}

func (p *generationProvider) Descriptor() Descriptor { return Descriptor{Kind: "generation-test"} }

func (p *generationProvider) Reputation(ctx context.Context, _ Subject) (Verdict, error) {
	p.started <- ctx
	if p.client != nil {
		req, _ := http.NewRequest(http.MethodGet, "https://fixture-provider.example/lookup", nil)
		_, err := p.client.Do(ctx, req)
		return Verdict{Disposition: DispositionMalicious}, err
	}
	// Simulate a response that arrives even after cancellation. Commit guards
	// must reject it independently of a well-behaved HTTP transport.
	<-p.release
	return Verdict{Disposition: DispositionMalicious}, nil
}

func (p *generationProvider) Enrich(ctx context.Context, _ Subject) (Enrichment, error) {
	p.started <- ctx
	<-p.release
	return Enrichment{}, nil
}

type generationStore struct{ verdicts, enrichments atomic.Int64 }

func (s *generationStore) SaveVerdict(context.Context, string, string, Verdict, time.Time) error {
	s.verdicts.Add(1)
	return nil
}
func (s *generationStore) FreshVerdicts(context.Context, int) ([]StoredVerdict, error) {
	return nil, nil
}
func (s *generationStore) SaveEnrichment(context.Context, string, string, Enrichment, time.Time) error {
	s.enrichments.Add(1)
	return nil
}

func waitSecurityCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal("timed out waiting for fixture state")
	}
}

func TestRevokedProviderGenerationsCannotCommitLateResults(t *testing.T) {
	for _, mutation := range []string{"mode_off", "provider_reload", "credential_rotation", "enrichment_off"} {
		t.Run(mutation, func(t *testing.T) {
			st := &generationStore{}
			p := &generationProvider{started: make(chan context.Context, 1), release: make(chan struct{})}
			e := NewEngine(Options{Mode: ModeCacheOnly, Enrichment: true, Log: quietLog(), Store: st})
			inst := fakeInstance("provider", p, CapReputation, CapEnrichment)
			e.SetInstances([]*Instance{inst})
			e.Start(context.Background())
			t.Cleanup(e.Stop)
			kind := CapReputation
			if mutation == "enrichment_off" {
				kind = CapEnrichment
			}
			result := make(chan Verdict, 1)
			if !e.enqueue(task{instance: inst, subject: DomainSubject("private.example"), kind: kind, done: result}) {
				t.Fatal("fixture not queued")
			}
			var ctx context.Context
			select {
			case ctx = <-p.started:
			case <-time.After(time.Second):
				close(p.release)
				t.Fatal("fixture not started")
			}
			switch mutation {
			case "mode_off":
				e.SetMode(ModeOff)
			case "provider_reload":
				e.SetInstances([]*Instance{fakeInstance("provider", &fakeProvider{})})
			case "credential_rotation":
				e.InvalidateProvider("provider")
			case "enrichment_off":
				e.SetEnrichment(false)
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				close(p.release)
				t.Fatal("old request context was not cancelled")
			}
			close(p.release)
			waitSecurityCondition(t, func() bool { return e.Stats().Completed > 0 })
			if e.cache.Len() != 0 || st.verdicts.Load() != 0 || st.enrichments.Load() != 0 {
				t.Fatal("revoked response repopulated memory or durable cache")
			}
			if kind == CapReputation {
				select {
				case v := <-result:
					if v.Disposition != DispositionUnknown {
						t.Fatal("revoked verdict reached a waiting DNS caller")
					}
				default:
					t.Fatal("waiting caller did not receive an unknown result")
				}
			}
		})
	}
}

func TestRevocationCancelsRateLimiterWaitBeforeAnyRequest(t *testing.T) {
	var calls atomic.Int64
	c := NewClient(ClientOptions{Timeout: time.Second, RatePerMinute: 6000, Transport: securityTransport(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})})
	c.limiter.mu.Lock()
	c.limiter.tokens = 0
	c.limiter.refill = 1
	c.limiter.mu.Unlock()
	p := &generationProvider{started: make(chan context.Context, 1), client: c}
	e := engineWith(t, Options{Mode: ModeCacheOnly}, fakeInstance("provider", p))
	e.Consult(context.Background(), "policy", "queued.example")
	waitSecurityCondition(t, func() bool { return c.Limiter().Waited() > 0 })
	e.SetMode(ModeOff)
	c.limiter.mu.Lock()
	c.limiter.tokens = 1
	c.limiter.mu.Unlock()
	waitSecurityCondition(t, func() bool { return e.Stats().Completed > 0 })
	if calls.Load() != 0 {
		t.Fatal("revoked limiter wait reached transport")
	}
}

func TestResolvedPrivateHostnameIsBlockedAtActualDial(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsServer := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		if len(q.Question) > 0 && q.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.ParseIP("127.0.0.1")}}
		}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = dnsServer.ActivateAndServe() }()
	defer dnsServer.Shutdown()
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", packet.LocalAddr().String())
	}}
	defer func() { net.DefaultResolver = original }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ValidateEndpoint("https://rebinding.example/lookup", false); err != nil {
		t.Fatalf("configuration validation unexpectedly resolved a host: %v", err)
	}
	_, err = NewTransport(false).DialContext(ctx, "tcp", "rebinding.example:443")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("hostname resolving to loopback bypassed per-connection check: %v", err)
	}
}

func TestDisablingProvidersCancelsQueuedWorkBeforeNetwork(t *testing.T) {
	p := &fakeProvider{verdict: Verdict{Disposition: DispositionBenign}}
	e := NewEngine(Options{Mode: ModeCacheOnly, Log: quietLog()})
	e.SetInstances([]*Instance{fakeInstance("provider", p)})
	e.Consult(context.Background(), "p_standard", "queued.example")
	if e.Stats().Enqueued == 0 {
		t.Fatal("positive control failed to queue work")
	}
	e.SetMode(ModeOff)
	e.Start(context.Background())
	defer e.Stop()
	deadline := time.Now().Add(time.Second)
	for e.Stats().Completed == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if e.Stats().Completed == 0 || p.calls.Load() != 0 {
		t.Fatal("revoked mode still sent queued provider work")
	}
}
