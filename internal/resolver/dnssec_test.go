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

// recordingUpstream answers everything with a fixed A record and remembers
// what it was asked, so the outgoing query can be inspected.
type recordingUpstream struct {
	mu       sync.Mutex
	received []*dns.Msg
	// setAD makes the upstream behave like a validating resolver.
	setAD bool
	rcode int
}

func (u *recordingUpstream) queries() []*dns.Msg {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]*dns.Msg(nil), u.received...)
}

func startRecordingUpstream(t *testing.T, u *recordingUpstream) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			u.mu.Lock()
			u.received = append(u.received, req.Copy())
			u.mu.Unlock()

			m := new(dns.Msg)
			m.SetReply(req)
			if u.rcode != 0 {
				m.Rcode = u.rcode
			}
			m.AuthenticatedData = u.setAD
			if m.Rcode == dns.RcodeSuccess && len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
				m.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name: req.Question[0].Name, Rrtype: dns.TypeA,
						Class: dns.ClassINET, Ttl: 300,
					},
					A: net.IPv4(203, 0, 113, 5),
				}}
			}
			_ = w.WriteMsg(m)
		}),
	}

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go srv.ActivateAndServe() //nolint:errcheck // shutdown returns the error

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("test upstream did not start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })

	return pc.LocalAddr().String()
}

func newTestResolver(t *testing.T, addr string, dnssecTelemetry bool) *Resolver {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r, err := New(config.DNS{
		Upstreams:       []string{"udp://" + addr},
		UpstreamMode:    "failover",
		Timeout:         config.Duration(2 * time.Second),
		DNSSECTelemetry: dnssecTelemetry,
	}, config.Cache{Enabled: false}, log)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestDNSSECTelemetryRequestsADBit(t *testing.T) {
	up := &recordingUpstream{setAD: true}
	addr := startRecordingUpstream(t, up)
	r := newTestResolver(t, addr, true)

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)

	res, err := r.Resolve(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	sent := up.queries()
	if len(sent) != 1 {
		t.Fatalf("upstream saw %d queries, want 1", len(sent))
	}
	if !sent[0].AuthenticatedData {
		t.Error("outgoing query did not set the AD bit, so the upstream has no reason to report its verdict")
	}
	// RFC 6840 §5.7's AD-in-query signal must not turn into a DO-bit request:
	// that would ask for DNSSEC records and inflate every response.
	if opt := sent[0].IsEdns0(); opt != nil && opt.Do() {
		t.Error("outgoing query set the DO bit; telemetry must not inflate response sizes")
	}

	if !res.Validated {
		t.Error("upstream set AD but the result did not record it as validated")
	}
	if res.MinTTL != 300 {
		t.Errorf("MinTTL = %d, want 300", res.MinTTL)
	}
	if res.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d", res.Rcode)
	}
}

func TestDNSSECTelemetryCanBeDisabled(t *testing.T) {
	up := &recordingUpstream{setAD: true}
	addr := startRecordingUpstream(t, up)
	r := newTestResolver(t, addr, false)

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)
	if _, err := r.Resolve(context.Background(), req, 1); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	sent := up.queries()
	if len(sent) != 1 {
		t.Fatalf("upstream saw %d queries", len(sent))
	}
	if sent[0].AuthenticatedData {
		t.Error("AD bit was set with dnssec_telemetry off")
	}
}

// A client that did not ask about DNSSEC must not be told its answer was
// authenticated (RFC 4035 §3.2.3). Because telemetry now sets AD on every
// upstream query, this stripping is what keeps the wire response correct.
func TestADBitStrippedForClientsThatDidNotAsk(t *testing.T) {
	up := &recordingUpstream{setAD: true}
	addr := startRecordingUpstream(t, up)
	r := newTestResolver(t, addr, true)

	t.Run("plain query", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("www.example.com.", dns.TypeA)

		res, err := r.Resolve(context.Background(), req, 1)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Msg.AuthenticatedData {
			t.Error("AD bit was passed to a client that set neither DO nor AD")
		}
		// The telemetry still recorded it.
		if !res.Validated {
			t.Error("validation status was lost along with the bit")
		}
	})

	t.Run("client sets AD", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("www.example.com.", dns.TypeA)
		req.AuthenticatedData = true

		res, err := r.Resolve(context.Background(), req, 1)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if !res.Msg.AuthenticatedData {
			t.Error("AD bit was stripped from a client that asked for it")
		}
	})

	t.Run("client sets DO", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("www.example.com.", dns.TypeA)
		req.SetEdns0(4096, true)

		res, err := r.Resolve(context.Background(), req, 1)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if !res.Msg.AuthenticatedData {
			t.Error("AD bit was stripped from a DNSSEC-aware client")
		}
	})
}

func TestResultReportsUpstreamRcode(t *testing.T) {
	up := &recordingUpstream{rcode: dns.RcodeServerFailure}
	addr := startRecordingUpstream(t, up)
	r := newTestResolver(t, addr, true)

	req := new(dns.Msg)
	req.SetQuestion("broken.example.com.", dns.TypeA)

	res, err := r.Resolve(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Rcode != dns.RcodeServerFailure {
		t.Errorf("Rcode = %d, want SERVFAIL", res.Rcode)
	}
	if res.Validated {
		t.Error("a SERVFAIL was reported as validated")
	}
	if res.MinTTL != 0 {
		t.Errorf("MinTTL = %d on a response with no answer, want 0", res.MinTTL)
	}
}

// Cached answers must report the same DNSSEC status as the live ones, or the
// telemetry would silently depend on cache state.
func TestCachedAnswersRetainValidationStatus(t *testing.T) {
	up := &recordingUpstream{setAD: true}
	addr := startRecordingUpstream(t, up)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r, err := New(config.DNS{
		Upstreams:       []string{"udp://" + addr},
		UpstreamMode:    "failover",
		Timeout:         config.Duration(2 * time.Second),
		DNSSECTelemetry: true,
	}, config.Cache{Enabled: true, MaxEntries: 10, MinTTL: 1, MaxTTL: 300, NegativeTTL: 10}, log)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}
	t.Cleanup(r.Close)

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)

	first, err := r.Resolve(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	second, err := r.Resolve(context.Background(), req, 1)
	if err != nil {
		t.Fatalf("Resolve (cached): %v", err)
	}

	if !second.Cached {
		t.Fatal("second lookup did not hit the cache")
	}
	if second.Validated != first.Validated {
		t.Errorf("cached validation status = %v, live = %v", second.Validated, first.Validated)
	}
	if second.MinTTL == 0 {
		t.Error("cached result lost its TTL")
	}
	// And the wire response is still stripped for a client that did not ask.
	if second.Msg.AuthenticatedData {
		t.Error("cached AD bit leaked to a client that did not request it")
	}
}
