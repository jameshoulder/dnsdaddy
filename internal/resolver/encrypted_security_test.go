package resolver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2/hpack"
)

// These fixtures use a generated, isolated trust root. Every connection is to
// loopback through explicit bootstrap addresses; no test needs public DNS, a
// vendor endpoint, or an operator's credentials.
type encryptedFixtureCA struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
	roots       *x509.CertPool
}

func newEncryptedFixtureCA(t *testing.T) encryptedFixtureCA {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "DNS Daddy encrypted transport fixture CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return encryptedFixtureCA{certificate: certificate, key: private, roots: roots}
}

func (ca encryptedFixtureCA) issue(t *testing.T, name string, expired bool) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	notBefore, notAfter := now.Add(-time.Hour), now.Add(time.Hour)
	if expired {
		notBefore, notAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, public, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.certificate.Raw}, PrivateKey: private, Leaf: leaf}
}

func encryptedFixtureQuery() *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion("encrypted-fixture.test.", dns.TypeA)
	query.Id = 0xbeef
	query.CheckingDisabled = true
	query.SetEdns0(1232, true)
	return query
}

func encryptedFixtureReply(t *testing.T, query *dns.Msg) []byte {
	t.Helper()
	reply := new(dns.Msg)
	reply.SetReply(query)
	reply.RecursionAvailable = true
	reply.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(203, 0, 113, 7),
	}}
	wire, err := reply.Pack()
	if err != nil {
		t.Errorf("pack fixture reply: %v", err)
	}
	return wire
}

func encryptedFixtureFrame(wire []byte) []byte {
	// DNS wire messages in these fixtures are all below 64 KiB.
	if len(wire) > 65535 {
		panic("fixture DNS message exceeds its two-byte framing limit")
	}
	framed := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(wire)))
	copy(framed[2:], wire)
	return framed
}

func encryptedFixtureEndpoint(t *testing.T, protocol, address string) EncryptedEndpoint {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	endpointAddress := net.JoinHostPort("dns.test", port)
	if protocol != "doq" {
		endpointAddress = "https://" + endpointAddress + "/dns-query"
	}
	return EncryptedEndpoint{
		Protocol: protocol, Address: endpointAddress, ServerName: "dns.test",
		BootstrapIPs: []string{"127.0.0.1"},
	}
}

type encryptedFixtureResponder func(context.Context, *dns.Msg) []byte

func encryptedFixtureDoQ(t *testing.T, certificate tls.Certificate, responder encryptedFixtureResponder, observeConnection ...func(quic.ConnectionState)) EncryptedEndpoint {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: []string{"doq"},
	}, &quic.Config{HandshakeIdleTimeout: time.Second, MaxIdleTimeout: 5 * time.Second, MaxIncomingStreams: 16})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			connection, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.CloseWithError(0, "fixture finished")
				state := connection.ConnectionState()
				if state.TLS.Version != tls.VersionTLS13 {
					t.Error("DoQ connection did not negotiate TLS 1.3")
				}
				for _, observe := range observeConnection {
					observe(state)
				}
				for {
					stream, err := connection.AcceptStream(ctx)
					if err != nil {
						return
					}
					workers.Add(1)
					go func() {
						defer workers.Done()
						defer stream.Close()
						_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
						var prefix [2]byte
						if _, err := io.ReadFull(stream, prefix[:]); err != nil {
							return
						}
						wire := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
						if _, err := io.ReadFull(stream, wire); err != nil {
							return
						}
						query := new(dns.Msg)
						if err := query.Unpack(wire); err != nil {
							t.Errorf("unpack DoQ request: %v", err)
							return
						}
						var extra [1]byte
						if n, err := stream.Read(extra[:]); n != 0 || err != io.EOF {
							t.Errorf("DoQ request must contain one frame followed by FIN; extra=%d, err=%v", n, err)
							return
						}
						requestCtx, requestCancel := context.WithCancel(ctx)
						stop := context.AfterFunc(stream.Context(), requestCancel)
						defer stop()
						defer requestCancel()
						var response []byte
						if responder != nil {
							response = responder(requestCtx, query)
						} else {
							response = encryptedFixtureFrame(encryptedFixtureReply(t, query))
						}
						if response != nil {
							_, _ = stream.Write(response)
						}
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("DoQ fixture did not stop its workers")
		}
	})
	return encryptedFixtureEndpoint(t, "doq", listener.Addr().String())
}

func encryptedFixtureHTTP(t *testing.T, protocol string, certificate tls.Certificate, handler http.Handler) EncryptedEndpoint {
	t.Helper()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	if protocol == "doh2" {
		server := httptest.NewUnstartedServer(handler)
		server.EnableHTTP2 = true
		server.TLS = tlsConfig
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.StartTLS()
		t.Cleanup(server.Close)
		return encryptedFixtureEndpoint(t, protocol, server.Listener.Addr().String())
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig: tlsConfig, Handler: handler,
		QUICConfig: &quic.Config{HandshakeIdleTimeout: time.Second, MaxIdleTimeout: 5 * time.Second},
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(packetConn) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = packetConn.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("HTTP/3 fixture did not stop")
		}
	})
	return encryptedFixtureEndpoint(t, protocol, packetConn.LocalAddr().String())
}

func encryptedFixtureServer(t *testing.T, protocol string, certificate tls.Certificate, responder encryptedFixtureResponder) EncryptedEndpoint {
	t.Helper()
	if protocol == "doq" {
		return encryptedFixtureDoQ(t, certificate, func(ctx context.Context, query *dns.Msg) []byte {
			if responder == nil {
				return encryptedFixtureFrame(encryptedFixtureReply(t, query))
			}
			wire := responder(ctx, query)
			if wire == nil {
				return nil
			}
			return encryptedFixtureFrame(wire)
		})
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantMajor := 2
		if protocol == "doh3" {
			wantMajor = 3
		}
		if r.ProtoMajor != wantMajor || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			t.Errorf("%s negotiated %s, TLS=%+v", protocol, r.Proto, r.TLS)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" {
			t.Errorf("unexpected DoH request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/dns-message" {
			t.Errorf("request content type = %q", r.Header.Get("Content-Type"))
		}
		wire, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			t.Errorf("unpack DoH query: %v", err)
			return
		}
		if responder == nil {
			wire = encryptedFixtureReply(t, query)
		} else {
			wire = responder(r.Context(), query)
		}
		if wire == nil {
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	})
	return encryptedFixtureHTTP(t, protocol, certificate, handler)
}

func encryptedFixtureClient(t *testing.T, roots *x509.CertPool, endpoints ...EncryptedEndpoint) *EncryptedUpstreams {
	t.Helper()
	client, err := newEncryptedUpstreamsWithRoots(endpoints, 2*time.Second, roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close encrypted client: %v", err)
		}
	})
	return client
}

func TestEncryptedFixtureRoundTrip(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	certificate := ca.issue(t, "dns.test", false)
	for _, protocol := range []string{"doq", "doh3", "doh2"} {
		t.Run(protocol, func(t *testing.T) {
			observed := make(chan *dns.Msg, 1)
			endpoint := encryptedFixtureServer(t, protocol, certificate, func(_ context.Context, query *dns.Msg) []byte {
				observed <- query.Copy()
				return encryptedFixtureReply(t, query)
			})
			client := encryptedFixtureClient(t, ca.roots, endpoint)
			query := encryptedFixtureQuery()
			before := query.Copy()
			reply, err := client.Exchange(context.Background(), query)
			if err != nil {
				t.Fatal(err)
			}
			if reply == nil || reply.Id != before.Id || !reply.Response || len(reply.Answer) != 1 {
				t.Fatalf("unexpected restored response: %s", reply)
			}
			answer, ok := reply.Answer[0].(*dns.A)
			if !ok || !answer.A.Equal(net.IPv4(203, 0, 113, 7)) {
				t.Fatalf("unexpected restored answer: %s", reply.Answer[0])
			}
			if query.String() != before.String() {
				t.Fatal("Exchange mutated the caller's request")
			}
			wireQuery := <-observed
			if wireQuery.Id != 0 || !wireQuery.CheckingDisabled || !wireQuery.RecursionDesired || wireQuery.IsEdns0() == nil || !wireQuery.IsEdns0().Do() {
				t.Fatalf("wire query lost ID normalization or DNS flags: %s", wireQuery)
			}
			if wireQuery.Question[0] != before.Question[0] {
				t.Fatalf("wire question = %+v, want %+v", wireQuery.Question, before.Question)
			}
			stats := client.Stats()
			if stats.Queries != 1 || stats.Successes != 1 || stats.Failures != 0 || stats.InFlight != 0 {
				t.Fatalf("unexpected successful-exchange stats: %+v", stats)
			}
		})
	}
}

func TestEncryptedFixtureRejectsUnauthenticatedServer(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	for _, protocol := range []string{"doq", "doh3", "doh2"} {
		for _, failure := range []string{"untrusted", "wrong-name", "expired"} {
			t.Run(protocol+"/"+failure, func(t *testing.T) {
				name := "dns.test"
				if failure == "wrong-name" {
					name = "another-resolver.test"
				}
				roots := ca.roots
				if failure == "untrusted" {
					roots = x509.NewCertPool()
				}
				certificate := ca.issue(t, name, failure == "expired")
				var payloads atomic.Int64
				endpoint := encryptedFixtureServer(t, protocol, certificate, func(_ context.Context, query *dns.Msg) []byte {
					payloads.Add(1)
					return encryptedFixtureReply(t, query)
				})
				client := encryptedFixtureClient(t, roots, endpoint)
				reply, err := client.Exchange(context.Background(), encryptedFixtureQuery())
				if err == nil || reply != nil {
					t.Fatalf("unacceptable certificate returned a DNS response: reply=%v, err=%v", reply, err)
				}
				// An unrelated connection failure must not make a negative TLS
				// test pass. Preserve and inspect the actual verification cause.
				switch failure {
				case "untrusted":
					var cause x509.UnknownAuthorityError
					if !errors.As(err, &cause) {
						t.Fatalf("expected untrusted-root rejection, got %v", err)
					}
				case "wrong-name":
					var cause x509.HostnameError
					if !errors.As(err, &cause) {
						t.Fatalf("expected identity rejection, got %v", err)
					}
				case "expired":
					var cause x509.CertificateInvalidError
					if !errors.As(err, &cause) || cause.Reason != x509.Expired {
						t.Fatalf("expected expiry rejection, got %v", err)
					}
				}
				if payloads.Load() != 0 {
					t.Fatalf("sent %d DNS payloads to an unauthenticated server", payloads.Load())
				}
				stats := client.Stats()
				if stats.Queries != 1 || stats.Successes != 0 || stats.Failures != 1 || stats.InFlight != 0 {
					t.Fatalf("unexpected certificate-failure stats: %+v", stats)
				}
			})
		}
	}
}

func TestEncryptedFixtureDoQRejectsMalformedResponses(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	certificate := ca.issue(t, "dns.test", false)
	for _, failure := range []string{"short-prefix", "zero-length", "short-body", "extra-byte", "two-responses", "nonzero-id", "wrong-question", "not-a-response"} {
		t.Run(failure, func(t *testing.T) {
			endpoint := encryptedFixtureDoQ(t, certificate, func(_ context.Context, query *dns.Msg) []byte {
				wire := encryptedFixtureReply(t, query)
				framed := encryptedFixtureFrame(wire)
				switch failure {
				case "short-prefix":
					return framed[:1]
				case "zero-length":
					return []byte{0, 0}
				case "short-body":
					return framed[:len(framed)-1]
				case "extra-byte":
					return append(framed, 0)
				case "two-responses":
					return append(framed, framed...)
				case "nonzero-id":
					wire[1] = 1
				case "wrong-question":
					modified := query.Copy()
					modified.Question[0].Name = "substituted.test."
					wire = encryptedFixtureReply(t, modified)
				case "not-a-response":
					wire[2] &^= 0x80
				}
				return encryptedFixtureFrame(wire)
			})
			client := encryptedFixtureClient(t, ca.roots, endpoint)
			if reply, err := client.Exchange(context.Background(), encryptedFixtureQuery()); err == nil || reply != nil {
				t.Fatalf("malformed DoQ response accepted: reply=%v, err=%v", reply, err)
			}
			stats := client.Stats()
			if stats.Successes != 0 || stats.Failures != 1 || stats.InFlight != 0 {
				t.Fatalf("unexpected malformed-response stats: %+v", stats)
			}
		})
	}
}

func TestEncryptedFixtureCancellationAndClose(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	certificate := ca.issue(t, "dns.test", false)
	for _, protocol := range []string{"doq", "doh3", "doh2"} {
		for _, operation := range []string{"cancel", "close"} {
			t.Run(protocol+"/"+operation, func(t *testing.T) {
				started := make(chan struct{})
				var startOnce sync.Once
				endpoint := encryptedFixtureServer(t, protocol, certificate, func(ctx context.Context, _ *dns.Msg) []byte {
					startOnce.Do(func() { close(started) })
					<-ctx.Done()
					return nil
				})
				client := encryptedFixtureClient(t, ca.roots, endpoint)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				result := make(chan error, 1)
				go func() {
					_, err := client.Exchange(ctx, encryptedFixtureQuery())
					result <- err
				}()
				select {
				case <-started:
				case err := <-result:
					t.Fatalf("exchange finished before fixture received request: %v", err)
				case <-time.After(3 * time.Second):
					t.Fatal("fixture did not receive request")
				}
				if operation == "cancel" {
					cancel()
				} else {
					closed := make(chan error, 1)
					go func() { closed <- client.Close() }()
					select {
					case err := <-closed:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(time.Second):
						t.Fatal("Close did not cancel active encrypted exchange")
					}
				}
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("cancelled exchange unexpectedly succeeded")
					}
				case <-time.After(time.Second):
					t.Fatal("encrypted exchange ignored cancellation")
				}
				if stats := client.Stats(); stats.InFlight != 0 || stats.Successes != 0 {
					t.Fatalf("cancelled exchange retained active work: %+v", stats)
				}
			})
		}
	}
}

func TestEncryptedFixtureDoHRejectsRedirect(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	certificate := ca.issue(t, "dns.test", false)
	for _, protocol := range []string{"doh3", "doh2"} {
		t.Run(protocol, func(t *testing.T) {
			var plaintextRequests atomic.Int64
			plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				plaintextRequests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer plaintext.Close()
			endpoint := encryptedFixtureHTTP(t, protocol, certificate, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, plaintext.URL+"/dns-query", http.StatusTemporaryRedirect)
			}))
			client := encryptedFixtureClient(t, ca.roots, endpoint)
			if reply, err := client.Exchange(context.Background(), encryptedFixtureQuery()); err == nil || reply != nil {
				t.Fatalf("redirect accepted: reply=%v, err=%v", reply, err)
			}
			if plaintextRequests.Load() != 0 {
				t.Fatal("DoH redirect leaked a request onto plaintext HTTP")
			}
		})
	}
}

func TestEncryptedFixtureDoH2RequiresTLS13(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	var payloads atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payloads.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	server.EnableHTTP2 = true
	// This deliberately old-only server verifies that the strict transport
	// cannot downgrade its TLS version even with an otherwise trusted identity.
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.issue(t, "dns.test", false)},
		MinVersion:   tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
	}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	client := encryptedFixtureClient(t, ca.roots, encryptedFixtureEndpoint(t, "doh2", server.Listener.Addr().String()))
	if reply, err := client.Exchange(context.Background(), encryptedFixtureQuery()); err == nil || reply != nil {
		t.Fatalf("TLS 1.2 downgrade accepted: reply=%v, err=%v", reply, err)
	}
	if payloads.Load() != 0 {
		t.Fatal("strict transport sent a DNS payload over TLS 1.2")
	}
}

func TestEncryptedFixtureFailoverStaysAuthenticated(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	var rejectedPayloads, acceptedPayloads atomic.Int64
	bad := encryptedFixtureServer(t, "doh3", ca.issue(t, "wrong.test", false), func(_ context.Context, query *dns.Msg) []byte {
		rejectedPayloads.Add(1)
		return encryptedFixtureReply(t, query)
	})
	good := encryptedFixtureServer(t, "doh2", ca.issue(t, "dns.test", false), func(_ context.Context, query *dns.Msg) []byte {
		acceptedPayloads.Add(1)
		return encryptedFixtureReply(t, query)
	})
	client := encryptedFixtureClient(t, ca.roots, bad, good)
	reply, err := client.Exchange(context.Background(), encryptedFixtureQuery())
	if err != nil {
		t.Fatal(err)
	}
	if reply.Id != 0xbeef || rejectedPayloads.Load() != 0 || acceptedPayloads.Load() != 1 {
		t.Fatalf("unexpected encrypted failover: reply=%v, rejected payloads=%d, accepted payloads=%d", reply, rejectedPayloads.Load(), acceptedPayloads.Load())
	}
	stats := client.Stats()
	if stats.Queries != 1 || stats.Successes != 1 || stats.Failures != 0 || stats.Failovers != 1 || stats.InFlight != 0 {
		t.Fatalf("unexpected failover accounting: %+v", stats)
	}
}

func TestEncryptedFixtureDoHRejectsInvalidEnvelope(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	certificate := ca.issue(t, "dns.test", false)
	for _, protocol := range []string{"doh3", "doh2"} {
		for _, failure := range []string{"wrong-content-type", "oversized", "trailing-data"} {
			t.Run(protocol+"/"+failure, func(t *testing.T) {
				endpoint := encryptedFixtureHTTP(t, protocol, certificate, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/dns-message")
					query := encryptedFixtureQuery()
					query.Id = 0
					wire := encryptedFixtureReply(t, query)
					switch failure {
					case "wrong-content-type":
						w.Header().Set("Content-Type", "text/html")
					case "oversized":
						wire = []byte(strings.Repeat("x", 65536))
					case "trailing-data":
						wire = append(wire, 0)
					}
					_, _ = w.Write(wire)
				}))
				client := encryptedFixtureClient(t, ca.roots, endpoint)
				if reply, err := client.Exchange(context.Background(), encryptedFixtureQuery()); err == nil || reply != nil {
					t.Fatalf("invalid DoH envelope accepted: reply=%v, err=%v", reply, err)
				}
			})
		}
	}
}

// Return a field list whose decoded HTTP size exceeds 32 KiB while its HPACK
// or QPACK representation stays below the 16 KiB response limit. A lone large
// literal might hit the encoded-frame limit first and miss decoder regressions.
func encryptedFixtureOversizedFields(t *testing.T, protocol string) []string {
	t.Helper()
	const name, value = "x-dns-padding", "a"
	const fieldSize = len(name) + len(value) + 32
	const copies = ((32 << 10) + fieldSize - 1) / fieldSize
	values := make([]string, copies)
	var encoded bytes.Buffer
	if protocol == "doh3" {
		encoder := qpack.NewEncoder(&encoded)
		for i := range values {
			values[i] = value
			if err := encoder.WriteField(qpack.HeaderField{Name: name, Value: value}); err != nil {
				t.Fatal(err)
			}
		}
	} else {
		encoder := hpack.NewEncoder(&encoded)
		for i := range values {
			values[i] = value
			if err := encoder.WriteField(hpack.HeaderField{Name: name, Value: value}); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Reserve space for ordinary status/content-type/date fields as well.
	if encoded.Len()+1024 >= maxEncryptedHeaderBytes || copies*fieldSize <= maxEncryptedHeaderBytes {
		t.Fatalf("fixture misses decoded-header boundary: encoded=%d, decoded=%d, limit=%d", encoded.Len(), copies*fieldSize, maxEncryptedHeaderBytes)
	}
	t.Logf("compressed padding=%d bytes; decoded padding=%d bytes; response field limit=%d bytes", encoded.Len(), copies*fieldSize, maxEncryptedHeaderBytes)
	return values
}

func TestEncryptedFixtureDoHRejectsOversizedDecodedFields(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	certificate := ca.issue(t, "dns.test", false)
	for _, protocol := range []string{"doh3", "doh2"} {
		for _, section := range []string{"headers", "trailers", "unannounced-trailers"} {
			t.Run(protocol+"/"+section, func(t *testing.T) {
				values := encryptedFixtureOversizedFields(t, protocol)
				var requests atomic.Int64
				endpoint := encryptedFixtureHTTP(t, protocol, certificate, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					w.Header().Set("Content-Type", "application/dns-message")
					if section == "headers" {
						w.Header()["X-Dns-Padding"] = values
					} else if section == "trailers" {
						w.Header().Set("Trailer", "X-Dns-Padding")
					}
					query := encryptedFixtureQuery()
					query.Id = 0
					_, _ = w.Write(encryptedFixtureReply(t, query))
					if section == "trailers" {
						w.Header()["X-Dns-Padding"] = values
					} else if section == "unannounced-trailers" {
						// No declaration in the initial response headers: this
						// requires the response body/trailer read to reject it.
						w.Header()[http.TrailerPrefix+"X-Dns-Padding"] = values
					}
				}))
				client := encryptedFixtureClient(t, ca.roots, endpoint)
				reply, err := client.Exchange(context.Background(), encryptedFixtureQuery())
				if err == nil || reply != nil {
					t.Fatalf("oversized decoded %s accepted: reply=%v, err=%v", section, reply, err)
				}
				var timeout net.Error
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || (errors.As(err, &timeout) && timeout.Timeout()) {
					t.Fatalf("fixture timed out instead of rejecting oversized %s: %v", section, err)
				}
				if requests.Load() != 1 {
					t.Fatalf("expected one authenticated fixture request, got %d", requests.Load())
				}
				if stats := client.Stats(); stats.Failures != 1 || stats.Successes != 0 || stats.InFlight != 0 {
					t.Fatalf("oversized response accounting: %+v", stats)
				}
			})
		}
	}
}

func TestEncryptedFixtureDoQReusesConnectionWithOutOfOrderResponses(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	const concurrent = 8
	var connections, earlyDataConnections atomic.Int64
	arrived := make(chan int, concurrent)
	release := make([]chan struct{}, concurrent)
	queries := make([]*dns.Msg, concurrent)
	indexByName := make(map[string]int, concurrent)
	for i := range concurrent {
		release[i] = make(chan struct{})
		queries[i] = encryptedFixtureQuery()
		queries[i].Question[0].Name = fmt.Sprintf("parallel-%d.encrypted-fixture.test.", i)
		queries[i].Id = uint16(i + 1)
		indexByName[queries[i].Question[0].Name] = i
	}
	endpoint := encryptedFixtureDoQ(t, ca.issue(t, "dns.test", false), func(ctx context.Context, query *dns.Msg) []byte {
		if i, parallel := indexByName[query.Question[0].Name]; parallel {
			arrived <- i
			select {
			case <-release[i]:
			case <-ctx.Done():
				return nil
			}
		}
		return encryptedFixtureFrame(encryptedFixtureReply(t, query))
	}, func(state quic.ConnectionState) {
		connections.Add(1)
		if state.Used0RTT {
			earlyDataConnections.Add(1)
		}
	})
	client := encryptedFixtureClient(t, ca.roots, endpoint)
	if _, err := client.Exchange(context.Background(), encryptedFixtureQuery()); err != nil {
		t.Fatalf("initial exchange: %v", err)
	}
	type result struct {
		index int
		reply *dns.Msg
		err   error
	}
	results := make(chan result, concurrent)
	for i := range concurrent {
		go func() {
			reply, err := client.Exchange(context.Background(), queries[i])
			results <- result{index: i, reply: reply, err: err}
		}()
	}
	arrivalOrder := make([]int, 0, concurrent)
	for range concurrent {
		select {
		case i := <-arrived:
			arrivalOrder = append(arrivalOrder, i)
		case failed := <-results:
			t.Fatalf("request %d finished before its response was released: %v", failed.index, failed.err)
		case <-time.After(3 * time.Second):
			t.Fatal("DoQ did not admit concurrent streams on the established connection")
		}
	}
	// Release one stream at a time in reverse arrival order. No sleeps or
	// scheduler assumptions are needed to prove independent stream responses.
	for i := len(arrivalOrder) - 1; i >= 0; i-- {
		index := arrivalOrder[i]
		close(release[index])
		select {
		case got := <-results:
			if got.err != nil || got.index != index || got.reply == nil {
				t.Fatalf("out-of-order stream result: index=%d, expected=%d, reply=%v, err=%v", got.index, index, got.reply, got.err)
			}
			if got.reply.Id != queries[index].Id || len(got.reply.Question) != 1 || got.reply.Question[0] != queries[index].Question[0] {
				t.Fatalf("DoQ mixed responses between streams: %s", got.reply)
			}
		case <-time.After(time.Second):
			t.Fatalf("released stream %d was blocked by another outstanding stream", index)
		}
	}
	if _, err := client.Exchange(context.Background(), encryptedFixtureQuery()); err != nil {
		t.Fatalf("exchange after concurrent batch: %v", err)
	}
	if connections.Load() != 1 || earlyDataConnections.Load() != 0 {
		t.Fatalf("expected one reused handshake and no observed early data; connections=%d, 0-RTT=%d", connections.Load(), earlyDataConnections.Load())
	}
	stats := client.Stats()
	if stats.Queries != concurrent+2 || stats.Successes != concurrent+2 || stats.Failures != 0 || stats.InFlight != 0 || len(stats.Endpoints) != 1 || stats.Endpoints[0].ConnectionsOpened != 1 {
		t.Fatalf("unexpected concurrent/reused connection stats: %+v", stats)
	}
}

func TestEncryptedFixtureTLSCloseReleasesOwnershipWhenPeerStopsReading(t *testing.T) {
	ca := newEncryptedFixtureCA(t)
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()
	clientTLS := tls.Client(clientPipe, &tls.Config{
		RootCAs: ca.roots, ServerName: "dns.test", MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
	})
	serverTLS := tls.Server(serverPipe, &tls.Config{
		Certificates: []tls.Certificate{ca.issue(t, "dns.test", false)},
		MinVersion:   tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	serverHandshake := make(chan error, 1)
	go func() { serverHandshake <- serverTLS.HandshakeContext(ctx) }()
	if err := clientTLS.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverHandshake; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	// No goroutine reads serverPipe after this point. net.Pipe has no write
	// buffering, so a graceful TLS close_notify is deterministically blocked.
	// The wrapper must force the raw connection closed instead of inheriting
	// crypto/tls's five-second graceful-close timeout.
	endpoint := &encryptedEndpoint{
		tlsSlots: make(chan struct{}, maxEncryptedTLSConnections),
		tlsConns: make(map[*encryptedTLSConn]struct{}),
	}
	socket := &encryptedTLSConn{Conn: clientTLS, endpoint: endpoint}
	endpoint.tlsSlots <- struct{}{}
	endpoint.tlsConns[socket] = struct{}{}
	const callers = 8
	ready, start := make(chan struct{}, callers), make(chan struct{})
	closed := make(chan error, callers)
	for range callers {
		go func() {
			ready <- struct{}{}
			<-start
			closed <- socket.Close()
		}()
	}
	for range callers {
		<-ready
	}
	close(start)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	var firstErr error
	for i := range callers {
		select {
		case err := <-closed:
			if i == 0 {
				firstErr = err
			} else if (err == nil) != (firstErr == nil) || (err != nil && err.Error() != firstErr.Error()) {
				t.Fatalf("concurrent Close callers observed inconsistent results: first=%v, later=%v", firstErr, err)
			}
		case <-deadline.C:
			// Unblock the fixture even when running against the regressed
			// implementation so the negative test does not leave workers.
			_ = clientPipe.Close()
			_ = serverPipe.Close()
			t.Fatal("owned TLS Close exceeded one second with an unread close_notify")
		}
	}
	endpoint.connMu.Lock()
	tracked := len(endpoint.tlsConns)
	endpoint.connMu.Unlock()
	if tracked != 0 || len(endpoint.tlsSlots) != 0 {
		t.Fatalf("Close retained TLS ownership: tracked sockets=%d, occupied slots=%d", tracked, len(endpoint.tlsSlots))
	}
}
