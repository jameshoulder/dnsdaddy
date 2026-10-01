package resolver

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func legacyDoHFixture(t *testing.T, handler http.Handler) *Upstream {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	u, err := ParseUpstream(server.URL+"/dns-query", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Authenticate only this fixture's certificate; verification remains on.
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	u.httpc.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
	t.Cleanup(u.Close)
	return u
}

func readLegacyDoHQuestion(t *testing.T, r *http.Request) *dns.Msg {
	t.Helper()
	wire, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		t.Error(err)
		return nil
	}
	query := new(dns.Msg)
	if err := query.Unpack(wire); err != nil {
		t.Error(err)
		return nil
	}
	return query
}

func TestLegacyDoHNormalizesWireIDAndRestoresClientIdentity(t *testing.T) {
	observed := make(chan *dns.Msg, 1)
	u := legacyDoHFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := readLegacyDoHQuestion(t, r)
		if query == nil {
			return
		}
		observed <- query.Copy()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(encryptedFixtureReply(t, query))
	}))
	query := encryptedFixtureQuery()
	query.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"}}
	before := query.Copy()
	reply, err := u.Exchange(context.Background(), query)
	if err != nil || reply == nil || reply.Id != before.Id || len(reply.Answer) != 1 {
		t.Fatalf("legacy DoH response = %v, %v", reply, err)
	}
	if wireQuery := <-observed; wireQuery.Id != 0 || wireQuery.Question[0] != before.Question[0] || !wireQuery.CheckingDisabled || wireQuery.IsEdns0() == nil || !wireQuery.IsEdns0().Do() || len(wireQuery.IsEdns0().Option) != 0 {
		t.Fatalf("DoH wire identity or DNSSEC flags = %s", wireQuery)
	}
	if query.String() != before.String() {
		t.Fatal("legacy DoH mutated the caller's query")
	}
}

func TestLegacyDoHDoesNotFollowRedirectsToPlaintext(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		query := readLegacyDoHQuestion(t, r)
		if query == nil {
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(encryptedFixtureReply(t, query))
	}))
	defer target.Close()
	u := legacyDoHFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/dns-query", http.StatusTemporaryRedirect)
	}))
	reply, err := u.Exchange(context.Background(), encryptedFixtureQuery())
	if err == nil || reply != nil || reached.Load() != 0 {
		t.Fatalf("DoH redirect escaped the configured HTTPS endpoint: reply=%v, err=%v, plaintext requests=%d", reply, err, reached.Load())
	}
}

func TestLegacyDoHRejectsInvalidResponseBeforeCaching(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*dns.Msg)
		mediaType   string
		appendBytes int
	}{
		{name: "wrong_id", mutate: func(m *dns.Msg) { m.Id++ }},
		{name: "question_not_response", mutate: func(m *dns.Msg) { m.Response = false }},
		{name: "different_name", mutate: func(m *dns.Msg) { m.Question[0].Name = "another.test." }},
		{name: "different_type", mutate: func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAAAA }},
		{name: "different_class", mutate: func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS }},
		{name: "different_opcode", mutate: func(m *dns.Msg) { m.Opcode = dns.OpcodeStatus }},
		{name: "wrong_content_type", mediaType: "text/plain"},
		{name: "trailing_bytes", appendBytes: 1},
		{name: "oversized_body", appendBytes: 65536},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := legacyDoHFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := readLegacyDoHQuestion(t, r)
				if query == nil {
					return
				}
				reply := new(dns.Msg)
				if err := reply.Unpack(encryptedFixtureReply(t, query)); err != nil {
					t.Error(err)
					return
				}
				if tt.mutate != nil {
					tt.mutate(reply)
				}
				wire, err := reply.Pack()
				if err != nil {
					t.Error(err)
					return
				}
				mediaType := tt.mediaType
				if mediaType == "" {
					mediaType = "application/dns-message"
				}
				w.Header().Set("Content-Type", mediaType)
				wire = append(wire, make([]byte, tt.appendBytes)...)
				_, _ = w.Write(wire)
			}))
			r := newRouteTestResolver(t, []string{"udp://127.0.0.1:1"}, true, "failover")
			r.upstreams = []*Upstream{u}
			if result, err := r.Resolve(context.Background(), encryptedFixtureQuery(), 1); err == nil || result.Msg != nil {
				t.Fatalf("invalid DoH response became a successful answer: %+v, %v", result, err)
			}
			if size, _, _ := r.Cache().Stats(); size != 0 {
				t.Fatalf("invalid DoH response populated %d cache entries", size)
			}
		})
	}
}

func TestLegacyDoHStillRequiresTrustedTLSCertificate(t *testing.T) {
	var reached atomic.Int32
	u := legacyDoHFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	u.httpc.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
	if reply, err := u.Exchange(context.Background(), encryptedFixtureQuery()); err == nil || reply != nil || reached.Load() != 0 {
		t.Fatalf("untrusted DoH peer received application DNS: reply=%v err=%v payloads=%d", reply, err, reached.Load())
	}
}

func TestLegacyDoHPreservesUpstreamDNSFailures(t *testing.T) {
	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNameError} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			u := legacyDoHFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := readLegacyDoHQuestion(t, r)
				if query == nil {
					return
				}
				reply := new(dns.Msg)
				reply.SetRcode(query, rcode)
				reply.SetEdns0(1232, true)
				reply.IsEdns0().Option = append(reply.IsEdns0().Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeBlocked})
				wire, err := reply.Pack()
				if err != nil {
					t.Error(err)
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(wire)
			}))
			var backupQueries atomic.Int32
			backup := routeFixtureHTTPUpstream(func(q *dns.Msg) (*dns.Msg, error) {
				backupQueries.Add(1)
				return new(dns.Msg).SetReply(q), nil
			})
			r := newRouteTestResolver(t, []string{"udp://127.0.0.1:1"}, true, "failover")
			r.upstreams = []*Upstream{u, backup}
			query := encryptedFixtureQuery()
			result, err := r.Resolve(context.Background(), query, 1)
			if err != nil || result.Msg == nil || result.Rcode != rcode || result.Msg.Id != query.Id || backupQueries.Load() != 0 {
				t.Fatalf("valid upstream DNS failure was changed or bypassed: %+v, err=%v backupQueries=%d", result, err, backupQueries.Load())
			}
			opt := result.Msg.IsEdns0()
			if opt == nil || len(opt.Option) != 1 || opt.Option[0].(*dns.EDNS0_EDE).InfoCode != dns.ExtendedErrorCodeBlocked {
				t.Fatalf("upstream extended DNS error was lost: %s", result.Msg)
			}
		})
	}
}

func TestLegacyDoHFailsOverAfterMalformedResponse(t *testing.T) {
	bad := routeFixtureHTTPUpstream(func(q *dns.Msg) (*dns.Msg, error) {
		reply := new(dns.Msg).SetReply(q)
		reply.Question[0].Name = "wrong.test."
		return reply, nil
	})
	var backupQueries atomic.Int32
	backup := routeFixtureHTTPUpstream(func(q *dns.Msg) (*dns.Msg, error) {
		backupQueries.Add(1)
		return new(dns.Msg).SetReply(q), nil
	})
	r := newRouteTestResolver(t, []string{"udp://127.0.0.1:1"}, false, "failover")
	r.upstreams = []*Upstream{bad, backup}
	query := encryptedFixtureQuery()
	result, err := r.Resolve(context.Background(), query, 1)
	if err != nil || result.Msg == nil || result.Rcode != dns.RcodeSuccess || result.Msg.Id != query.Id || backupQueries.Load() != 1 {
		t.Fatalf("malformed DoH response prevented approved backup: %+v, err=%v backupQueries=%d", result, err, backupQueries.Load())
	}
}
