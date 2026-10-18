package feedpolicy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/miekg/dns"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func publicPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestAddressClassesAndDNSRebindingCandidates(t *testing.T) {
	p := publicPolicy(t)
	for _, raw := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if p.checkAddress("https://feed.example:443", netip.MustParseAddr(raw)) != nil {
			t.Errorf("public address denied: %s", raw)
		}
	}
	for _, raw := range []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "fc00::1", "fe80::1", "169.254.169.254", "fd00:ec2::254", "100.100.100.200", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "192.0.2.1", "2001:db8::1", "2002:7f00:1::", "64:ff9b::7f00:1", "::ffff:127.0.0.1", "fe80::1%en0"} {
		if p.checkAddress("https://feed.example:443", netip.MustParseAddr(raw)) == nil {
			t.Errorf("forbidden address allowed: %s", raw)
		}
	}
	// Simulate changing and mixed DNS answers; each numeric candidate is checked.
	ctx := context.WithValue(context.Background(), originKey{}, "https://feed.example:443")
	for i, address := range []string{"1.1.1.1:443", "127.0.0.1:443", "[::1]:443", "10.0.0.1:443", "[::ffff:169.254.169.254]:443"} {
		err := p.control(ctx, "tcp", address, nil)
		if (err == nil) != (i == 0) {
			t.Errorf("candidate %s error=%v", address, err)
		}
	}
	if p.control(context.Background(), "tcp", "1.1.1.1:443", nil) == nil {
		t.Fatal("connection without request policy context allowed")
	}
}
func TestExplicitPrivatePolicyNeverAllowsMetadata(t *testing.T) {
	p, err := New([]Rule{{Origin: "https://corp.example:8443", PrivateCIDRs: []string{"10.20.0.0/16", "fd12:3456::/48", "fd00:ec2::/64"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"10.20.1.1", "fd12:3456::42"} {
		if p.checkAddress("https://corp.example:8443", netip.MustParseAddr(address)) != nil {
			t.Fatal("explicit internal feed denied")
		}
	}
	for _, c := range []struct{ origin, addr string }{{"https://other.example:8443", "10.20.1.1"}, {"https://corp.example:443", "10.20.1.1"}, {"https://corp.example:8443", "10.21.1.1"}, {"https://corp.example:8443", "fd00:ec2::254"}, {"https://corp.example:8443", "169.254.169.254"}, {"https://corp.example:8443", "::1"}} {
		if p.checkAddress(c.origin, netip.MustParseAddr(c.addr)) == nil {
			t.Fatalf("exception escaped: %+v", c)
		}
	}
	for _, raw := range []string{"0.0.0.0/0", "127.0.0.0/8", "169.254.0.0/16", "2000::/3", "10.0.0.0/7"} {
		if _, err := New([]Rule{{Origin: "https://corp.example", PrivateCIDRs: []string{raw}}}); err == nil {
			t.Errorf("overbroad rule accepted %s", raw)
		}
	}
}
func TestURLAndRuleAdmission(t *testing.T) {
	p := publicPolicy(t)
	for _, raw := range []string{"http://feed.example/", "https://u:synthetic-secret@feed.example/", "https://localhost/", "https://sub.localhost/", "https://metadata.google.internal/", "https://[fe80::1%25en0]/", "https://host:0/", "https://host:65536/", "https://host:bad/", "https://feed.example/#fragment", "https:opaque", "https://feed.example/\nsecret"} {
		if p.ValidateURL(raw) == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if p.ValidateURL("https://feed.example:8443/private-path?api_key=synthetic") != nil {
		t.Fatal("query-authenticated HTTPS source rejected")
	}
	for _, rules := range [][]Rule{{{Origin: "https://feed.example/path"}}, {{Origin: "https://feed.example?secret=x"}}, {{Origin: "https://feed.example"}, {Origin: "https://FEED.EXAMPLE:443/"}}, {{Origin: "https://feed.example", RedirectOrigins: []string{"http://other.example"}}}} {
		if _, err := New(rules); err == nil {
			t.Fatal("invalid origin rules accepted")
		}
	}
}
func TestRedirectOriginsAndHeaders(t *testing.T) {
	p, err := New([]Rule{{Origin: "https://feed.example", RedirectOrigins: []string{"https://cdn.example:8443"}}})
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := http.NewRequest("GET", "https://feed.example/list?token=synthetic", nil)
	for _, target := range []string{"http://feed.example/list", "https://other.example/list", "https://127.0.0.1/list", "https://u:secret@cdn.example:8443/list"} {
		req, _ := http.NewRequest("GET", target, nil)
		if p.CheckRedirect(req, []*http.Request{initial}) == nil {
			t.Errorf("redirect allowed %s", target)
		}
	}
	req, _ := http.NewRequest("GET", "https://FEED.EXAMPLE:443/new", nil)
	req.Header.Set("Referer", initial.URL.String())
	if err := p.CheckRedirect(req, []*http.Request{initial}); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Referer") != "" {
		t.Fatal("URL credential in Referer")
	}
	req, _ = http.NewRequest("GET", "https://cdn.example:8443/list", nil)
	for _, key := range []string{"Authorization", "Cookie", "If-None-Match", "Referer", "X-API-Key"} {
		req.Header.Set(key, "synthetic-secret")
	}
	if err := p.CheckRedirect(req, []*http.Request{initial}); err != nil {
		t.Fatal(err)
	}
	for _, v := range req.Header {
		if strings.Contains(strings.Join(v, ""), "synthetic-secret") {
			t.Fatal("cross-origin credential/header leakage")
		}
	}
	if p.CheckRedirect(req, []*http.Request{initial, initial, initial, initial, initial}) == nil {
		t.Fatal("unbounded redirects")
	}
}
func TestActualDialGuardBeforeLoopbackConnect(t *testing.T) {
	// The supplied loopback listener is a synthetic fixture, not a host service.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	p := publicPolicy(t)
	client := p.NewClient(time.Second)
	tr := client.Transport.(*Transport)
	ctx := context.WithValue(context.Background(), originKey{}, "https://feed.example:443")
	conn, err := tr.inner.DialContext(ctx, "tcp", listener.Addr().String())
	if conn != nil {
		conn.Close()
		t.Fatal("guard connected to denied loopback fixture")
	}
	if !errors.Is(err, ErrDestination) {
		t.Fatalf("actual socket hook did not deny destination: %v", err)
	}
	if tr.inner.Proxy != nil || tr.inner.TLSClientConfig.InsecureSkipVerify || tr.inner.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("weakened transport settings")
	}
}
func TestHTTPSFixturesKeepCertificateVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "synthetic.example\n") }))
	defer server.Close()
	p := publicPolicy(t)
	for _, tc := range []struct {
		name, host string
		trust      bool
		wantOK     bool
	}{{"trusted", "example.com", true, true}, {"wrong-host", "wrong.example", true, false}, {"unknown-ca", "example.com", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			client := p.NewClient(2 * time.Second)
			tr := client.Transport.(*Transport)
			defer tr.CloseIdleConnections()
			roots := x509.NewCertPool()
			if tc.trust {
				roots.AddCert(server.Certificate())
			}
			tr.inner.TLSClientConfig.RootCAs = roots
			// Test-only dial seam: assert policy context and numeric guard, then route
			// to our synthetic TLS fixture. Certificate identity remains example.com.
			tr.inner.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if err := p.control(ctx, network, "1.1.1.1:443", nil); err != nil {
					return nil, err
				}
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			response, err := client.Get("https://" + tc.host + "/list")
			if response != nil {
				response.Body.Close()
			}
			if (err == nil) != tc.wantOK {
				t.Fatalf("TLS result: %v", err)
			}
		})
	}
}
func TestSafeFailuresNeverIncludeWrappedURL(t *testing.T) {
	wrapped := &net.OpError{Op: "synthetic-secret", Err: errors.New("https://u:synthetic-secret@feed.example/secret?token=synthetic-secret")}
	if strings.Contains(Failure(wrapped), "synthetic-secret") {
		t.Fatal("network error leaked")
	}
	for _, err := range []error{ErrURL, ErrDestination, ErrRedirect, ErrRedirectLimit, context.Canceled, context.DeadlineExceeded} {
		if Failure(err) == "" {
			t.Fatal("missing actionable failure")
		}
	}
}

func TestResolvedHostnameCheckedAtActualConnection(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		if len(q.Question) > 0 {
			h := dns.RR_Header{Name: q.Question[0].Name, Class: dns.ClassINET, Ttl: 0}
			if q.Question[0].Qtype == dns.TypeA {
				h.Rrtype = dns.TypeA
				response.Answer = []dns.RR{&dns.A{Hdr: h, A: net.ParseIP("127.0.0.1")}}
			}
			if q.Question[0].Qtype == dns.TypeAAAA {
				h.Rrtype = dns.TypeAAAA
				response.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.ParseIP("fd00:ec2::254")}}
			}
		}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	defer server.Shutdown()
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", packet.LocalAddr().String())
	}}
	defer func() { net.DefaultResolver = original }()
	p := publicPolicy(t)
	client := p.NewClient(2 * time.Second)
	defer client.CloseIdleConnections()
	if err := p.ValidateURL("https://rebind.example/list"); err != nil {
		t.Fatal(err)
	}
	_, err = client.Get("https://rebind.example/list")
	if !errors.Is(err, ErrDestination) {
		t.Fatalf("resolved address bypassed socket policy: %v", err)
	}
}

func TestExpiredFixtureCertificateRejected(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("expired certificate reached HTTP handler") }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	p := publicPolicy(t)
	client := p.NewClient(2 * time.Second)
	defer client.CloseIdleConnections()
	tr := client.Transport.(*Transport)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	tr.inner.TLSClientConfig.RootCAs = roots
	tr.inner.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := p.control(ctx, network, "1.1.1.1:443", nil); err != nil {
			return nil, err
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	response, err := client.Get("https://example.com/list")
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("expired certificate accepted")
	}
}
