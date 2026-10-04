package dnsserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/miekg/dns"
)

func seededAccess(t *testing.T, h *testHarness) *clientacl.Controller {
	t.Helper()
	c := clientacl.NewController([]string{"127.0.0.1/32", "::1/128"}, false, func(ctx context.Context) ([]clientacl.Network, error) {
		rows, err := h.store.ListNetworks(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]clientacl.Network, 0, len(rows))
		for _, n := range rows {
			out = append(out, clientacl.Network{ID: n.ID, Name: n.Name, CIDRs: n.CIDRs, Enabled: n.Enabled, AllowResolver: n.AllowResolver})
		}
		return out, nil
	})
	if err := c.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.handler.acl = c
	return c
}

func accessQuestion(domain string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(domain+".", dns.TypeA)
	return m
}
func accessRequest(h *testHarness, ip, proto, domain string) *dns.Msg {
	return h.handler.Handle(context.Background(), accessQuestion(domain), requestMeta{clientAddr: netip.MustParseAddr(ip), proto: proto})
}

// The acceptance criterion is a real answer and query history with an EMPTY
// feed index, not just another successful denial test. The in-process upstream
// is local; no public resolver, API key or threat feed is involved.
func TestRefusedClientCanRecoverAndProduceHistoryWithoutBlocklists(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	acl := seededAccess(t, h)
	for _, proto := range []string{"udp", "tcp"} {
		m := h.handler.Handle(ctx, func() *dns.Msg { q := accessQuestion("never-persist.example"); q.SetEdns0(1232, false); return q }(), requestMeta{clientAddr: netip.MustParseAddr("203.0.113.9"), proto: proto})
		if m.Rcode != dns.RcodeRefused {
			t.Fatal("unpermitted client was admitted")
		}
		opt := m.IsEdns0()
		if opt == nil || len(opt.Option) != 1 {
			t.Fatal("missing EDNS refusal explanation")
		}
		if e, ok := opt.Option[0].(*dns.EDNS0_EDE); !ok || e.InfoCode != dns.ExtendedErrorCodeProhibited {
			t.Fatal("wrong refusal class")
		}
	}
	a := h.handler.AccessActivity()
	if len(a.Entries) != 1 || a.Entries[0].CIDR != "203.0.113.9/32" || a.Entries[0].Refused != 2 {
		t.Fatal(a)
	}
	name, policy, on := "Known client", "p_standard", true
	cidrs := []string{"203.0.113.9/32"}
	n, err := h.store.CreateNetwork(ctx, store.NetworkInput{Name: &name, PolicyID: &policy, CIDRs: &cidrs, Enabled: &on, AllowResolver: &on, PublicAck: &on})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if err := acl.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	for _, proto := range []string{"udp", "tcp"} {
		m := accessRequest(h, "203.0.113.9", proto, "allowed.example")
		if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 {
			t.Fatalf("permitted %s client did not get an answer: %v", proto, m)
		}
	}
	if len(h.handler.AccessActivity().Entries) != 1 || h.handler.AccessActivity().Entries[0].Answered != 2 {
		t.Fatal("recovery was not observed")
	}
	if accessRequest(h, "203.0.113.10", "udp", "other.example").Rcode != dns.RcodeRefused {
		t.Fatal("grant widened")
	}
	// A local policy rule remains functional without a feed index.
	blocked := []string{"local-policy.example"}
	if _, err := h.store.UpdatePolicy(ctx, policy, store.PolicyInput{BlockDomains: &blocked}); err != nil {
		t.Fatal(err)
	}
	if err := h.engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if accessRequest(h, "203.0.113.9", "udp", "local-policy.example").Rcode != dns.RcodeNameError {
		t.Fatal("local policy was not enforced")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		var count int
		if err := h.store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM query_log WHERE network_id = ?", n.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admitted queries did not enter query history")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// QueryEvent.Domain is stored as query_log.qname. Check the same column
	// for both positive and negative evidence so an empty/wrong query cannot
	// masquerade as successful privacy protection.
	for _, expected := range []struct {
		qname string
		count int
	}{
		{"allowed.example", 2},
		{"local-policy.example", 1},
		{"never-persist.example", 0},
		{"other.example", 0},
	} {
		var count int
		if err := h.store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM query_log WHERE qname = ?", expected.qname).Scan(&count); err != nil {
			t.Fatalf("read query history for %q: %v", expected.qname, err)
		}
		if count != expected.count {
			t.Fatalf("query history rows for %q = %d, want %d", expected.qname, count, expected.count)
		}
	}
	off := false
	if _, err := h.store.UpdateNetwork(ctx, n.ID, store.NetworkInput{AllowResolver: &off}); err != nil {
		t.Fatal(err)
	}
	if err := acl.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if accessRequest(h, "203.0.113.9", "udp", "allowed.example").Rcode != dns.RcodeRefused {
		t.Fatal("revocation ignored a cached answer")
	}
}

func TestRefusedSourceEvidenceHonoursGlobalAndPolicyPrivacy(t *testing.T) {
	for _, mode := range []string{"query", "address", "policy"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, nil)
			seededAccess(t, h)
			switch mode {
			case "query":
				h.handler.queryLogEnabled = false
			case "address":
				h.handler.logClientIP = false
			case "policy":
				off := false
				if _, err := h.store.UpdatePolicy(context.Background(), "p_standard", store.PolicyInput{LogQueries: &off}); err != nil {
					t.Fatal(err)
				}
				if err := h.engine.Reload(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if accessRequest(h, "203.0.113.9", "udp", "private.example").Rcode != dns.RcodeRefused {
				t.Fatal("privacy changed admission")
			}
			if len(h.handler.AccessActivity().Entries) != 0 {
				t.Fatal("privacy bypassed by diagnostics")
			}
			if h.handler.LiveActivity().SinceStart.Refused != 1 {
				t.Fatal("anonymous counts stopped")
			}
		})
	}
}

// The actual DoH handler serves a token-authenticated client over verified
// TLS 1.3 with no source-IP permission and no feeds. Token auth must not be
// misreported as recovery of the same source's ordinary DNS permission.
func TestTokenisedDoHResolvesOverTLSWithoutFeedOrSourceGrant(t *testing.T) {
	h := newHarness(t, nil)
	seededAccess(t, h)
	accessRequest(h, "203.0.113.9", "udp", "refused.example")
	n, err := h.store.GetNetwork(context.Background(), clientacl.DefaultNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	doh := NewDoHHandler(h.handler, h.store, h.handler.log, DoHOptions{})
	srv := httptest.NewUnstartedServer(doh)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	raw, err := accessQuestion("encrypted.example").Pack()
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/dns-query/"+n.Token, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	wire, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("DoH did not use verified TLS 1.3: status=%d", resp.StatusCode)
	}
	var answer dns.Msg
	if err := answer.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) == 0 {
		t.Fatal("encrypted permitted client has no answer")
	}
	if got := h.handler.AccessActivity().Entries[0]; got.Answered != 0 {
		t.Fatal("token permission misrepresented as source grant")
	}
	bad, err := http.NewRequest(http.MethodPost, srv.URL+"/dns-query/not-a-valid-token", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	bad.Header.Set("Content-Type", "application/dns-message")
	rejected, err := srv.Client().Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	rejected.Body.Close()
	if rejected.StatusCode != 404 {
		t.Fatalf("invalid token did not fail closed: %d", rejected.StatusCode)
	}
}
