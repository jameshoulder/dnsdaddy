package api

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/miekg/dns"
)

type accessResponseWriter struct {
	peer string
	msg  *dns.Msg
}

func (w *accessResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}
func (w *accessResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(w.peer), Port: 53000}
}
func (w *accessResponseWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m.Copy()
	return nil
}
func (w *accessResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *accessResponseWriter) Close() error              { return nil }
func (w *accessResponseWriter) TsigStatus() error         { return nil }
func (w *accessResponseWriter) TsigTimersOnly(bool)       {}
func (w *accessResponseWriter) Hijack()                   {}

func queryAccessAPI(t *testing.T, h *harness, ip string) *dns.Msg {
	t.Helper()
	w := &accessResponseWriter{peer: ip}
	req := new(dns.Msg)
	req.SetQuestion("evil.com.", dns.TypeA) // local fixture feed, no upstream request
	h.api.DNS.ServeDNS(w, req)
	if w.msg == nil {
		t.Fatal("handler did not answer")
	}
	return w.msg
}

func readAccessAPI(t *testing.T, h *harness) ClientAccessActivity {
	t.Helper()
	resp, raw := h.do("GET", "/api/v1/activity/live", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("activity read: %d %s", resp.StatusCode, raw)
	}
	var got struct {
		dnsserver.LiveActivity
		ClientAccess ClientAccessActivity `json:"clientAccess"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got.ClientAccess
}

func TestAccessAPIRequiresAuthAndDistinguishesPermissionFromResolution(t *testing.T) {
	h := newHarness(t)
	if got := queryAccessAPI(t, h, "203.0.113.9"); got.Rcode != dns.RcodeRefused {
		t.Fatal("fixture source should be refused")
	}
	resp, _ := h.do("GET", "/api/v1/activity/live", nil)
	if resp.StatusCode != 401 {
		t.Fatalf("source diagnostics disclosed without authentication: %d", resp.StatusCode)
	}
	h.login()
	before := readAccessAPI(t, h)
	if len(before.Entries) != 1 || before.Entries[0].Status != "needs_permission" || before.Entries[0].CIDR != "203.0.113.9/32" || !before.Entries[0].Public {
		t.Fatalf("bad refused source: %+v", before)
	}
	entry := before.Entries[0]
	resp, raw := h.do("POST", "/api/v1/networks", map[string]any{"name": "Source fixture", "policyId": entry.PolicyID, "cidrs": []string{entry.CIDR}, "enabled": true, "allowResolver": true, "publicAck": true})
	if resp.StatusCode != 201 {
		t.Fatalf("grant: %d %s", resp.StatusCode, raw)
	}
	waiting := readAccessAPI(t, h)
	if waiting.Entries[0].Status != "permitted_waiting" || !waiting.Entries[0].SourceAllowed {
		t.Fatal("saving a grant must not claim a successful query")
	}
	if got := queryAccessAPI(t, h, "203.0.113.9"); got.Rcode != dns.RcodeNameError {
		t.Fatal("permitted client lost its local malware policy")
	}
	after := readAccessAPI(t, h)
	if after.Entries[0].Status != "policy_blocked" {
		t.Fatalf("policy block misreported as source refusal: %+v", after.Entries[0])
	}
	off := false
	if _, err := h.store.UpdatePolicy(context.Background(), entry.PolicyID, store.PolicyInput{LogQueries: &off}); err != nil {
		t.Fatal(err)
	}
	if err := h.api.Engine.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(readAccessAPI(t, h).Entries) != 0 {
		t.Fatal("a later policy privacy change failed to hide retained source evidence")
	}
}
