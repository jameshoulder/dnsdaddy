package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
	"github.com/miekg/dns"
)

func TestLiveActivityRequiresAuthenticationAndReportsImmediateDNSWork(t *testing.T) {
	h := newHarness(t)
	if resp, _ := h.do(http.MethodGet, "/api/v1/activity/live", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated activity returned %d", resp.StatusCode)
	}
	h.login()
	read := func() dnsserver.LiveActivity {
		t.Helper()
		resp, raw := h.do(http.MethodGet, "/api/v1/activity/live", nil)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("live response: status=%d cache=%q body=%s", resp.StatusCode, resp.Header.Get("Cache-Control"), raw)
		}
		var live dnsserver.LiveActivity
		if err := json.Unmarshal(raw, &live); err != nil {
			t.Fatal(err)
		}
		return live
	}
	if fresh := read(); fresh.Status != "waiting" || fresh.LastQueryAt != nil {
		t.Fatalf("fresh API invented activity: %+v", fresh)
	}
	q := new(dns.Msg)
	q.SetQuestion("evil.com.", dns.TypeA)
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Content-Type", "application/dns-message")
	response := httptest.NewRecorder()
	h.api.DoH.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("DNS request: %d %s", response.Code, response.Body.String())
	}
	live := read()
	if live.SinceStart.Received != 1 || live.SinceStart.Completed != 1 || live.SinceStart.Blocked != 1 || live.LastRcode != "NXDOMAIN" {
		t.Fatalf("DNS request not immediately visible: %+v", live)
	}
	if overview := h.overview(t); overview.Live.SinceStart != live.SinceStart {
		t.Fatalf("overview and lightweight activity disagree: %+v / %+v", overview.Live, live)
	}
	// Repeated dashboard polls do not probe DNS or inflate traffic counts.
	if again := read(); again.SinceStart != live.SinceStart || !again.StartedAt.Equal(live.StartedAt) {
		t.Fatalf("reading activity changed it: %+v / %+v", again, live)
	}

	// The endpoint must work even when no store or historical dashboard
	// dependencies are available; only the running handler is required.
	minimal := &API{Deps: Deps{DNS: h.api.DNS}}
	withoutStore := httptest.NewRecorder()
	minimal.handleLiveActivity(withoutStore, httptest.NewRequest(http.MethodGet, "/api/v1/activity/live", nil))
	if withoutStore.Code != http.StatusOK {
		t.Fatalf("live activity depends on historical data: %d", withoutStore.Code)
	}
}

func TestLiveActivityUnavailableDoesNotReportZeroTraffic(t *testing.T) {
	a := &API{}
	w := httptest.NewRecorder()
	a.handleLiveActivity(w, httptest.NewRequest(http.MethodGet, "/api/v1/activity/live", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing handler returned %d: %s", w.Code, w.Body.String())
	}
}
