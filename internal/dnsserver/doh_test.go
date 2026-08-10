package dnsserver

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/httpx"
)

func newDoH(t *testing.T, o DoHOptions) *DoHHandler {
	t.Helper()
	h := newHarnessWithOptions(t, nil)
	return NewDoHHandler(h.handler, h.store, slog.New(slog.NewTextHandler(io.Discard, nil)), o)
}

func packedQuery(t *testing.T, name string) []byte {
	t.Helper()
	b, err := query(name, dns.TypeA).Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return b
}

// The bare /dns-query path has no client authentication at all. Behind a public
// reverse proxy, leaving it open would hand anyone who finds the path a free
// DoH resolver running on the operator's IP address.
func TestBareDoHPathRequiresToken(t *testing.T) {
	d := newDoH(t, DoHOptions{AllowUntokenized: false})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(packedQuery(t, "example.com")))
	req.Header.Set("Content-Type", "application/dns-message")
	req.RemoteAddr = "203.0.113.9:5555"
	d.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for the untokenized path", rec.Code)
	}
}

func TestBareDoHPathAllowedWhenOptedIn(t *testing.T) {
	d := newDoH(t, DoHOptions{AllowUntokenized: true})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(packedQuery(t, "example.com")))
	req.Header.Set("Content-Type", "application/dns-message")
	req.RemoteAddr = "203.0.113.9:5555"
	d.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with allow_untokenized_doh set", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/dns-message" {
		t.Errorf("content-type = %q, want application/dns-message", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("the DoH response is missing X-Content-Type-Options: nosniff")
	}
}

// An unknown token must be an error, never a silent fall back to IP-based
// attribution — that would quietly apply the wrong filtering policy.
func TestUnknownDoHTokenIsRejected(t *testing.T) {
	d := newDoH(t, DoHOptions{AllowUntokenized: true})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dns-query/nosuchtoken",
		bytes.NewReader(packedQuery(t, "example.com")))
	req.Header.Set("Content-Type", "application/dns-message")
	req.RemoteAddr = "203.0.113.9:5555"
	d.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an unknown token", rec.Code)
	}
}

// A DoH body far larger than any real DNS message is abuse, not a query.
func TestOversizedDoHBodyIsRejected(t *testing.T) {
	d := newDoH(t, DoHOptions{AllowUntokenized: true})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(make([]byte, maxDoHBody*4)))
	req.Header.Set("Content-Type", "application/dns-message")
	req.RemoteAddr = "203.0.113.9:5555"
	d.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an oversized body", rec.Code)
	}
}

// DoH attribution picks the filtering policy, so believing X-Forwarded-For from
// an untrusted peer would let any caller select any network's policy.
func TestDoHClientAttributionIgnoresUntrustedXFF(t *testing.T) {
	h := newHarnessWithOptions(t, nil)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	trusted, err := httpx.ParseTrustedProxies([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	d := NewDoHHandler(h.handler, h.store, log, DoHOptions{
		TrustedProxies: trusted, AllowUntokenized: true,
	})

	tests := []struct {
		name   string
		remote string
		xff    string
		want   string
	}{
		{"untrusted peer, header ignored", "203.0.113.9:5555", "10.0.0.1", "203.0.113.9"},
		{"trusted proxy, header believed", "127.0.0.1:5555", "203.0.113.77", "203.0.113.77"},
		{"trusted proxy, spoofed prefix skipped", "127.0.0.1:5555", "10.9.9.9, 203.0.113.77", "203.0.113.77"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/dns-query", nil)
			req.RemoteAddr = tt.remote
			req.Header.Set("X-Forwarded-For", tt.xff)
			if got := d.clientAddr(req).String(); got != tt.want {
				t.Errorf("clientAddr = %s, want %s", got, tt.want)
			}
		})
	}
}
