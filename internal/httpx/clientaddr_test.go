package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func mustTrusted(t *testing.T, cidrs ...string) *TrustedProxies {
	t.Helper()
	tp, err := ParseTrustedProxies(cidrs)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%v): %v", cidrs, err)
	}
	return tp
}

func req(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientAddr(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		headers map[string]string
		trusted []string
		want    string
	}{
		{
			name:   "no proxy trusted, headers ignored",
			remote: "203.0.113.9:5555",
			// The whole point: an untrusted caller cannot pick its own identity.
			headers: map[string]string{"X-Forwarded-For": "10.0.0.1"},
			want:    "203.0.113.9",
		},
		{
			name:    "trusted proxy, single entry",
			remote:  "127.0.0.1:5555",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: []string{"127.0.0.1/32"},
			want:    "203.0.113.9",
		},
		{
			// The client prepended a lie. Walking from the right skips it.
			name:    "spoofed left-most entry is not believed",
			remote:  "127.0.0.1:5555",
			headers: map[string]string{"X-Forwarded-For": "10.9.9.9, 203.0.113.9"},
			trusted: []string{"127.0.0.1/32"},
			want:    "203.0.113.9",
		},
		{
			// Two hops of our own infrastructure appended themselves; the
			// right-most entry that is not ours is the real client.
			name:    "our own proxy chain is skipped",
			remote:  "127.0.0.1:5555",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9, 10.1.0.5, 10.1.0.6"},
			trusted: []string{"127.0.0.1/32", "10.1.0.0/24"},
			want:    "203.0.113.9",
		},
		{
			name:    "x-real-ip when no XFF",
			remote:  "127.0.0.1:5555",
			headers: map[string]string{"X-Real-IP": "203.0.113.9"},
			trusted: []string{"127.0.0.1/32"},
			want:    "203.0.113.9",
		},
		{
			name:    "x-real-ip ignored from untrusted peer",
			remote:  "203.0.113.9:5555",
			headers: map[string]string{"X-Real-IP": "10.0.0.1"},
			want:    "203.0.113.9",
		},
		{
			name:    "garbage XFF falls back to the peer",
			remote:  "127.0.0.1:5555",
			headers: map[string]string{"X-Forwarded-For": "not-an-address"},
			trusted: []string{"127.0.0.1/32"},
			want:    "127.0.0.1",
		},
		{
			name:    "XFF of only trusted hops falls back to the peer",
			remote:  "127.0.0.1:5555",
			headers: map[string]string{"X-Forwarded-For": "127.0.0.1"},
			trusted: []string{"127.0.0.1/32"},
			want:    "127.0.0.1",
		},
		{
			name:   "IPv4-mapped IPv6 is unmapped",
			remote: "[::ffff:203.0.113.9]:5555",
			want:   "203.0.113.9",
		},
		{
			name:   "IPv6 zone is stripped",
			remote: "[fe80::1%eth0]:5555",
			want:   "fe80::1",
		},
		{
			name:    "IPv6 proxy and client",
			remote:  "[2001:db8::1]:5555",
			headers: map[string]string{"X-Forwarded-For": "2001:db8:beef::9"},
			trusted: []string{"2001:db8::/64"},
			want:    "2001:db8:beef::9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClientAddr(req(tt.remote, tt.headers), mustTrusted(t, tt.trusted...))
			if got.String() != tt.want {
				t.Errorf("ClientAddr = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestIsHTTPS(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		headers map[string]string
		trusted []string
		want    bool
	}{
		{
			name:   "plain HTTP direct",
			remote: "10.0.0.5:5555",
			want:   false,
		},
		{
			// Otherwise any client could force a Secure cookie it will never
			// send back, locking itself — and the operator — out.
			name:    "X-Forwarded-Proto ignored from untrusted peer",
			remote:  "10.0.0.5:5555",
			headers: map[string]string{"X-Forwarded-Proto": "https"},
			want:    false,
		},
		{
			name:    "X-Forwarded-Proto believed from trusted proxy",
			remote:  "127.0.0.1:5555",
			headers: map[string]string{"X-Forwarded-Proto": "https"},
			trusted: []string{"127.0.0.1/32"},
			want:    true,
		},
		{
			name:    "trusted proxy reporting http",
			remote:  "127.0.0.1:5555",
			headers: map[string]string{"X-Forwarded-Proto": "http"},
			trusted: []string{"127.0.0.1/32"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHTTPS(req(tt.remote, tt.headers), mustTrusted(t, tt.trusted...)); got != tt.want {
				t.Errorf("IsHTTPS = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsHTTPSWithTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsHTTPS(r, mustTrusted(t)) {
			t.Error("IsHTTPS = false on a real TLS connection")
		}
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
}

func TestTrustedProxiesRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"not-an-address", "10.0.0.0/64", "10.0.0.0/-1", "::/200"} {
		if _, err := ParseTrustedProxies([]string{bad}); err == nil {
			t.Errorf("ParseTrustedProxies(%q) accepted an invalid entry", bad)
		}
	}
}

// A v4 prefix must never match a v6 address or vice versa; without the family
// check, ::/0-style entries would silently trust everything.
func TestTrustsDoesNotCrossAddressFamilies(t *testing.T) {
	tp := mustTrusted(t, "0.0.0.0/0")
	if ClientAddr(req("[2001:db8::1]:5555", map[string]string{"X-Forwarded-For": "203.0.113.9"}), tp).String() != "2001:db8::1" {
		t.Error("an IPv4 prefix matched an IPv6 peer")
	}
}
