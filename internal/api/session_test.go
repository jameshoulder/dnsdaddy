package api

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Sessions used to be self-contained: the cookie was "<expiry>.<hmac(expiry)>"
// and the server kept no record of any particular one. That made logout
// advisory, made a password change irrelevant to live sessions, and made the
// signing key a permanent forgery capability.
//
// These tests pin the three properties that fixed it. Each of them was false
// before the change.

// currentSession returns the session cookie the harness's jar is holding.
func currentSession(t *testing.T, h *harness) string {
	t.Helper()
	for _, c := range h.client.Jar.Cookies(nil) {
		if c.Name == sessionCookie {
			return c.Value
		}
	}
	t.Fatal("no session cookie in the jar")
	return ""
}

func TestLogoutRevokesTheSessionServerSide(t *testing.T) {
	h := newHarness(t)
	h.login()

	token := currentSession(t, h)
	if live, err := h.store.LookupSession(context.Background(), token); err != nil || !live {
		t.Fatalf("session not recorded after login: live=%v err=%v", live, err)
	}

	if resp, raw := h.do("POST", "/api/v1/auth/logout", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("logout: status %d, body %s", resp.StatusCode, raw)
	}

	// The point of the whole change: the value the browser was holding is
	// dead on the server, not merely forgotten by the browser. Presenting the
	// captured cookie again must fail.
	if live, err := h.store.LookupSession(context.Background(), token); err != nil || live {
		t.Errorf("the session survived logout: live=%v err=%v", live, err)
	}

	req, _ := http.NewRequest("GET", h.server.URL+"/api/v1/overview", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a cookie captured before logout still works: status %d, want 401", resp.StatusCode)
	}
}

func TestChangingThePasswordSignsEverySessionOut(t *testing.T) {
	// An operator changing the password because they think somebody has been
	// in expects that somebody to be thrown out. Before this, the intruder's
	// cookie kept working for up to twelve hours.
	h := newHarness(t)
	h.login()
	first := currentSession(t, h)

	// A second, independent browser.
	h2 := &http.Client{Jar: &cookieJar{cookies: map[string]*http.Cookie{}}}
	body := strings.NewReader(`{"password":"` + testPassword + `"}`)
	req, _ := http.NewRequest("POST", h.server.URL+"/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h2.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var second string
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			second = c.Value
		}
	}
	if second == "" {
		t.Fatal("the second login issued no session cookie")
	}
	if second == first {
		t.Fatal("two logins produced the same session token; they must be independent")
	}

	resp2, raw := h.do("POST", "/api/v1/auth/password", map[string]string{
		"currentPassword": testPassword,
		"newPassword":     "a-much-longer-replacement-password",
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("change password: status %d, body %s", resp2.StatusCode, raw)
	}

	for name, token := range map[string]string{"the changing session": first, "the other browser": second} {
		if live, err := h.store.LookupSession(context.Background(), token); err != nil || live {
			t.Errorf("%s survived the password change: live=%v err=%v", name, live, err)
		}
	}

	// And the response says so, so the dashboard can show the login screen
	// rather than letting the operator find out on their next click.
	got := decode[map[string]any](t, raw)
	if got["sessionsRevoked"] != true {
		t.Errorf("the response does not report that sessions were revoked: %s", raw)
	}
}

func TestSessionTokensAreOpaqueAndUnforgeable(t *testing.T) {
	h := newHarness(t)
	h.login()
	token := currentSession(t, h)

	// The old format leaked its own expiry and was a deterministic function of
	// one integer plus a key. Neither should be true now.
	if strings.Contains(token, ".") {
		t.Errorf("the session token still looks structured: %q", token)
	}
	if _, err := time.Parse(time.RFC3339, token); err == nil {
		t.Errorf("the session token is a timestamp: %q", token)
	}

	// Nothing derived from the token is accepted: not a truncation, not an
	// extension, not a neighbouring value.
	for _, bad := range []string{
		token[:len(token)-1],
		token + "a",
		strings.ToUpper(token),
		"",
		"9999999999.0000000000000000000000000000000000000000000000000000000000000000",
	} {
		live, err := h.store.LookupSession(context.Background(), bad)
		if err != nil {
			t.Fatalf("LookupSession(%q): %v", bad, err)
		}
		if live {
			t.Errorf("a derived value was accepted as a session: %q", bad)
		}
	}
}

func TestExpiredSessionsAreRefused(t *testing.T) {
	h := newHarness(t)
	// Issued directly with a negative TTL: the row exists, and is past.
	token, err := h.store.CreateSession(context.Background(), -time.Minute, "expired")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if live, err := h.store.LookupSession(context.Background(), token); err != nil || live {
		t.Errorf("an expired session was accepted: live=%v err=%v", live, err)
	}

	req, _ := http.NewRequest("GET", h.server.URL+"/api/v1/overview", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an expired session reached the API: status %d, want 401", resp.StatusCode)
	}
}

func TestSessionSecretIsNotStoredInPlaintext(t *testing.T) {
	// The sessions table lives in the same SQLite file as the query log and
	// the feed cache. A database that leaks must not hand over live sessions
	// with it.
	h := newHarness(t)
	h.login()
	token := currentSession(t, h)

	var stored string
	row := h.store.DB().QueryRow(`SELECT token_hash FROM sessions LIMIT 1`)
	if err := row.Scan(&stored); err != nil {
		t.Fatalf("read sessions table: %v", err)
	}
	if stored == token {
		t.Fatal("the session token is stored verbatim; a database copy would be a set of live sessions")
	}
	if len(stored) != 64 {
		t.Errorf("token_hash = %q, want a 64-character SHA-256 hex digest", stored)
	}
}

func TestLegacySessionKeyIsRetired(t *testing.T) {
	// Nothing reads <data_dir>/session.key any more. Leaving a 32-byte file
	// with that name in place would have an operator protecting a secret that
	// grants nothing, and a reviewer assuming it is load-bearing.
	dir := t.TempDir()
	path := dir + "/session.key"
	if err := writeFile(path, []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}

	if _, err := NewAuth(newTestStore(t), dir, AuthOptions{}); err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	if fileExists(path) {
		t.Error("the obsolete session.key was left in the data directory")
	}
}

func TestPurgeExpiredSessionsLeavesLiveOnesAlone(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	live, err := h.store.CreateSession(ctx, time.Hour, "live")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CreateSession(ctx, -time.Hour, "dead"); err != nil {
		t.Fatal(err)
	}

	n, err := h.store.PurgeExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("PurgeExpiredSessions: %v", err)
	}
	if n != 1 {
		t.Errorf("purged %d sessions, want 1", n)
	}
	if ok, err := h.store.LookupSession(ctx, live); err != nil || !ok {
		t.Errorf("the live session was purged: ok=%v err=%v", ok, err)
	}
}

func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
