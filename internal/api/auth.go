package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jameshoulder/dnsdaddy/internal/httpx"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

const (
	settingAdminHash = "admin_password_hash"
	sessionCookie    = "dnsdaddy_session"
	sessionTTL       = 12 * time.Hour
)

// Auth handles dashboard sessions and API-token authentication.
type Auth struct {
	store  *store.Store
	secret []byte

	secureCookies  string
	trustedProxies *httpx.TrustedProxies

	// limiter slows password guessing. The dashboard is expected to sit behind
	// a firewall, but "expected to" is not a control.
	limiter *attemptLimiter
}

// AuthOptions configures cookie and proxy behaviour.
type AuthOptions struct {
	// SecureCookies is "auto", "always", or "never". Empty means "auto".
	SecureCookies string
	// TrustedProxies bounds which peers' forwarding headers are believed.
	TrustedProxies *httpx.TrustedProxies
}

// NewAuth loads or creates the session-signing secret under dataDir.
func NewAuth(st *store.Store, dataDir string, o AuthOptions) (*Auth, error) {
	secret, err := loadOrCreateSecret(filepath.Join(dataDir, "session.key"))
	if err != nil {
		return nil, err
	}
	mode := o.SecureCookies
	if mode == "" {
		mode = "auto"
	}
	trusted := o.TrustedProxies
	if trusted == nil {
		trusted = &httpx.TrustedProxies{}
	}
	return &Auth{
		store:          st,
		secret:         secret,
		secureCookies:  mode,
		trustedProxies: trusted,
		limiter:        newAttemptLimiter(10, 15*time.Minute),
	}, nil
}

func loadOrCreateSecret(path string) ([]byte, error) {
	// #nosec G304 -- path is <data_dir>/session.key, built from operator config,
	// never from a request.
	b, err := os.ReadFile(path)
	if err == nil && len(b) >= 32 {
		return b, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read session key: %w", err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, fmt.Errorf("write session key: %w", err)
	}
	return secret, nil
}

// EnsureAdminPassword sets the admin password from configuration, or generates
// one on first run.
//
// The generated password is written to dataDir/initial-password.txt with 0600
// and returned so the caller can print it once. Writing it to a file rather
// than only logging it means an operator who missed the boot output is not
// locked out of their own resolver.
func (a *Auth) EnsureAdminPassword(ctx context.Context, configured, dataDir string) (generated string, err error) {
	if configured != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(configured), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
		return "", a.store.SetSetting(ctx, settingAdminHash, string(hash))
	}

	if _, err := a.store.GetSetting(ctx, settingAdminHash); err == nil {
		return "", nil // already configured
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}

	password := generatePassword()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	if err := a.store.SetSetting(ctx, settingAdminHash, string(hash)); err != nil {
		return "", err
	}

	path := filepath.Join(dataDir, "initial-password.txt")
	content := fmt.Sprintf("DNS Daddy initial admin password: %s\n\nChange it from Settings, then delete this file.\n", password)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return password, fmt.Errorf("write %s: %w", path, err)
	}
	return password, nil
}

func generatePassword() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic("dnsdaddy: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// CheckPassword verifies the admin password.
func (a *Auth) CheckPassword(ctx context.Context, password string) bool {
	hash, err := a.store.GetSetting(ctx, settingAdminHash)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// SetPassword replaces the admin password after verifying the current one.
func (a *Auth) SetPassword(ctx context.Context, current, next string) error {
	if !a.CheckPassword(ctx, current) {
		return errors.New("current password is incorrect")
	}
	if len(next) < 12 {
		return errors.New("new password must be at least 12 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return a.store.SetSetting(ctx, settingAdminHash, string(hash))
}

// issueSession returns a signed session value of the form "<expiry>.<mac>".
func (a *Auth) issueSession() string {
	exp := time.Now().Add(sessionTTL).Unix()
	payload := strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

func (a *Auth) validSession(value string) bool {
	payload, sig, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payload))
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}
	exp, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() < exp
}

// secureFlag decides the session cookie's Secure attribute.
//
// Semgrep's cookie-missing-secure rule wants an unconditional `true`. That
// would be wrong for this product: DNS Daddy is self-hosted software that
// legitimately runs on plain HTTP inside a LAN, and a browser will not send a
// Secure cookie back over HTTP — so hard-coding true would make login
// impossible for a large share of real deployments.
//
// Instead the operator gets an explicit setting (http.secure_cookies) that
// defaults to detecting TLS per request, and the detection only believes
// X-Forwarded-Proto from a configured trusted proxy. Deployments that
// terminate TLS should set "always"; docs/deploy.md says so in the TLS
// section, and the security-posture warning at startup nags about it.
func (a *Auth) secureFlag(r *http.Request) bool {
	switch a.secureCookies {
	case "always":
		return true
	case "never":
		return false
	default: // "auto"
		return httpx.IsHTTPS(r, a.trustedProxies)
	}
}

// SetSessionCookie writes the session cookie on a successful login.
func (a *Auth) SetSessionCookie(w http.ResponseWriter, r *http.Request) {
	// Secure is conditional, not absent. secureFlag resolves http.secure_cookies:
	// "always" and "never" are literal, and "auto" (the default) sets the flag
	// whenever the request genuinely arrived over TLS — either r.TLS != nil, or
	// X-Forwarded-Proto: https from a peer whose address falls inside
	// http.trusted_proxy_cidrs, checked by httpx.TrustedProxies.Trusts. A
	// forwarding header from any other peer is ignored, so a direct client
	// cannot talk us into either answer.
	//
	// Hard-coding Secure: true would break the supported plain-HTTP deployment
	// on loopback or a trusted private network: the browser accepts the cookie
	// and then never sends it back, so nobody can log in. See SECURITY.md,
	// "Management access policy".
	//
	// Proven by TestSecureCookieModes, TestSecureCookieAutoHonoursTrustedProxyOnly,
	// and httpx.TestIsHTTPS / TestIsHTTPSWithTLS.
	//
	// #nosec G124 -- HttpOnly and SameSite are set literally; only Secure is
	// computed, and G124 cannot evaluate secureFlag to see that it resolves to
	// true on every TLS request. The suppression covers this one cookie
	// literal, so a future cookie elsewhere is still checked.
	//
	// The nosemgrep below has to be the last line before the statement: Semgrep
	// only honours it on the matched line or the one immediately above, so a
	// blank comment line between the two silently disables the suppression.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    a.issueSession(),
		Path:     "/",
		HttpOnly: true,
		// Lax rather than Strict so following a bookmark into the dashboard
		// keeps you logged in; state-changing requests are additionally
		// protected by the Origin check in requireSameOrigin.
		SameSite: http.SameSiteLaxMode,
		Secure:   a.secureFlag(r),
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

// ClearSessionCookie logs the browser out.
func (a *Auth) ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	// This is a deletion cookie, and it must carry the same attributes as the
	// one it replaces — same secureFlag(r) decision, Path, HttpOnly and
	// SameSite. A browser matches on those, so a mismatch leaves the original
	// session cookie in place and logout silently does nothing.
	//
	// The Secure reasoning is identical to SetSessionCookie above: conditional
	// on a validated TLS determination, and forcing it true would break the
	// supported plain-HTTP mode.
	//
	// Proven by TestClearSessionCookieMatchesSetAttributes.
	//
	// #nosec G124 -- same reasoning as SetSessionCookie, and additionally
	// forced here: the deletion cookie has to carry byte-identical attributes
	// to the one it clears, so hard-coding Secure would leave the live session
	// cookie in place on a plain-HTTP deployment and break logout outright.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   a.secureFlag(r),
		MaxAge:   -1,
	})
}

// sameOrigin reports whether a state-changing, cookie-authenticated request
// came from the dashboard itself.
//
// SameSite=Lax already blocks cross-site POSTs from most browsers, but it is a
// browser-side default that older clients and some embedded webviews do not
// enforce, and it does not cover every navigation shape. For a management
// interface that can repoint a whole network's DNS, an explicit server-side
// check is worth the few lines.
//
// Requests authenticated by bearer token skip this: a token is never attached
// automatically by a browser, so it cannot be driven cross-site.
func sameOrigin(r *http.Request, trusted *httpx.TrustedProxies) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// No Origin: fall back to Referer, which browsers send on form posts.
		// If neither is present the request did not come from a browser page,
		// which is the case for curl and for our own tests.
		if ref := r.Header.Get("Referer"); ref != "" {
			origin = ref
		} else {
			return true
		}
	}

	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}

	// Compare against the Host the request was addressed to. Behind a trusted
	// proxy, X-Forwarded-Host is the browser-visible name.
	want := r.Host
	if trusted.Trusts(httpx.PeerAddr(r)) {
		if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fwd != "" {
			want = fwd
		}
	}
	return strings.EqualFold(u.Host, want)
}

// principal identifies who made a request.
type principal struct {
	kind  string // "session" or "token"
	label string
}

// authenticate resolves the caller, or reports that they are anonymous.
func (a *Auth) authenticate(r *http.Request) (principal, bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		token, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			return principal{}, false
		}
		t, err := a.store.VerifyAPIToken(r.Context(), strings.TrimSpace(token))
		if err != nil {
			return principal{}, false
		}
		return principal{kind: "token", label: t.Name}, true
	}

	c, err := r.Cookie(sessionCookie)
	if err != nil || !a.validSession(c.Value) {
		return principal{}, false
	}
	return principal{kind: "session", label: "admin"}, true
}

// attemptLimiter is a fixed-window counter keyed by client address.
type attemptLimiter struct {
	mu      sync.Mutex
	windows map[string]*window
	max     int
	period  time.Duration
}

type window struct {
	count int
	until time.Time
}

func newAttemptLimiter(max int, period time.Duration) *attemptLimiter {
	return &attemptLimiter{windows: map[string]*window{}, max: max, period: period}
}

// allow records an attempt and reports whether it may proceed.
func (l *attemptLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	// Opportunistically drop expired windows so the map cannot grow without
	// bound under a distributed guessing attempt.
	for k, w := range l.windows {
		if now.After(w.until) {
			delete(l.windows, k)
		}
	}

	w, ok := l.windows[key]
	if !ok || now.After(w.until) {
		l.windows[key] = &window{count: 1, until: now.Add(l.period)}
		return true
	}
	w.count++
	return w.count <= l.max
}

// reset clears the counter after a successful login.
func (l *attemptLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.windows, key)
}
