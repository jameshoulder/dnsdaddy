package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/querylog"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

const testPassword = "correct-horse-battery-staple"

type harness struct {
	t        *testing.T
	server   *httptest.Server
	store    *store.Store
	client   *http.Client
	detector *detect.Engine
	// lists is the live blocklist index the API and DNS handler share, so a
	// test can assert what a refresh actually made blockable.
	lists *blocklist.Holder
	// feeds is the same manager the API holds, so a test can rebuild the index
	// from disk the way a restart does.
	feeds *blocklist.Manager
	// acl is the live client ACL the DNS handler reads, so a test can assert
	// that a permission granted through the API is in force without a restart.
	acl *clientacl.Controller
	// failACLReload breaks the ACL reload without breaking the write it
	// follows, which is the only way to reach "stored but not in force".
	failACLReload *atomic.Bool
	// holdACLReload parks the next reload inside the handler's write lock, so
	// a test can check what a concurrent write is prevented from doing.
	holdACLReload *atomic.Pointer[chan struct{}]
	// dir is the data directory, kept so a test can reopen the database and
	// check that a setting survived a restart.
	dir string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	lists := blocklist.NewHolder()
	b := blocklist.NewBuilder(4)
	b.Add("evil.com", blocklist.Entry{Category: "malware", FeedID: "f_test", FeedName: "Test feed"})
	lists.Store(b.Build())

	cfg := config.Default()
	cfg.DataDir = dir
	cfg.DNS.Upstreams = []string{"udp://127.0.0.1:65353"} // unreachable; DoH tests only need blocks

	engine := policy.NewEngine(st, lists)
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("engine.Reload: %v", err)
	}

	feeds, err := blocklist.NewManager(st, lists, cfg.Feeds, dir, log)
	if err != nil {
		t.Fatalf("blocklist.NewManager: %v", err)
	}

	res, err := resolver.New(cfg.DNS, cfg.Cache, log)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}
	t.Cleanup(res.Close)

	qlog := querylog.New(st, querylog.Options{BufferSize: 64, FlushIntervalMS: 20}, log)
	ctx, cancel := context.WithCancel(context.Background())
	go qlog.Run(ctx)
	t.Cleanup(func() {
		cancel()
		qlog.Wait()
	})

	// The detection engine is wired in so the findings endpoints are exercised
	// against a real engine rather than a stub. It is not Run() here: the tests
	// that need findings insert them directly, which keeps them deterministic
	// rather than dependent on an evaluation tick.
	detector := detect.New(
		[]detect.Detector{detect.NewTunnelDetector(detect.DefaultTunnelConfig())},
		detect.NewStoreSink(st),
		detect.NewExclusions(nil, false),
		detect.Options{},
		log,
	)

	// The live client ACL, built from the same configuration the daemon uses,
	// so the handler and the API agree on who may resolve — and so a test that
	// grants a network access exercises the real reload path rather than a
	// stub that cannot be wrong.
	// failACLReload lets a test break the reload without breaking the write it
	// follows. Those are separate failures in production — a transient
	// database error between the commit and the reload — and there is no
	// other way to reach the path where a change is stored but not in force.
	//
	// holdACLReload blocks inside the reload, which runs while the handler
	// holds API.networkWrites. That is the only seam from which a test can
	// observe whether a second network write is being kept out.
	var (
		failACLReload atomic.Bool
		holdACLReload atomic.Pointer[chan struct{}]
	)
	acl := clientacl.NewController(cfg.DNS.AllowedClientCIDRs, cfg.DNS.AllowPublicResolver,
		func(ctx context.Context) ([]clientacl.Network, error) {
			if hold := holdACLReload.Swap(nil); hold != nil {
				<-*hold
			}
			if failACLReload.Load() {
				return nil, errors.New("simulated reload failure")
			}
			networks, err := st.ListNetworks(ctx)
			if err != nil {
				return nil, err
			}
			return store.ClientACLNetworks(networks), nil
		})
	if err := acl.Reload(context.Background()); err != nil {
		t.Fatalf("clientacl.Reload: %v", err)
	}

	dnsHandler := dnsserver.NewHandler(engine, res, lists, qlog, log, dnsserver.HandlerOptions{
		QueryLogEnabled: true,
		ClientACL:       acl,
		Detector:        detector,
	})

	auth, err := NewAuth(st, dir, AuthOptions{})
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	if _, err := auth.EnsureAdminPassword(context.Background(), testPassword, dir); err != nil {
		t.Fatalf("EnsureAdminPassword: %v", err)
	}

	api := New(Deps{
		Config:   cfg,
		Store:    st,
		Engine:   engine,
		Feeds:    feeds,
		Lists:    lists,
		Resolver: res,
		DNS:      dnsHandler,
		DoH: dnsserver.NewDoHHandler(dnsHandler, st, log, dnsserver.DoHOptions{
			// Tests exercise the bare /dns-query path directly; the
			// token-required default is covered by its own test below.
			AllowUntokenized: true,
		}),
		QueryLog:  qlog,
		Detector:  detector,
		Auth:      auth,
		Log:       log,
		ClientACL: acl,
		StartedAt: time.Now(),
	})

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	jar := &cookieJar{cookies: map[string]*http.Cookie{}}
	return &harness{
		t: t, server: srv, store: st, acl: acl, failACLReload: &failACLReload,
		holdACLReload: &holdACLReload,
		client:        &http.Client{Jar: jar},
		detector:      detector, lists: lists, feeds: feeds, dir: dir,
	}
}

// reopen opens a second store over the same database file, which is what a
// restart amounts to: the schema is reapplied and the defaults are re-seeded.
// Anything the operator chose has to survive that.
func (h *harness) reopen(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(h.dir, "test.db"))
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// cookieJar is a minimal same-origin jar; net/http/cookiejar needs a
// public-suffix list to behave for 127.0.0.1.
type cookieJar struct{ cookies map[string]*http.Cookie }

func (j *cookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		if c.MaxAge < 0 {
			delete(j.cookies, c.Name)
			continue
		}
		j.cookies[c.Name] = c
	}
}

func (j *cookieJar) Cookies(_ *url.URL) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(j.cookies))
	for _, c := range j.cookies {
		out = append(out, c)
	}
	return out
}

func (h *harness) do(method, path string, body any) (*http.Response, []byte) {
	h.t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read body: %v", err)
	}
	return resp, raw
}

func (h *harness) login() {
	h.t.Helper()
	resp, raw := h.do("POST", "/api/v1/auth/login", map[string]string{"password": testPassword})
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("login: status %d, body %s", resp.StatusCode, raw)
	}
}

func decode[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return out
}

func TestHealthIsUnauthenticated(t *testing.T) {
	h := newHarness(t)

	resp, raw := h.do("GET", "/api/v1/health", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	body := decode[map[string]any](t, raw)
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok (the test index is non-empty)", body["status"])
	}
}

func TestManagementEndpointsRequireAuth(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/api/v1/overview", "/api/v1/networks", "/api/v1/policies",
		"/api/v1/feeds", "/api/v1/queries", "/api/v1/settings",
		"/api/v1/tokens", "/api/v1/reports/summary", "/metrics",
	} {
		resp, _ := h.do("GET", path, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without auth returned %d, want 401", path, resp.StatusCode)
		}
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	h := newHarness(t)

	resp, _ := h.do("POST", "/api/v1/auth/login", map[string]string{"password": "wrong"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", resp.StatusCode)
	}

	resp, _ = h.do("GET", "/api/v1/overview", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Error("a failed login still produced a usable session")
	}
}

func TestLoginRateLimited(t *testing.T) {
	h := newHarness(t)

	var limited bool
	for i := 0; i < 20; i++ {
		resp, _ := h.do("POST", "/api/v1/auth/login", map[string]string{"password": "wrong"})
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("password guessing was never rate limited")
	}
}

func TestSessionFlow(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("GET", "/api/v1/overview", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overview after login: %d, body %s", resp.StatusCode, raw)
	}

	overview := decode[Overview](t, raw)
	if overview.BlocklistDomains != 1 {
		t.Errorf("blocklistDomains = %d, want 1", overview.BlocklistDomains)
	}
	if overview.ProtectedNetworks != 1 {
		t.Errorf("protectedNetworks = %d, want the seeded network", overview.ProtectedNetworks)
	}

	h.do("POST", "/api/v1/auth/logout", nil)
	resp, _ = h.do("GET", "/api/v1/overview", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Error("the session survived logout")
	}
}

func TestAPITokenAuthentication(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("POST", "/api/v1/tokens", map[string]string{"name": "control-centre"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: %d, body %s", resp.StatusCode, raw)
	}
	token := decode[store.APIToken](t, raw)
	if !strings.HasPrefix(token.Secret, "dnsd_") {
		t.Errorf("secret %q does not carry the dnsd_ prefix", token.Secret)
	}

	// A bearer token must work without any cookie.
	req, _ := http.NewRequest("GET", h.server.URL+"/api/v1/overview", nil)
	req.Header.Set("Authorization", "Bearer "+token.Secret)
	bare := &http.Client{}
	tokenResp, err := bare.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		t.Errorf("bearer-token request returned %d, want 200", tokenResp.StatusCode)
	}

	// A wrong token must not.
	req2, _ := http.NewRequest("GET", h.server.URL+"/api/v1/overview", nil)
	req2.Header.Set("Authorization", "Bearer dnsd_not-a-real-token")
	badResp, err := bare.Do(req2)
	if err != nil {
		t.Fatalf("bad token request: %v", err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an invalid bearer token returned %d, want 401", badResp.StatusCode)
	}
}

func TestNetworkCRUD(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("POST", "/api/v1/networks", map[string]any{
		"name":     "Warehouse",
		"location": "Slough",
		"cidrs":    []string{"10.4.9.0/24"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d, body %s", resp.StatusCode, raw)
	}
	created := decode[store.Network](t, raw)
	if created.Token == "" {
		t.Error("no DoH token issued for the new network")
	}

	resp, raw = h.do("PATCH", "/api/v1/networks/"+created.ID, map[string]any{"location": "Slough, UK"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch: %d, body %s", resp.StatusCode, raw)
	}
	if decode[store.Network](t, raw).Location != "Slough, UK" {
		t.Error("patch did not apply")
	}

	resp, _ = h.do("DELETE", "/api/v1/networks/"+created.ID, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: %d, want 204", resp.StatusCode)
	}

	resp, _ = h.do("GET", "/api/v1/networks/"+created.ID, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("get after delete: %d, want 404", resp.StatusCode)
	}
}

func TestNetworkRejectsBadCIDR(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, _ := h.do("POST", "/api/v1/networks", map[string]any{
		"name":  "Broken",
		"cidrs": []string{"not-a-cidr"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestPolicyRuleRoundTrip(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("POST", "/api/v1/policies/p_standard/rules", map[string]string{
		"kind": "allow", "domain": "supplier.example.com", "note": "ticket 4412",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add rule: %d, body %s", resp.StatusCode, raw)
	}
	p := decode[store.Policy](t, raw)
	if len(p.AllowDomains) != 1 || p.AllowDomains[0] != "supplier.example.com" {
		t.Fatalf("allow list = %v", p.AllowDomains)
	}

	resp, _ = h.do("DELETE", "/api/v1/policies/p_standard/rules/allow/supplier.example.com", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete rule: %d", resp.StatusCode)
	}

	_, raw = h.do("GET", "/api/v1/policies/p_standard", nil)
	if len(decode[store.Policy](t, raw).AllowDomains) != 0 {
		t.Error("the rule survived deletion")
	}
}

func TestPolicyRejectsUnknownCategory(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, _ := h.do("PATCH", "/api/v1/policies/p_standard", map[string]any{
		"categories": []string{"malware", "not-a-real-category"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestUnknownJSONFieldsRejected(t *testing.T) {
	// Silently ignoring a misspelled field would let an operator believe they
	// had changed a setting they had not.
	h := newHarness(t)
	h.login()

	resp, _ := h.do("PATCH", "/api/v1/policies/p_standard", map[string]any{"catagories": []string{"malware"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400 for a misspelled field", resp.StatusCode)
	}
}

func TestChangePassword(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, _ := h.do("POST", "/api/v1/auth/password", map[string]string{
		"currentPassword": "wrong", "newPassword": "a-much-longer-new-password",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong current password returned %d, want 400", resp.StatusCode)
	}

	resp, _ = h.do("POST", "/api/v1/auth/password", map[string]string{
		"currentPassword": testPassword, "newPassword": "short",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a too-short password was accepted (%d)", resp.StatusCode)
	}

	resp, raw := h.do("POST", "/api/v1/auth/password", map[string]string{
		"currentPassword": testPassword, "newPassword": "a-much-longer-new-password",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change password: %d, body %s", resp.StatusCode, raw)
	}

	h.do("POST", "/api/v1/auth/logout", nil)
	resp, _ = h.do("POST", "/api/v1/auth/login", map[string]string{"password": "a-much-longer-new-password"})
	if resp.StatusCode != http.StatusOK {
		t.Error("could not log in with the new password")
	}
}

func TestReportMarkdown(t *testing.T) {
	h := newHarness(t)
	h.login()

	// Record a block so the report has something to say.
	now := time.Now().UTC()
	err := h.store.InsertQueryBatch(context.Background(), []store.QueryEvent{
		{Time: now, NetworkID: "n_default", Domain: "evil.com", QType: "A",
			Action: store.ActionBlocked, Category: "malware"},
	}, true)
	if err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}

	resp, raw := h.do("GET", "/api/v1/reports/summary?days=7&format=markdown", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("Content-Type = %q, want text/markdown", ct)
	}

	md := string(raw)
	for _, want := range []string{"# Protective DNS report", "evil.com", "Threats blocked", "Malware"} {
		if !strings.Contains(md, want) {
			t.Errorf("report is missing %q", want)
		}
	}
}

func TestMetricsExposition(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("GET", "/metrics", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body := string(raw)
	for _, want := range []string{
		"# TYPE dnsdaddy_queries_total counter",
		"dnsdaddy_blocklist_domains 1",
		"dnsdaddy_build_info",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output is missing %q", want)
		}
	}
}

func TestOpenAPIServed(t *testing.T) {
	h := newHarness(t)

	resp, raw := h.do("GET", "/openapi.yaml", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.HasPrefix(string(raw), "openapi: 3.1.0") {
		t.Error("the served document does not look like an OpenAPI spec")
	}
	if !strings.Contains(string(raw), "/api/v1/overview") {
		t.Error("the spec does not document the overview endpoint")
	}
}

func TestDoHBlocksListedDomain(t *testing.T) {
	h := newHarness(t)

	q := new(dns.Msg)
	q.SetQuestion("evil.com.", dns.TypeA)
	packed, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	resp, err := http.Post(h.server.URL+"/dns-query", "application/dns-message", bytes.NewReader(packed))
	if err != nil {
		t.Fatalf("DoH POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Errorf("Content-Type = %q", ct)
	}
	// A browser must not be tempted to sniff and reinterpret raw DNS wire
	// format as something else.
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}

	raw, _ := io.ReadAll(resp.Body)
	answer := new(dns.Msg)
	if err := answer.Unpack(raw); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if answer.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[answer.Rcode])
	}
}

func TestDoHGetForm(t *testing.T) {
	h := newHarness(t)

	q := new(dns.Msg)
	q.SetQuestion("evil.com.", dns.TypeA)
	packed, _ := q.Pack()
	encoded := base64.RawURLEncoding.EncodeToString(packed)

	resp, err := http.Get(h.server.URL + "/dns-query?dns=" + encoded)
	if err != nil {
		t.Fatalf("DoH GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
}

func TestDoHRejectsUnknownToken(t *testing.T) {
	// Falling back to IP attribution here would silently apply the wrong
	// policy to a roaming device.
	h := newHarness(t)

	q := new(dns.Msg)
	q.SetQuestion("evil.com.", dns.TypeA)
	packed, _ := q.Pack()

	resp, err := http.Post(h.server.URL+"/dns-query/notarealtoken",
		"application/dns-message", bytes.NewReader(packed))
	if err != nil {
		t.Fatalf("DoH POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404 for an unknown resolver token", resp.StatusCode)
	}
}

func TestDoHRejectsGarbage(t *testing.T) {
	h := newHarness(t)

	resp, err := http.Post(h.server.URL+"/dns-query", "application/dns-message",
		strings.NewReader("this is not a dns message"))
	if err != nil {
		t.Fatalf("DoH POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestDashboardServedWithSecurityHeaders(t *testing.T) {
	h := newHarness(t)

	resp, raw := h.do("GET", "/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(string(raw), "DNS Daddy") {
		t.Error("the dashboard HTML was not served")
	}

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no Content-Security-Policy header")
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Error("the CSP allows inline script or style")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options; the dashboard could be framed")
	}
}

func TestDashboardAssetsServed(t *testing.T) {
	h := newHarness(t)

	for path, want := range map[string]string{
		"/app.css":     "text/css",
		"/app.js":      "javascript",
		"/favicon.svg": "image/svg",
	} {
		resp, raw := h.do("GET", path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status %d", path, resp.StatusCode)
			continue
		}
		if len(raw) == 0 {
			t.Errorf("GET %s returned an empty body", path)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, want) {
			t.Errorf("GET %s Content-Type = %q, want it to contain %q", path, ct, want)
		}
	}
}
