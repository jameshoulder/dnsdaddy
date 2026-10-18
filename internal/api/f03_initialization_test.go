package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func freshF03(t *testing.T) (*Auth, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, e := store.Open(filepath.Join(dir, "auth.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { st.Close() })
	a, e := NewAuth(st, dir, AuthOptions{})
	if e != nil {
		t.Fatal(e)
	}
	return a, st, dir
}
func TestF03FreshInitializationAndInvalidConfiguration(t *testing.T) {
	for i, password := range []string{"synthetic-valid-password", strings.Repeat("a", 72), strings.Repeat("é", 12)} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			a, st, dir := freshF03(t)
			if returned, e := a.EnsureAdminPassword(context.Background(), password, dir); e != nil || returned != "" {
				t.Fatal("configured bootstrap failed")
			}
			c, e := st.ReadAdminCredential(context.Background())
			if e != nil || !a.CheckPassword(context.Background(), password) {
				t.Fatal("initial credential invalid")
			}
			if cost, e := bcrypt.Cost([]byte(c.Hash)); e != nil || cost != bcrypt.DefaultCost {
				t.Fatal("password hashing cost changed")
			}
			if _, e := os.Lstat(filepath.Join(dir, initialPasswordName)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("configured bootstrap created secret file")
			}
		})
	}
	for _, password := range []string{"short", strings.Repeat("a", 11), strings.Repeat("a", 73), strings.Repeat("é", 37), string([]byte{0xff}) + strings.Repeat("a", 15)} {
		t.Run("invalid-"+fmt.Sprint(len(password)), func(t *testing.T) {
			a, st, dir := freshF03(t)
			if returned, e := a.EnsureAdminPassword(context.Background(), password, dir); !errors.Is(e, ErrPasswordPolicy) || returned != "" {
				t.Fatal("invalid initial credential accepted")
			}
			c, e := st.ReadAdminCredential(context.Background())
			if e != nil || c.Hash != "" || c.State != store.AuthBootstrapPending {
				t.Fatal("invalid input mutated credential")
			}
		})
	}
}
func TestF03GeneratedPasswordFileAndNormalRestart(t *testing.T) {
	a, st, dir := freshF03(t)
	ctx := context.Background()
	password, e := a.EnsureAdminPassword(ctx, "", dir)
	if e != nil || password == "" {
		t.Fatal("generated bootstrap failed")
	}
	file, err := os.Stat(filepath.Join(dir, initialPasswordName))
	if err != nil || file.Mode().Perm() != 0o600 {
		t.Fatal("unsafe initial file mode")
	}
	read, e := readInitialPassword(dir)
	if e != nil || read != password || !a.CheckPassword(ctx, password) {
		t.Fatal("generated credential not delivered consistently")
	}
	before, e := st.ReadAdminCredential(ctx)
	if e != nil {
		t.Fatal(e)
	}
	token, e := a.Login(ctx, password, "synthetic")
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(dir, initialPasswordName)); e != nil {
		t.Fatal(e)
	}
	if generated, e := a.EnsureAdminPassword(ctx, "synthetic-stale-bootstrap", dir); e != nil || generated != "" {
		t.Fatal("active account regenerated")
	}
	after, e := st.ReadAdminCredential(ctx)
	if e != nil || after != before {
		t.Fatal("active hash changed")
	}
	if live, e := st.LookupSession(ctx, token); e != nil || !live {
		t.Fatal("normal startup revoked session")
	}
	if _, e := os.Lstat(filepath.Join(dir, initialPasswordName)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("startup recreated delivery file")
	}
}
func TestF03InterruptedGeneratedDelivery(t *testing.T) {
	const password = "synthetic-generated-password"
	for _, kind := range []string{"matching", "missing", "wrong", "partial", "symlink", "hardlink", "permissions", "directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			a, st, dir := freshF03(t)
			ctx := context.Background()
			hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = st.InitializeAdminCredential(ctx, string(hash), true); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(dir, initialPasswordName)
			switch kind {
			case "matching":
				if e = writeInitialPassword(dir, password); e != nil {
					t.Fatal(e)
				}
			case "wrong":
				e = writeInitialPassword(dir, "synthetic-wrong-password")
			case "partial":
				e = os.WriteFile(path, []byte("synthetic-partial"), 0o600)
			case "symlink":
				e = os.Symlink("auth.db", path)
			case "hardlink":
				target := filepath.Join(dir, "other")
				e = os.WriteFile(target, []byte(initialPasswordContent(password)), 0o600)
				if e == nil {
					e = os.Link(target, path)
				}
			case "permissions":
				e = os.WriteFile(path, []byte(initialPasswordContent(password)), 0o644)
			case "directory":
				e = os.Mkdir(path, 0o700)
			case "fifo":
				e = syscall.Mkfifo(path, 0o600)
			}
			if e != nil {
				t.Fatal("fixture failed")
			}
			result, e := a.EnsureAdminPassword(ctx, "synthetic-ignored-bootstrap", dir)
			if kind == "matching" {
				if e != nil || result != password || !a.CheckPassword(ctx, password) {
					t.Fatal("matching delivery did not resume")
				}
			} else {
				if !errors.Is(e, ErrPasswordBootstrap) || result != "" {
					t.Fatal("unsafe interrupted delivery activated")
				}
				c, err := st.ReadAdminCredential(ctx)
				if err != nil || c.Hash != string(hash) || c.State != store.AuthBootstrapPending {
					t.Fatal("pending credential changed")
				}
				if a.CheckPassword(ctx, password) {
					t.Fatal("pending password authenticated")
				}
				if _, err := st.CreateSessionAtRevision(ctx, 0, sessionTTL, "pending"); err == nil {
					t.Fatal("pending state issued session")
				}
			}
		})
	}
}
func TestF03InitialFileNeverOverwritesExistingContent(t *testing.T) {
	a, st, dir := freshF03(t)
	path := filepath.Join(dir, initialPasswordName)
	body := []byte("synthetic-existing-file")
	if e := os.WriteFile(path, body, 0o600); e != nil {
		t.Fatal(e)
	}
	returned, e := a.EnsureAdminPassword(context.Background(), "", dir)
	if !errors.Is(e, ErrPasswordBootstrap) || returned != "" {
		t.Fatal("conflicting file activated credential")
	}
	got, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(got, body) {
		t.Fatal("conflicting file overwritten")
	}
	c, e := st.ReadAdminCredential(context.Background())
	if e != nil || c.State != store.AuthBootstrapPending {
		t.Fatal("failed file delivery activated credential")
	}
}
func TestF03PasswordBoundaries(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{{strings.Repeat("a", 11), false}, {strings.Repeat("a", 12), true}, {strings.Repeat("a", 71), true}, {strings.Repeat("a", 72), true}, {strings.Repeat("a", 73), false}, {strings.Repeat("é", 11), false}, {strings.Repeat("é", 12), true}, {strings.Repeat("é", 36), true}, {strings.Repeat("é", 37), false}, {"  synthetic-password  ", true}} {
		if (validateNewPassword(tc.value) == nil) != tc.valid {
			t.Fatal("password byte/character policy mismatch")
		}
	}
}
func TestF03ConfigPrecedenceCannotReplaceStoredHash(t *testing.T) {
	a, st, dir := freshF03(t)
	ctx := context.Background()
	const password = "synthetic-current-password"
	if _, e := a.EnsureAdminPassword(ctx, password, dir); e != nil {
		t.Fatal(e)
	}
	before, e := st.ReadAdminCredential(ctx)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "config.yaml")
	if e := os.WriteFile(path, []byte("http:\n  admin_password: synthetic-stale-yaml-password\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"synthetic-stale-env-password", "", strings.Repeat("x", 73)} {
		t.Setenv("DNSDADDY_ADMIN_PASSWORD", v)
		cfg, e := config.Load(path)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = a.EnsureAdminPassword(ctx, cfg.HTTP.AdminPassword, dir); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Unsetenv("DNSDADDY_ADMIN_PASSWORD"); e != nil {
		t.Fatal(e)
	}
	cfg, e := config.Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.EnsureAdminPassword(ctx, cfg.HTTP.AdminPassword, dir); e != nil {
		t.Fatal(e)
	}
	after, e := st.ReadAdminCredential(ctx)
	if e != nil || after != before {
		t.Fatal("bootstrap config replaced stored hash")
	}
}
func TestF03AuthErrorsNeverExposeDatabasePayload(t *testing.T) {
	h := newHarness(t)
	h.login()
	var logs bytes.Buffer
	h.api.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	const marker = "synthetic-secret-db-token"
	if _, e := h.store.DB().Exec("CREATE TRIGGER auth_fault BEFORE UPDATE ON settings BEGIN SELECT RAISE(ABORT,'" + marker + "'); END"); e != nil {
		t.Fatal(e)
	}
	resp, body := h.do("POST", "/api/v1/auth/password", map[string]string{"currentPassword": testPassword, "newPassword": "synthetic-replacement-password"})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("password storage error misreported")
	}
	if strings.Contains(string(body)+logs.String(), marker) || strings.Contains(string(body)+logs.String(), testPassword) {
		t.Fatal("authentication error exposed credentials")
	}
	// Login storage failures must also be static, not arbitrary DB error text.
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"password":"synthetic-request-password"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.store.Close()
	h.api.handleLogin(w, req)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String()+logs.String(), "synthetic-request-password") {
		t.Fatal("unsafe login storage failure")
	}
}

func TestF03GeneratedActivationFailureCanResume(t *testing.T) {
	a, st, dir := freshF03(t)
	ctx := context.Background()
	if _, e := st.DB().Exec("CREATE TRIGGER fail_activation BEFORE UPDATE ON admin_auth_state WHEN NEW.state='active' BEGIN SELECT RAISE(ABORT,'synthetic-secret'); END"); e != nil {
		t.Fatal(e)
	}
	if result, e := a.EnsureAdminPassword(ctx, "", dir); !errors.Is(e, store.ErrAdminStorage) || result != "" {
		t.Fatal("failed activation returned credential")
	}
	before, e := st.ReadAdminCredential(ctx)
	if e != nil || before.State != store.AuthBootstrapPending || before.Hash == "" {
		t.Fatal("activation failure lost pending credential")
	}
	delivered, e := readInitialPassword(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := st.DB().Exec("DROP TRIGGER fail_activation"); e != nil {
		t.Fatal(e)
	}
	result, e := a.EnsureAdminPassword(ctx, "synthetic-stale-config", dir)
	if e != nil || result != delivered {
		t.Fatal("safe activation recovery failed")
	}
	after, e := st.ReadAdminCredential(ctx)
	if e != nil || after.Hash != before.Hash || after.State != store.AuthActive {
		t.Fatal("recovery replaced credential")
	}
}
func TestF03MalformedActiveHashNeverFallsBackToConfig(t *testing.T) {
	a, st, dir := freshF03(t)
	ctx := context.Background()
	if _, e := a.EnsureAdminPassword(ctx, "synthetic-initial-password", dir); e != nil {
		t.Fatal(e)
	}
	if _, e := st.DB().Exec("UPDATE settings SET value='synthetic-broken-hash' WHERE key=?", store.AdminPasswordHashKey); e != nil {
		t.Fatal(e)
	}
	if result, e := a.EnsureAdminPassword(ctx, "synthetic-bootstrap-replacement", dir); !errors.Is(e, store.ErrAdminRecovery) || result != "" {
		t.Fatal("malformed active hash reset")
	}
	value, e := st.GetSetting(ctx, store.AdminPasswordHashKey)
	if e != nil || value != "synthetic-broken-hash" {
		t.Fatal("broken stored credential overwritten")
	}
}
func TestF03RotationAuditAndLogsDoNotContainCredentials(t *testing.T) {
	h := newHarness(t)
	h.login()
	var logs bytes.Buffer
	h.api.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	token := currentSession(t, h)
	before, e := h.store.GetSetting(context.Background(), store.AdminPasswordHashKey)
	if e != nil {
		t.Fatal(e)
	}
	const next = "synthetic-audited-password"
	response, body := h.do("POST", "/api/v1/auth/password", map[string]string{"currentPassword": testPassword, "newPassword": next})
	if response.StatusCode != http.StatusOK {
		t.Fatal("password rotation failed")
	}
	after, e := h.store.GetSetting(context.Background(), store.AdminPasswordHashKey)
	if e != nil {
		t.Fatal(e)
	}
	events, _, e := h.store.ListConfigChanges(context.Background(), 0, 50)
	if e != nil {
		t.Fatal(e)
	}
	audit, e := json.Marshal(events)
	if e != nil {
		t.Fatal(e)
	}
	combined := string(body) + logs.String() + string(audit)
	for _, secret := range []string{testPassword, next, before, after, token} {
		if strings.Contains(combined, secret) {
			t.Fatal("credential appeared in auth diagnostics/history")
		}
	}
	if live, _ := h.store.LookupSession(context.Background(), token); live {
		t.Fatal("old session not invalidated")
	}
}

func TestF03ConcurrentPasswordChangesHaveOneWinner(t *testing.T) {
	a, _, dir := freshF03(t)
	ctx := context.Background()
	const old = "synthetic-old-password"
	if _, e := a.EnsureAdminPassword(ctx, old, dir); e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, next := range []string{"synthetic-new-password-one", "synthetic-new-password-two"} {
		go func(next string) { <-start; errs <- a.SetPassword(ctx, old, next) }(next)
	}
	close(start)
	wins := 0
	for range 2 {
		e := <-errs
		if e == nil {
			wins++
		} else if !errors.Is(e, ErrPasswordIncorrect) && !errors.Is(e, store.ErrAdminConflict) {
			t.Fatal("unexpected concurrent auth result")
		}
	}
	if wins != 1 || a.CheckPassword(ctx, old) {
		t.Fatal("concurrent changes violated credential authority")
	}
	one := a.CheckPassword(ctx, "synthetic-new-password-one")
	two := a.CheckPassword(ctx, "synthetic-new-password-two")
	if one == two {
		t.Fatal("expected one effective password")
	}
}
