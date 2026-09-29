package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/secrets"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/jameshoulder/dnsdaddy/internal/webhook"
)

var testPassphrase = []byte("these are isolated recovery test words")

func TestEncryptedStreamAuthenticatesAllRecordsAndTerminator(t *testing.T) {
	plain := bytes.Repeat([]byte("no provider key leaves this envelope\n"), 80000)
	var encrypted bytes.Buffer
	w, err := newSealWriter(&encrypted, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := encrypted.Bytes()
	if bytes.Contains(encoded, plain[:100]) {
		t.Fatal("plaintext appears in backup")
	}
	r, err := newOpenReader(bytes.NewReader(encoded), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v", err)
	}
	cases := map[string][]byte{
		"truncated_header":    encoded[:20],
		"truncated_record":    encoded[:len(encoded)-35],
		"missing_terminal":    encoded[:len(encoded)-20],
		"appended_data":       append(append([]byte{}, encoded...), 42),
		"tampered_ciphertext": append([]byte{}, encoded...),
		"tampered_salt":       append([]byte{}, encoded...),
	}
	cases["tampered_ciphertext"][headerSize+50] ^= 1
	cases["tampered_salt"][18] ^= 1
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := newOpenReader(bytes.NewReader(data), testPassphrase)
			if err == nil {
				_, err = io.Copy(io.Discard, r)
			}
			if err == nil {
				t.Fatal("accepted unauthenticated stream")
			}
		})
	}
	r, err = newOpenReader(bytes.NewReader(encoded), []byte("a different but valid passphrase"))
	if err == nil {
		_, err = io.Copy(io.Discard, r)
	}
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong passphrase: %v", err)
	}
}

func recoveryFixture(t *testing.T) (*Manager, *store.Store, string, string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.EnsureAuditSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, "admin_password_hash", "current-dashboard-password-hash"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, "protection.settings.v1", `{"version":3,"rateLimit":{"enabled":true}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession(ctx, time.Hour, "admin"); err != nil {
		t.Fatal(err)
	}
	provider, err := st.CreateAPIProvider(ctx, store.APIProvider{Name: "Test API", Kind: "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secrets.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	credential := "user-owned-provider-credential-do-not-log"
	sealed, err := ring.Seal([]byte(credential), provider.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProviderSecret(ctx, provider.ID, sealed, ring.KeyID(), "log"); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"daddybound-learning.json": `{"schemaVersion":1,"algorithm":"robust-ewma-v1","baselines":[{"client":"10.0.0.5","samples":20}]}`,
		"daddybound-anchors.json":  `{"zone":".","keys":[],"lastSuccess":"2026-09-29T10:00:00Z"}`,
		"initial-password.txt":     "this retired bootstrap file must not be exported",
		"session.key":              "this legacy key is no longer used",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "feeds"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "feeds", "feed_fixture.list"), []byte("blocked.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(dir, "local-source")
	if err := os.Mkdir(local, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.Feeds.LocalFeedDir = local
	if err := os.WriteFile(filepath.Join(local, "local.txt"), []byte("local-blocked.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st.SetLocalFeedDir(local)
	if _, err := st.DB().Exec(`INSERT INTO feeds(id,name,url,category,created_at,updated_at) VALUES('local-test','Local',?,'malware',0,0)`, "file://"+filepath.Join(local, "local.txt")); err != nil {
		t.Fatal(err)
	}
	cfg.HTTP.AdminPassword = "old-bootstrap-password"
	configPath := filepath.Join(dir, "source.yaml")
	if err := os.WriteFile(configPath, []byte("# original configuration\ndata_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkpointed := false
	m := New(Options{Config: cfg, ConfigPath: configPath, Database: st.DB(), Version: "fixture", FlushLearning: func(context.Context) error { checkpointed = true; return nil }})
	t.Cleanup(func() {
		if !checkpointed && t.Name() == "TestBackupRestorePreservesRecoveryStateAndRevokesSessions" {
			t.Error("learning checkpoint was not called")
		}
	})
	return m, st, provider.ID, credential
}

func TestBackupRestorePreservesRecoveryStateAndRevokesSessions(t *testing.T) {
	m, st, id, credential := recoveryFixture(t)
	ctx := context.Background()
	var ciphertext bytes.Buffer
	manifest, err := m.Create(ctx, testPassphrase, &ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range manifest.Files {
		if strings.Contains(f.Name, "initial-password") || strings.Contains(f.Name, "session.key") {
			t.Errorf("included obsolete secret %s", f.Name)
		}
	}
	if bytes.Contains(ciphertext.Bytes(), []byte(credential)) || bytes.Contains(ciphertext.Bytes(), []byte("old-bootstrap-password")) {
		t.Fatal("backup exposes secret")
	}
	target := filepath.Join(t.TempDir(), "restored")
	result, err := Restore(ctx, bytes.NewReader(ciphertext.Bytes()), testPassphrase, target)
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionsRevoked != 1 {
		t.Fatalf("sessions revoked %d", result.SessionsRevoked)
	}
	dataDir := filepath.Join(target, "data")
	recovered, err := store.OpenReadOnly(filepath.Join(dataDir, "dnsdaddy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	var liveSessions int
	if err := st.DB().QueryRow("SELECT COUNT(*) FROM sessions").Scan(&liveSessions); err != nil || liveSessions != 1 {
		t.Fatalf("backup changed live sessions: %d %v", liveSessions, err)
	}
	ring, err := secrets.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := recovered.ProviderSecretCiphertext(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := ring.Open(sealed, id)
	if err != nil || string(opened) != credential {
		t.Fatalf("restored provider credential: %v", err)
	}
	hash, err := recovered.GetSetting(ctx, "admin_password_hash")
	if err != nil || hash != "current-dashboard-password-hash" {
		t.Fatal("current admin password was not preserved")
	}
	var feedURL string
	if err := recovered.DB().QueryRow("SELECT url FROM feeds WHERE id='local-test'").Scan(&feedURL); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(feedURL, filepath.Join(target, "refs", "local-feeds", "local.txt")) {
		t.Fatalf("local feed was not relocated: %s", feedURL)
	}
	loaded, err := config.Load(result.ConfigPath)
	if err != nil {
		t.Fatalf("restored YAML cannot load: %v", err)
	}
	if loaded.DataDir != dataDir || loaded.HTTP.AdminPassword != "" {
		t.Fatalf("restored runtime paths/password wrong: %s", loaded.DataDir)
	}
	if loaded.DNS.Timeout != m.opts.Config.DNS.Timeout || loaded.Feeds.RefreshInterval != m.opts.Config.Feeds.RefreshInterval {
		t.Fatal("duration serialization changed configuration")
	}
	for _, name := range []string{"daddybound-learning.json", "daddybound-anchors.json", "feeds/feed_fixture.list"} {
		original, err := os.ReadFile(filepath.Join(m.opts.Config.DataDir, name))
		if err != nil {
			t.Fatal(err)
		}
		actual, err := os.ReadFile(filepath.Join(dataDir, name))
		if err != nil || !bytes.Equal(original, actual) {
			t.Fatalf("state differs %s: %v", name, err)
		}
	}
	if err := filepath.WalkDir(target, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		want := os.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}
		if st.Mode().Perm() != want {
			t.Errorf("permissions %s = %o, want %o", p, st.Mode().Perm(), want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlySourceSnapshotIncludesCommittedWAL(t *testing.T) {
	m, st, _, _ := recoveryFixture(t)
	if err := st.SetSetting(context.Background(), "wal-fixture", "a value committed while the source remains open"); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenSource(m.opts.Config.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	m.opts.Database = ro
	var ciphertext bytes.Buffer
	if _, err := m.Create(context.Background(), testPassphrase, &ciphertext); err != nil {
		t.Fatalf("read-only VACUUM INTO: %v", err)
	}
	target := filepath.Join(t.TempDir(), "from-wal")
	if _, err := Restore(context.Background(), bytes.NewReader(ciphertext.Bytes()), testPassphrase, target); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenReadOnly(filepath.Join(target, "data", "dnsdaddy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if value, err := db.GetSetting(context.Background(), "wal-fixture"); err != nil || value != "a value committed while the source remains open" {
		t.Fatalf("WAL row lost: %v", err)
	}
}

func TestBackupRefusesMissingOrWrongCredentialKey(t *testing.T) {
	m, _, _, _ := recoveryFixture(t)
	path := filepath.Join(m.opts.Config.DataDir, "secrets.key")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(context.Background(), testPassphrase, io.Discard); err == nil {
		t.Fatal("backed up unrecoverable credentials")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(context.Background(), testPassphrase, io.Discard); err == nil {
		t.Fatal("accepted wrong encryption key")
	}
}

func TestRestoreRefusesExistingDestinationAndCleansFailure(t *testing.T) {
	existing := t.TempDir()
	sentinel := filepath.Join(existing, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), bytes.NewReader(nil), testPassphrase, existing); err == nil {
		t.Fatal("accepted existing destination")
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "preserve" {
		t.Fatal("existing data changed")
	}
	target := filepath.Join(t.TempDir(), "failed")
	if _, err := Restore(context.Background(), bytes.NewReader([]byte("invalid")), testPassphrase, target); err == nil {
		t.Fatal("accepted invalid package")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed restore left plaintext directory")
	}
}

func TestRestoreRejectsUnsafeManifestAndArchiveEntries(t *testing.T) {
	for _, test := range []struct {
		name string
		file string
		kind byte
	}{
		{"traversal", "../escape", tar.TypeReg}, {"absolute", "/tmp/escape", tar.TypeReg},
		{"backslash", "refs\\escape", tar.TypeReg}, {"symlink", "config.yaml", tar.TypeSymlink},
		{"hardlink", "config.yaml", tar.TypeLink}, {"device", "config.yaml", tar.TypeChar},
	} {
		t.Run(test.name, func(t *testing.T) {
			var encrypted bytes.Buffer
			w, err := newSealWriter(&encrypted, testPassphrase)
			if err != nil {
				t.Fatal(err)
			}
			tw := tar.NewWriter(w)
			hash := sha256.Sum256(nil)
			manifest := Manifest{FormatVersion: 1, Files: []File{{Name: test.file, Size: 0, SHA256: hex.EncodeToString(hash[:])}, {Name: "data/dnsdaddy.db", Size: 0, SHA256: hex.EncodeToString(hash[:])}}, Paths: map[string]string{}}
			encoded, _ := json.Marshal(manifest)
			if err := writeTarBytes(tw, "manifest.json", encoded, time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := tw.WriteHeader(&tar.Header{Name: test.file, Typeflag: test.kind, Mode: 0o600}); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "target")
			if _, err := Restore(context.Background(), bytes.NewReader(encrypted.Bytes()), testPassphrase, target); err == nil {
				t.Fatal("accepted unsafe archive")
			}
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed restore retained unsafe tree")
			}
		})
	}
}

func TestBackupRejectsSymlinkSourcesAndLimits(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openRegular(link, 100); err == nil {
		t.Fatal("followed source symlink")
	}
	if _, err := openRegular(outside, 2); !errors.Is(err, ErrLimit) {
		t.Fatalf("ignored source size limit: %v", err)
	}
	for _, p := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte("x"), 1025), {0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe}} {
		if !errors.Is(ValidatePassphrase(p), ErrPassphrase) {
			t.Fatal("accepted invalid passphrase")
		}
	}
}

func TestBackupRecoversWebhookOnlyCredentialAndRefusesMissingKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.InitWebhooks(ctx); err != nil {
		t.Fatal(err)
	}
	ring, err := secrets.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("webhook-signing-secret-that-belongs-to-the-operator")
	sealed, err := ring.Seal(secret, webhook.SecretIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec("UPDATE webhook_config SET ciphertext=?,key_id=? WHERE id=1", sealed, ring.KeyID()); err != nil {
		t.Fatal(err)
	}
	m := New(Options{Config: cfg, Database: st.DB(), Version: "webhook-fixture"})
	var encrypted bytes.Buffer
	if _, err := m.Create(ctx, testPassphrase, &encrypted); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(ctx, bytes.NewReader(encrypted.Bytes()), testPassphrase, target); err != nil {
		t.Fatal(err)
	}
	r, err := store.OpenReadOnly(filepath.Join(target, "data", "dnsdaddy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	restoredKey, err := secrets.Open(filepath.Join(target, "data"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := r.WebhookSecretCiphertext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := restoredKey.Open(ciphertext, webhook.SecretIdentity)
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatalf("webhook secret was lost: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "secrets.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(ctx, testPassphrase, io.Discard); err == nil {
		t.Fatal("backed up unrecoverable webhook-only credential")
	}
}

func TestBackupPreservesUnpinnedModeAndLaterDashboardChoice(t *testing.T) {
	for _, mode := range []string{config.LocalDNSSECOff, config.LocalDNSSECObserve} {
		t.Run(mode, func(t *testing.T) {
			m, st, _, _ := recoveryFixture(t)
			ctx := context.Background()
			// The runtime may originally have resolved its implicit installation
			// default to Live. The backup receives the unpinned configuration and
			// must leave the later dashboard choice in the DB authoritative.
			m.opts.Config.DNS.LocalDNSSECValidation = config.LocalDNSSECUnset
			if err := st.SetSetting(ctx, store.SettingLocalDNSSECDefault, config.LocalDNSSECEnforce); err != nil {
				t.Fatal(err)
			}
			if err := st.SetSetting(ctx, "dnssec.mode", mode); err != nil {
				t.Fatal(err)
			}
			var encrypted bytes.Buffer
			if _, err := m.Create(ctx, testPassphrase, &encrypted); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(t.TempDir(), "restored")
			result, err := Restore(ctx, bytes.NewReader(encrypted.Bytes()), testPassphrase, dest)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(result.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.DNS.LocalDNSSECConfigured() {
				t.Fatal("backup converted implicit default into an explicit mode pin")
			}
			db, err := store.OpenReadOnly(cfg.DBPath())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			chosen, err := db.GetSetting(ctx, "dnssec.mode")
			if err != nil {
				t.Fatal(err)
			}
			got, _ := cfg.ResolveLocalDNSSEC(chosen)
			if got != mode {
				t.Fatalf("restored %s instead of saved %s", got, mode)
			}
		})
	}
}
