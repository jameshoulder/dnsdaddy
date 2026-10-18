package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test-only producer recreates the pre-remediation archive format.
func TestStage5ALegacyPendingRestore(t *testing.T) {
	for _, hasHash := range []bool{true, false} {
		t.Run(map[bool]string{true: "proof-available", false: "no-proof"}[hasHash], func(t *testing.T) {
			ctx := context.Background()
			m, st, _, _ := recoveryFixture(t)
			source := []byte("# old-bootstrap-password\nhttp:\n  admin_password: old-bootstrap-password\n")
			if e := os.WriteFile(m.opts.ConfigPath, source, 0600); e != nil {
				t.Fatal(e)
			}
			var active bytes.Buffer
			if _, e := m.Create(ctx, testPassphrase, &active); e != nil {
				t.Fatal(e)
			}
			unchanged, e := os.ReadFile(m.opts.ConfigPath)
			if e != nil || !bytes.Equal(source, unchanged) {
				t.Fatal("original configuration modified")
			}
			rd, e := newOpenReader(bytes.NewReader(active.Bytes()), testPassphrase)
			if e != nil {
				t.Fatal(e)
			}
			tr := tar.NewReader(rd)
			files := map[string][]byte{}
			var manifest Manifest
			for {
				h, e := tr.Next()
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
				b, e := io.ReadAll(tr)
				if e != nil {
					t.Fatal(e)
				}
				if h.Name == "manifest.json" {
					if e = json.Unmarshal(b, &manifest); e != nil {
						t.Fatal(e)
					}
				} else {
					files[h.Name] = b
				}
			}
			if _, e = io.Copy(io.Discard, rd); e != nil {
				t.Fatal(e)
			}
			for _, name := range []string{"config.yaml", "source-config.yaml"} {
				if len(files[name]) == 0 || bytes.Contains(files[name], []byte("old-bootstrap-password")) {
					t.Fatal("bootstrap plaintext in archive")
				}
			}
			dbpath := filepath.Join(t.TempDir(), "legacy.db")
			if e = os.WriteFile(dbpath, files["data/dnsdaddy.db"], 0600); e != nil {
				t.Fatal(e)
			}
			s, e := store.Open(dbpath)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.DB().Exec("UPDATE admin_auth_state SET state='bootstrap_pending',source='generated',revision=0"); e != nil {
				t.Fatal(e)
			}
			if !hasHash {
				if _, e = s.DB().Exec("DELETE FROM settings WHERE key=?", store.AdminPasswordHashKey); e != nil {
					t.Fatal(e)
				}
				if _, e = s.DB().Exec("UPDATE admin_auth_state SET source=''"); e != nil {
					t.Fatal(e)
				}
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			files["data/dnsdaddy.db"], e = os.ReadFile(dbpath)
			if e != nil {
				t.Fatal(e)
			}
			for i := range manifest.Files {
				f := &manifest.Files[i]
				b := files[f.Name]
				sum := sha256.Sum256(b)
				f.Size = int64(len(b))
				f.SHA256 = hex.EncodeToString(sum[:])
			}
			var legacy bytes.Buffer
			w, e := newSealWriter(&legacy, testPassphrase)
			if e != nil {
				t.Fatal(e)
			}
			tw := tar.NewWriter(w)
			b, _ := json.Marshal(manifest)
			if e = writeTarBytes(tw, "manifest.json", b, time.Now()); e != nil {
				t.Fatal(e)
			}
			for _, f := range manifest.Files {
				if e = writeTarBytes(tw, f.Name, files[f.Name], time.Now()); e != nil {
					t.Fatal(e)
				}
			}
			if e = tw.Close(); e != nil {
				t.Fatal(e)
			}
			if e = w.Close(); e != nil {
				t.Fatal(e)
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			interrupted := filepath.Join(t.TempDir(), "interrupted")
			if _, e = Restore(canceled, bytes.NewReader(legacy.Bytes()), testPassphrase, interrupted); e == nil {
				t.Fatal("canceled restoration succeeded")
			}
			if _, e = os.Stat(interrupted); !os.IsNotExist(e) {
				t.Fatal("interrupted restore left target")
			}
			for n := 0; n < 2; n++ {
				dest := filepath.Join(t.TempDir(), "restored")
				result, e := Restore(ctx, bytes.NewReader(legacy.Bytes()), testPassphrase, dest)
				if e != nil {
					t.Fatal(e)
				}
				want := store.AuthRecoveryRequired
				if hasHash {
					want = AdminPendingProof
				}
				if result.AdminStatus != want {
					t.Fatal("missing explicit recovery status")
				}
				recovered, e := store.Open(filepath.Join(dest, "data", "dnsdaddy.db"))
				if e != nil {
					t.Fatal(e)
				}
				c, e := recovered.ReadAdminCredential(ctx)
				if hasHash {
					original, _ := st.ReadAdminCredential(ctx)
					if e != nil || c.Hash != original.Hash || c.State != store.AuthBootstrapPending {
						t.Fatal("legacy hash changed")
					}
				} else if e == nil {
					t.Fatal("missing proof allowed initialization")
				}
				recovered.Close()
				if _, e = os.Stat(filepath.Join(dest, "data", "initial-password.txt")); !os.IsNotExist(e) {
					t.Fatal("plaintext proof restored")
				}
				if _, e = os.Stat(filepath.Join(dest, "data", AdminRecoveryNoticeName)); e != nil {
					t.Fatal("missing recovery notice")
				}
			}
		})
	}
}
func TestStage5AConfigCredentialExclusion(t *testing.T) {
	const secret = "synthetic-config-password-never-export"
	for _, input := range []string{"http:\n  admin_password: " + secret + "\n", "# " + secret + "\nhttp:\n  admin_password: " + secret + "\n"} {
		b, e := sanitizedConfig([]byte(input))
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("credential exported")
		}
	}
	for _, input := range []string{"http: &x\n  admin_password: " + secret + "\n", "unknown: " + secret, "http: [", "{}\n---\nhttp: {}"} {
		if _, e := sanitizedConfig([]byte(input)); e == nil || strings.Contains(e.Error(), secret) {
			t.Fatal("ambiguous configuration accepted or echoed")
		}
	}
}
