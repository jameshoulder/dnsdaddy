//go:build unix

package main

import (
	"bytes"
	"context"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"golang.org/x/crypto/bcrypt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStage5AOfflineRecoveryCommand(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "dnsdaddy.db")
	ctx := context.Background()
	s, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	const password = "synthetic-offline-existing-password"
	h, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.InitializeAdminCredential(ctx, string(h), true); e != nil {
		t.Fatal(e)
	}
	before, e := s.ReadAdminCredential(ctx)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if e = os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	note := filepath.Join(dir, "ADMIN_RECOVERY_REQUIRED.json")
	if e = os.WriteFile(note, []byte(`{"adminStatus":"pending_password_proof"}`), 0600); e != nil {
		t.Fatal(e)
	}
	args := []string{"-data-dir", dir, "-password-stdin", "-service-stopped"}
	var out bytes.Buffer
	for _, input := range []string{"", "wrong-password", strings.Repeat("x", 75)} {
		e = runRecoverAdmin(args, strings.NewReader(input), &out)
		if e == nil || strings.Contains(e.Error(), password) || out.Len() != 0 {
			t.Fatal("invalid proof accepted or exposed")
		}
	}
	if e = runRecoverAdmin(args[:2], strings.NewReader(password), &out); e == nil {
		t.Fatal("missing explicit proof/stopped assertion accepted")
	}
	s, e = store.OpenAdminRecovery(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	after, e := s.ReadAdminCredential(ctx)
	s.Close()
	if e != nil || before != after {
		t.Fatal("failed proof changed credential")
	}
	if e = runRecoverAdmin(args, strings.NewReader(password+"\n"), &out); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), password) || strings.Contains(out.String(), string(h)) {
		t.Fatal("secret in output")
	}
	if _, e = os.Stat(note); !os.IsNotExist(e) {
		t.Fatal("recovery notice not removed")
	}
	s, e = store.OpenAdminRecovery(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	after, e = s.ReadAdminCredential(ctx)
	s.Close()
	if e != nil || after.Hash != before.Hash || after.State != store.AuthActive {
		t.Fatal("activation reset password")
	}
	if e = runRecoverAdmin(args, strings.NewReader(password), &out); e != nil {
		t.Fatal("repeat recovery", e)
	}
	if e = runRecoverAdmin(args, strings.NewReader("wrong-password"), &out); e == nil {
		t.Fatal("active incorrect proof accepted")
	}
}
func TestStage5ARecoveryRefusesUnsafeDatabase(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "hardlink", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			os.Chmod(dir, 0700)
			path := filepath.Join(dir, "dnsdaddy.db")
			if kind != "missing" {
				target := filepath.Join(dir, "target")
				if e := os.WriteFile(target, []byte("synthetic"), 0600); e != nil {
					t.Fatal(e)
				}
				var e error
				switch kind {
				case "symlink":
					e = os.Symlink(target, path)
				case "hardlink":
					e = os.Link(target, path)
				case "permissions":
					e = os.Rename(target, path)
					if e == nil {
						e = os.Chmod(path, 0644)
					}
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			var out bytes.Buffer
			if e := runRecoverAdmin([]string{"-data-dir", dir, "-password-stdin", "-service-stopped"}, strings.NewReader("synthetic-proof"), &out); e == nil {
				t.Fatal("unsafe database accepted")
			}
			if kind == "missing" {
				if _, e := os.Stat(path); !os.IsNotExist(e) {
					t.Fatal("missing DB created")
				}
			}
		})
	}
}
