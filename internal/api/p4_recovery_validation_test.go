package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/backup"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Stage 5A regression replacing the retained Phase 4 defect characterization.
func TestStage5APendingBackupsRefused(t *testing.T) {
	for _, delivered := range []bool{false, true} {
		t.Run(fmt.Sprint(delivered), func(t *testing.T) {
			ctx := context.Background()
			_, st, dir := freshF03(t)
			hash, _ := bcrypt.GenerateFromPassword([]byte("synthetic-pending-proof-password"), bcrypt.MinCost)
			if _, e := st.InitializeAdminCredential(ctx, string(hash), true); e != nil {
				t.Fatal(e)
			}
			if delivered {
				if e := writeInitialPassword(dir, "synthetic-pending-proof-password"); e != nil {
					t.Fatal(e)
				}
			}
			before, _ := st.ReadAdminCredential(ctx)
			cfg := config.Default()
			cfg.DataDir = dir
			var out bytes.Buffer
			_, e := backup.New(backup.Options{Config: cfg, Database: st.DB()}).Create(ctx, []byte("synthetic-backup-passphrase"), &out)
			after, _ := st.ReadAdminCredential(ctx)
			if !errors.Is(e, backup.ErrAdminNotReady) || out.Len() != 0 || before != after {
				t.Fatal("pending backup not rejected safely")
			}
		})
	}
}

func TestStage5AProofRecovery(t *testing.T) {
	ctx := context.Background()
	a, st, dir := freshF03(t)
	const password = "synthetic-pending-proof-password"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if _, e := st.InitializeAdminCredential(ctx, string(hash), true); e != nil {
		t.Fatal(e)
	}
	before, _ := st.ReadAdminCredential(ctx)
	if token, e := a.Login(ctx, password, "synthetic"); e == nil || token != "" {
		t.Fatal("pending credential issued a session")
	}
	if got, e := a.EnsureAdminPassword(ctx, password, dir); e == nil || got != "" {
		t.Fatal("bootstrap configuration bypassed missing activation proof")
	}
	for _, proof := range []string{"", "wrong-password"} {
		if e := a.RecoverPendingAdmin(ctx, []byte(proof)); !errors.Is(e, ErrPasswordIncorrect) {
			t.Fatal("invalid proof accepted")
		}
		after, _ := st.ReadAdminCredential(ctx)
		if after != before {
			t.Fatal("invalid proof changed authority")
		}
	}
	if e := a.RecoverPendingAdmin(ctx, []byte(password)); e != nil {
		t.Fatal(e)
	}
	after, _ := st.ReadAdminCredential(ctx)
	if after.Hash != before.Hash || after.State != store.AuthActive || after.Revision != 1 {
		t.Fatal("activation replaced authority")
	}
	if e := a.RecoverPendingAdmin(ctx, []byte(password)); !errors.Is(e, ErrRecoveryAlreadyActive) {
		t.Fatal("repeat not idempotent")
	}
	if _, e := a.EnsureAdminPassword(ctx, "stale-bootstrap-password", dir); e != nil {
		t.Fatal(e)
	}
	if !a.CheckPassword(ctx, password) {
		t.Fatal("existing credential unusable")
	}
	if e := a.SetPassword(ctx, password, "synthetic-rotated-new-password"); e != nil {
		t.Fatal(e)
	}
	rotated, _ := st.ReadAdminCredential(ctx)
	if e := a.RecoverPendingAdmin(ctx, []byte(password)); !errors.Is(e, ErrPasswordIncorrect) {
		t.Fatal("old proof accepted after rotation")
	}
	final, _ := st.ReadAdminCredential(ctx)
	if rotated != final {
		t.Fatal("recovery reset rotated account")
	}
}

func TestP4ActiveRotatedRestorePreservesAuthority(t *testing.T) {
	ctx := context.Background()
	a, st, dir := freshF03(t)
	const initial = "synthetic-initial-password"
	const rotated = "synthetic-rotated-password"
	if _, e := a.EnsureAdminPassword(ctx, initial, dir); e != nil {
		t.Fatal("fixture initialization")
	}
	if e := a.SetPassword(ctx, initial, rotated); e != nil {
		t.Fatal("fixture rotation")
	}
	token, e := a.Login(ctx, rotated, "synthetic")
	if e != nil {
		t.Fatal("fixture login")
	}
	before, e := st.ReadAdminCredential(ctx)
	if e != nil || before.Revision <= 1 {
		t.Fatal("fixture revision")
	}
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.HTTP.AdminPassword = initial
	m := backup.New(backup.Options{Config: cfg, Database: st.DB(), Version: "p4-synthetic"})
	var archive bytes.Buffer
	if _, e = m.Create(ctx, []byte("synthetic-encrypted-backup-passphrase"), &archive); e != nil {
		t.Fatal("active backup", e)
	}
	destination := filepath.Join(t.TempDir(), "restored")
	if _, e = backup.Restore(ctx, bytes.NewReader(archive.Bytes()), []byte("synthetic-encrypted-backup-passphrase"), destination); e != nil {
		t.Fatal("active restore", e)
	}
	restoredDir := filepath.Join(destination, "data")
	path := filepath.Join(restoredDir, "dnsdaddy.db")
	restored, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	auth, e := NewAuth(restored, restoredDir, AuthOptions{})
	if e != nil {
		restored.Close()
		t.Fatal(e)
	}
	for _, bootstrap := range []string{initial, "", "synthetic-invalid-bootstrap"} {
		if got, err := auth.EnsureAdminPassword(ctx, bootstrap, restoredDir); err != nil || got != "" {
			restored.Close()
			t.Fatal("restored active authority overridden")
		}
	}
	after, e := restored.ReadAdminCredential(ctx)
	if e != nil || after != before {
		restored.Close()
		t.Fatal("restored rotated hash/revision changed")
	}
	if auth.CheckPassword(ctx, initial) || !auth.CheckPassword(ctx, rotated) {
		restored.Close()
		t.Fatal("restored password validity changed")
	}
	if valid, e := restored.LookupSession(ctx, token); e != nil || valid {
		restored.Close()
		t.Fatal("restored old session accepted")
	}
	if count, e := restored.CountSessions(ctx); e != nil || count != 0 {
		restored.Close()
		t.Fatal("restore did not revoke sessions")
	}
	if e = restored.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	final, e := reopened.ReadAdminCredential(ctx)
	if e != nil || final != before {
		t.Fatal("reopen reset restored credential")
	}
	corrupted := append([]byte(nil), archive.Bytes()...)
	corrupted[len(corrupted)-1] ^= 1
	badDestination := filepath.Join(t.TempDir(), "rejected")
	if _, e = backup.Restore(ctx, bytes.NewReader(corrupted), []byte("synthetic-encrypted-backup-passphrase"), badDestination); e == nil {
		t.Fatal("tampered archive accepted")
	}
	if _, e = os.Stat(badDestination); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("failed restore left target")
	}
	original, e := st.ReadAdminCredential(ctx)
	if e != nil || original != before {
		t.Fatal("restore altered original authority")
	}
	t.Log("VALIDATED: active revision>1 archive/reopen preserves exact credential authority; stale bootstrap rejected; sessions revoked; tampered restore rejected and cleaned without source mutation")
}
