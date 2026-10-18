package backup

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func TestF03RecoveryPreservesCredentialRevision(t *testing.T) {
	m, st, _, _ := recoveryFixture(t)
	ctx := context.Background()
	before, e := st.ReadAdminCredential(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var archive bytes.Buffer
	if _, e = m.Create(ctx, testPassphrase, &archive); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, e = Restore(ctx, bytes.NewReader(archive.Bytes()), testPassphrase, target); e != nil {
		t.Fatal(e)
	}
	recovered, e := store.Open(filepath.Join(target, "data", "dnsdaddy.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer recovered.Close()
	after, e := recovered.ReadAdminCredential(ctx)
	if e != nil || after != before {
		t.Fatal("recovery changed credential state")
	}
	count, e := recovered.CountSessions(ctx)
	if e != nil || count != 0 {
		t.Fatal("restore retained sessions")
	}
}
func TestF03LegacyRecoveryMigratesWithoutPasswordReset(t *testing.T) {
	m, st, _, _ := recoveryFixture(t)
	ctx := context.Background()
	before, e := st.ReadAdminCredential(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// Synthetic archive with the pre-revision schema, not a historical production backup.
	for _, q := range []string{"DROP TABLE admin_auth_state", "ALTER TABLE sessions DROP COLUMN credential_revision"} {
		if _, e = st.DB().Exec(q); e != nil {
			t.Fatal("legacy fixture failed")
		}
	}
	var archive bytes.Buffer
	if _, e = m.Create(ctx, testPassphrase, &archive); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, e = Restore(ctx, bytes.NewReader(archive.Bytes()), testPassphrase, target); e != nil {
		t.Fatal(e)
	}
	recovered, e := store.Open(filepath.Join(target, "data", "dnsdaddy.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer recovered.Close()
	after, e := recovered.ReadAdminCredential(ctx)
	if e != nil || after.Hash != before.Hash || after.State != store.AuthActive || after.Source != "legacy" {
		t.Fatal("legacy recovery did not preserve credential")
	}
	count, e := recovered.CountSessions(ctx)
	if e != nil || count != 0 {
		t.Fatal("legacy recovery restored sessions")
	}
}
