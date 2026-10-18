//go:build unix

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/jameshoulder/dnsdaddy/internal/backup"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test-only format-1 legacy producer: current Create correctly refuses pending
// credentials. No production eligibility bypass or committed fixture DB is added.
func rev02PendingArchive(t *testing.T) ([]byte, []byte, string) {
	t.Helper()
	ctx := context.Background()
	dbpath := filepath.Join(t.TempDir(), "dnsdaddy.db")
	st, e := store.Open(dbpath)
	if e != nil {
		t.Fatal(e)
	}
	const password = "synthetic-rev02-existing-password"
	hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = st.InitializeAdminCredential(ctx, string(hash), true); e != nil {
		t.Fatal(e)
	}
	if e = st.Close(); e != nil {
		t.Fatal(e)
	}
	db, e := os.ReadFile(dbpath)
	if e != nil {
		t.Fatal(e)
	}
	files := map[string][]byte{"config.yaml": []byte("data_dir: /synthetic\n"), "data/dnsdaddy.db": db}
	manifest := backup.Manifest{FormatVersion: 1, ApplicationVersion: "synthetic-rev02", CreatedAt: time.Now().UTC()}
	names := []string{"config.yaml", "data/dnsdaddy.db"}
	for _, name := range names {
		b := files[name]
		sum := sha256.Sum256(b)
		manifest.Files = append(manifest.Files, backup.File{Name: name, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])})
	}
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	add := func(name string, b []byte) {
		if e := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(b)), Typeflag: tar.TypeReg}); e != nil {
			t.Fatal(e)
		}
		if _, e := tw.Write(b); e != nil {
			t.Fatal(e)
		}
	}
	encoded, e := json.Marshal(manifest)
	if e != nil {
		t.Fatal(e)
	}
	add("manifest.json", encoded)
	for _, name := range names {
		add(name, files[name])
	}
	if e = tw.Close(); e != nil {
		t.Fatal(e)
	}
	passphrase := []byte("synthetic-rev02-archive-passphrase")
	header := make([]byte, 52)
	copy(header, []byte("DNSDADDYBACKUP\x00\x01"))
	if _, e = rand.Read(header[16:]); e != nil {
		t.Fatal(e)
	}
	key, e := scrypt.Key(passphrase, header[16:48], 1<<17, 8, 1, 32)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	block, e := aes.NewCipher(key)
	if e != nil {
		t.Fatal(e)
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	var sealed bytes.Buffer
	sealed.Write(header)
	var index uint64
	record := func(b []byte) {
		nonce := make([]byte, 12)
		copy(nonce, header[48:])
		binary.BigEndian.PutUint64(nonce[4:], index)
		size := uint32(len(b) + aead.Overhead())
		aad := make([]byte, 64)
		copy(aad, header)
		binary.BigEndian.PutUint64(aad[52:], index)
		binary.BigEndian.PutUint32(aad[60:], size)
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], size)
		sealed.Write(prefix[:])
		sealed.Write(aead.Seal(nil, nonce, b, aad))
		index++
	}
	b := plain.Bytes()
	for len(b) > 0 {
		n := min(len(b), 1<<20)
		record(b[:n])
		b = b[n:]
	}
	record(nil)
	return sealed.Bytes(), passphrase, string(hash)
}
func TestREV02RestoreLayoutProofRecovery(t *testing.T) {
	archive, passphrase, hash := rev02PendingArchive(t)
	destination := filepath.Join(t.TempDir(), "restored")
	ctx := context.Background()
	result, e := backup.Restore(ctx, bytes.NewReader(archive), passphrase, destination)
	if e != nil {
		t.Fatal(e)
	}
	if result.AdminStatus != backup.AdminPendingProof {
		t.Fatal("legacy pending status missing")
	}
	data := filepath.Join(destination, "data")
	notice := filepath.Join(data, "ADMIN_RECOVERY_REQUIRED.json")
	// The real Restore-produced notice must reside inside -data-dir.
	actual := notice
	marker, e := os.ReadFile(actual)
	if e != nil {
		t.Fatal("actual restore notice missing inside data directory")
	}
	parentNotice := filepath.Join(destination, "ADMIN_RECOVERY_REQUIRED.json")
	if _, e = os.Lstat(parentNotice); !os.IsNotExist(e) {
		t.Fatal("Restore wrote a notice outside the recovery data root")
	}
	// A historical parent notice is informational and must never be removed by
	// traversing outside the data root, even after successful proof.
	parentSentinel := []byte("synthetic legacy parent notice")
	if e = os.WriteFile(parentNotice, parentSentinel, 0600); e != nil {
		t.Fatal(e)
	}
	st, e := store.OpenAdminRecovery(ctx, filepath.Join(data, "dnsdaddy.db"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = st.DB().Exec("INSERT INTO sessions(token_hash,created_at,expires_at,last_seen,credential_revision) VALUES('synthetic-rev02',0,9999999999,0,0)"); e != nil {
		t.Fatal(e)
	}
	before, e := st.ReadAdminCredential(ctx)
	if e != nil {
		t.Fatal(e)
	}
	st.Close()
	args := []string{"-data-dir", data, "-password-stdin", "-service-stopped"}
	var out bytes.Buffer
	if e = runRecoverAdmin(args, strings.NewReader("synthetic-wrong-proof"), &out); e == nil || out.Len() != 0 {
		t.Fatal("wrong proof accepted")
	}
	afterMarker, e := os.ReadFile(actual)
	if e != nil || !bytes.Equal(marker, afterMarker) {
		t.Fatal("incorrect proof changed notice")
	}
	st, e = store.OpenAdminRecovery(ctx, filepath.Join(data, "dnsdaddy.db"))
	if e != nil {
		t.Fatal(e)
	}
	after, e := st.ReadAdminCredential(ctx)
	if e != nil || after != before {
		t.Fatal("incorrect proof changed authority")
	}
	n, e := st.CountSessions(ctx)
	st.Close()
	if e != nil || n != 1 {
		t.Fatal("incorrect proof changed sessions")
	}
	if e = runRecoverAdmin(args, strings.NewReader("synthetic-rev02-existing-password"), &out); e != nil {
		t.Fatal(e)
	}
	st, e = store.OpenAdminRecovery(ctx, filepath.Join(data, "dnsdaddy.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	after, e = st.ReadAdminCredential(ctx)
	if e != nil || after.Hash != hash || after.State != store.AuthActive || after.Revision != before.Revision+1 || after.Source != before.Source {
		t.Fatal("recovery changed hash")
	}
	n, e = st.CountSessions(ctx)
	if e != nil || n != 0 {
		t.Fatal("recovery retained sessions")
	}
	if _, e = os.Lstat(actual); !os.IsNotExist(e) {
		t.Fatal("successful recovery left the real restore notice")
	}
	parentAfter, e := os.ReadFile(parentNotice)
	if e != nil || !bytes.Equal(parentAfter, parentSentinel) {
		t.Fatal("recovery escaped its data root")
	}
	if strings.Contains(out.String(), hash) || strings.Contains(out.String(), "synthetic-rev02-existing-password") {
		t.Fatal("secret in output")
	}
}

func TestREV02RecoveryNoticeSymlinkStaysConfined(t *testing.T) {
	archive, passphrase, _ := rev02PendingArchive(t)
	destination := filepath.Join(t.TempDir(), "restored")
	if _, e := backup.Restore(context.Background(), bytes.NewReader(archive), passphrase, destination); e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(destination, "data")
	notice := filepath.Join(data, backup.AdminRecoveryNoticeName)
	target := filepath.Join(destination, "synthetic-outside-data")
	sentinel := []byte("synthetic outside-root target")
	if e := os.WriteFile(target, sentinel, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(notice); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(target, notice); e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e := runRecoverAdmin([]string{"-data-dir", data, "-password-stdin", "-service-stopped"}, strings.NewReader("synthetic-rev02-existing-password"), &out); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(notice); !os.IsNotExist(e) {
		t.Fatal("notice link not removed")
	}
	after, e := os.ReadFile(target)
	if e != nil || !bytes.Equal(after, sentinel) {
		t.Fatal("notice cleanup followed link outside root")
	}
}
