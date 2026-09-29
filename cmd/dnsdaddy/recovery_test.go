package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func TestRecoveryCLIRoundTripAndNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "source-data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(data, "dnsdaddy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetSetting(context.Background(), "recovery-cli-fixture", "present"); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configFile, []byte("data_dir: "+data+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(dir, "passphrase")
	if err := os.WriteFile(passFile, []byte("isolated command line recovery phrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "backup.ddbackup")
	args := []string{"-config", configFile, "-output", output, "-passphrase-file", passFile}
	if err := runBackup(args); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := runBackup(args); err == nil {
		t.Fatal("overwrote existing backup")
	}
	after, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing backup changed")
	}
	restored := filepath.Join(dir, "restored")
	if err := runRestore([]string{"-input", output, "-destination", restored, "-passphrase-file", passFile}); err != nil {
		t.Fatal(err)
	}
	r, err := store.OpenReadOnly(filepath.Join(restored, "data", "dnsdaddy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if v, err := r.GetSetting(context.Background(), "recovery-cli-fixture"); err != nil || v != "present" {
		t.Fatalf("restored data: %s %v", v, err)
	}
	if err := runRestore([]string{"-input", output, "-destination", data, "-passphrase-file", passFile}); err == nil {
		t.Fatal("accepted live source as restore destination")
	}
}

func TestRecoveryPassphraseSourcesAreExplicitAndPrivate(t *testing.T) {
	if _, err := readRecoveryPassphrase("", false, strings.NewReader("long test passphrase")); err == nil {
		t.Fatal("accepted unspecified passphrase source")
	}
	if _, err := readRecoveryPassphrase("file", true, strings.NewReader("long test passphrase")); err == nil {
		t.Fatal("accepted ambiguous passphrase sources")
	}
	p, err := readRecoveryPassphrase("", true, strings.NewReader("  whitespace is deliberate  \r\n"))
	if err != nil || string(p) != "  whitespace is deliberate  " {
		t.Fatalf("changed phrase spaces: %q %v", p, err)
	}
	file := filepath.Join(t.TempDir(), "phrase")
	if err := os.WriteFile(file, []byte("long test passphrase"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryPassphrase(file, false, nil); err == nil {
		t.Fatal("accepted broadly readable passphrase")
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryPassphrase(link, false, nil); err == nil {
		t.Fatal("followed passphrase symlink")
	}
	if _, err := readRecoveryPassphrase(file, false, nil); err != nil {
		t.Fatal(err)
	}
}
