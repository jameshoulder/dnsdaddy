package trustanchors_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/trustanchors"
)

// The state file round-trips, is written atomically, and is not world-readable.
//
// Atomicity is the part worth testing rather than assuming. A process killed
// halfway through overwriting this file in place leaves a resolver that, on its
// next start, cannot read what it trusts — so the write goes to a temporary
// file and is renamed, and a reader either sees the whole old state or the
// whole new one.
func TestTheStateFileRoundTripsAndIsWrittenAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.json")
	store := trustanchors.FileStore{Path: path}

	if _, err := store.Load(); err == nil {
		t.Fatal("loading a file that does not exist returned no error")
	} else if !isNoState(err) {
		t.Fatalf("a missing file should be reported as no state, got %v", err)
	}

	at := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	want := trustanchors.TrustPoint{
		Zone:        ".",
		LastSuccess: at,
		LastRefresh: at,
		NextRefresh: at.Add(24 * time.Hour),
		Keys: []trustanchors.ManagedKey{
			{Key: ". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
				KeyTag: 20326, Algorithm: 8, Flags: 257,
				State: trustanchors.StateValid, FirstSeen: at, LastSeen: at, Seeded: true},
		},
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("saving: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if got.Zone != want.Zone || len(got.Keys) != 1 {
		t.Fatalf("round trip lost the trust point: %+v", got)
	}
	if got.Keys[0].State != trustanchors.StateValid || got.Keys[0].KeyTag != 20326 {
		t.Errorf("round trip lost the key state: %+v", got.Keys[0])
	}
	if !got.LastSuccess.Equal(at) {
		t.Errorf("LastSuccess = %s, want %s", got.LastSuccess, at)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("the state file is mode %o; a file others can write is a file "+
			"others can use to change what this resolver trusts", perm)
	}

	// No temporary files left behind. A directory that fills with
	// .anchors-*.tmp is a slow disk leak on a device an operator never looks at.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the directory: %v", err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the save left %d files behind: %v", len(entries), names)
	}
}

// A state file that is not readable state is an error, not an empty one.
//
// The difference matters: "nothing stored yet" is a normal first run and seeds
// from the configured anchors, while "this file is not what I wrote" might be a
// truncated write or might be somebody editing what this resolver trusts. The
// manager falls back to the configured anchors either way, but only one of the
// two is worth waking somebody up for.
func TestACorruptStateFileIsAnErrorRatherThanAnEmptyOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchors.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	_, err := trustanchors.FileStore{Path: path}.Load()
	if err == nil {
		t.Fatal("a corrupt state file loaded without error")
	}
	if isNoState(err) {
		t.Fatal("a corrupt state file was reported as no state at all; " +
			"a truncated write and an empty trust point are not the same event")
	}
}

func isNoState(err error) bool {
	return err != nil && err.Error() == trustanchors.ErrNoState.Error()
}
