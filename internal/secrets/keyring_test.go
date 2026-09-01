package secrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSealAndOpenRoundTrip(t *testing.T) {
	k, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}

	const (
		owner  = "apr_0123456789ab"
		secret = "vt-api-key-9f8e7d6c5b4a"
	)

	sealed, err := k.Seal([]byte(secret), owner)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// The plaintext must not survive anywhere in the ciphertext. Obvious, and
	// exactly the thing a misconfigured cipher mode gets wrong.
	if bytes.Contains(sealed, []byte(secret)) {
		t.Fatal("the sealed value contains the plaintext")
	}

	got, err := k.Open(sealed, owner)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != secret {
		t.Errorf("round trip returned %q, want %q", got, secret)
	}
}

// Two seals of the same plaintext must differ, or the ciphertext leaks the
// fact that two providers share a credential.
func TestSealIsNotDeterministic(t *testing.T) {
	k, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := k.Seal([]byte("same"), "apr_1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.Seal([]byte("same"), "apr_1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("sealing the same plaintext twice produced identical ciphertext")
	}
}

// The owner is authenticated data, so a ciphertext lifted from one provider's
// row into another's must fail rather than open. Direct database edits and
// UPDATE bugs both produce exactly this, and both should be loud.
func TestCiphertextIsBoundToItsOwner(t *testing.T) {
	k, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k.Seal([]byte("virustotal-key"), "apr_aaa")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := k.Open(sealed, "apr_bbb"); !errors.Is(err, ErrOpenFailed) {
		t.Errorf("opening under a different owner returned %v, want ErrOpenFailed", err)
	}
	// And still opens under the right one, so the test above is about the
	// owner rather than about the ciphertext being broken.
	if _, err := k.Open(sealed, "apr_aaa"); err != nil {
		t.Errorf("opening under the correct owner failed: %v", err)
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	k, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k.Seal([]byte("a-real-credential"), "apr_x")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"flipped byte in the body", func(b []byte) []byte {
			c := append([]byte(nil), b...)
			c[len(c)-1] ^= 0x01
			return c
		}},
		{"flipped byte in the nonce", func(b []byte) []byte {
			c := append([]byte(nil), b...)
			c[0] ^= 0x01
			return c
		}},
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }},
		{"empty", func([]byte) []byte { return nil }},
		{"shorter than a nonce", func(b []byte) []byte { return b[:4] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := k.Open(tc.mutate(sealed), "apr_x"); !errors.Is(err, ErrOpenFailed) {
				t.Errorf("opening a %s value returned %v, want ErrOpenFailed", tc.name, err)
			}
		})
	}
}

// A different key must not open another key's ciphertext. This is what makes
// "back up the database without the key file and the credentials are useless"
// a property rather than a hope.
func TestAnotherKeyCannotOpen(t *testing.T) {
	a, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a.KeyID() == b.KeyID() {
		t.Fatal("two independently generated keys have the same id")
	}

	sealed, err := a.Seal([]byte("secret"), "apr_1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(sealed, "apr_1"); !errors.Is(err, ErrOpenFailed) {
		t.Errorf("a foreign key opened the ciphertext: %v", err)
	}
}

func TestKeyFileIsCreatedOwnerReadableOnly(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, KeyFileName))
	if err != nil {
		t.Fatalf("key file was not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode is %04o, want 0600 — it is the whole secret", perm)
	}
	if info.Size() != keyLen {
		t.Errorf("key file is %d bytes, want %d", info.Size(), keyLen)
	}

	// No temporary file left behind: a .secrets.key-* with the real key in it
	// would defeat the mode above.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".secrets.key-") {
			t.Errorf("a temporary key file was left behind: %s", e.Name())
		}
	}
}

// Reopening must adopt the existing key rather than generating a new one —
// otherwise every restart would orphan every stored credential.
func TestReopenKeepsTheSameKey(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := first.Seal([]byte("persisted"), "apr_1")
	if err != nil {
		t.Fatal(err)
	}

	second, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second.KeyID() != first.KeyID() {
		t.Errorf("reopening produced key %q, want %q", second.KeyID(), first.KeyID())
	}
	got, err := second.Open(sealed, "apr_1")
	if err != nil {
		t.Fatalf("a restart could not open what it had sealed: %v", err)
	}
	if string(got) != "persisted" {
		t.Errorf("got %q after reopen", got)
	}
}

// A key file of the wrong length is a corrupt key, not a key to be used. It
// must be reported rather than silently replaced: overwriting it would destroy
// the only thing that could open the stored ciphertexts.
func TestAShortKeyFileIsRefusedNotReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, KeyFileName)
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}

	k, err := Open(dir)
	if err == nil {
		t.Fatal("a truncated key file was accepted")
	}
	if !errors.Is(err, ErrNoKey) {
		t.Errorf("error is %v, want it to wrap ErrNoKey", err)
	}
	if k.Available() {
		t.Error("keyring reports itself available with no usable key")
	}

	// The file is untouched. Replacing it would be the single most destructive
	// thing this package could do.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "too short" {
		t.Errorf("the existing key file was overwritten (now %q)", raw)
	}
}

// Sealing and opening with no key must fail loudly. The failure mode being
// guarded against is a keyring that silently stores plaintext when it cannot
// encrypt.
func TestNoKeyMeansNoSealing(t *testing.T) {
	k := &Keyring{} // no key adopted

	sealed, err := k.Seal([]byte("credential"), "apr_1")
	if !errors.Is(err, ErrNoKey) {
		t.Errorf("Seal without a key returned %v, want ErrNoKey", err)
	}
	if sealed != nil {
		t.Error("Seal returned bytes despite failing — plaintext could reach the database")
	}
	if _, err := k.Open([]byte("anything"), "apr_1"); !errors.Is(err, ErrNoKey) {
		t.Errorf("Open without a key returned %v, want ErrNoKey", err)
	}
}

func TestKeyIDIsNotTheKey(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, keyLen)
	k, err := OpenWithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	id := k.KeyID()
	if id == "" {
		t.Fatal("no key id")
	}
	// It goes in a database column, so it must not contain the key in any
	// encoding a reader could reverse.
	if strings.Contains(id, "ab") && len(id) > 40 {
		t.Errorf("key id %q looks like it encodes the key", id)
	}
	if len(id) != 17 { // "k" + 16 hex characters
		t.Errorf("key id %q is %d characters, want 17", id, len(id))
	}
}

func TestHintShowsTooLittleToBeUseful(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"short", ""},
		{"12345678", ""},      // eight characters: still too short to hint
		{"123456789", "6789"}, // nine: the first length that gets one
		{"vt-api-key-abcd", "abcd"},
	} {
		if got := Hint(tc.in); got != tc.want {
			t.Errorf("Hint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The keyring is read by every worker goroutine at once.
func TestConcurrentSealAndOpen(t *testing.T) {
	k, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				sealed, err := k.Seal([]byte("credential"), "apr_1")
				if err != nil {
					t.Errorf("seal: %v", err)
					return
				}
				got, err := k.Open(sealed, "apr_1")
				if err != nil {
					t.Errorf("open: %v", err)
					return
				}
				if string(got) != "credential" {
					t.Errorf("round trip returned %q", got)
					return
				}
			}
		}()
	}
	wg.Wait()
}
