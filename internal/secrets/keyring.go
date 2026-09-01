// Package secrets seals operator-supplied credentials so that a copy of the
// database is not a copy of the credentials.
//
// DNS Daddy stores exactly one class of recoverable secret: the API keys an
// operator gives it for external intelligence providers. Everything else it
// holds is a one-way hash — the admin password is bcrypt, API tokens and
// session cookies are SHA-256 of something the server never needs to read
// back. Those are the right shape because the server only ever has to *check*
// them.
//
// A provider credential is different. It has to be sent to VirusTotal on the
// next lookup, so it must be recoverable, so it must be encrypted rather than
// hashed. That is a genuine change to what a stolen dnsdaddy.db is worth, and
// this package exists to keep the answer "nothing": the key lives in a
// separate file that no backup of the database contains.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

const (
	// KeyFileName is the keyring's file inside the data directory.
	KeyFileName = "secrets.key"

	// keyLen is 32 bytes: AES-256.
	keyLen = 32

	// keyFileMode is owner-read-only. The file is the whole secret.
	keyFileMode fs.FileMode = 0o600
)

// ErrNoKey means the keyring has no usable key, so nothing can be opened.
//
// Distinguished from a decryption failure on purpose. "The key file is gone"
// and "this ciphertext is corrupt" need different things from an operator —
// restore a file versus re-enter one credential — and reporting both as
// "could not decrypt" sends them looking in the wrong place.
var ErrNoKey = errors.New("secrets: no encryption key available")

// ErrOpenFailed means the ciphertext did not authenticate under this key.
//
// Deliberately says nothing about why. GCM cannot tell a wrong key from a
// flipped bit from a ciphertext moved between rows, and inventing a
// distinction the primitive does not provide would be a guess presented as a
// diagnosis.
var ErrOpenFailed = errors.New("secrets: could not open sealed value")

// Keyring seals and opens credentials with AES-256-GCM.
//
// Safe for concurrent use. The cipher.AEAD is immutable once built, so reads
// need no lock; the mutex covers only lazy initialisation.
type Keyring struct {
	path string

	mu    sync.RWMutex
	aead  cipher.AEAD
	keyID string
	err   error // why there is no key, when there is none
}

// Open prepares a keyring backed by dir/secrets.key, creating the key on first
// use.
//
// Creating on first use rather than at install time is deliberate: an operator
// who never adds a provider never has a key file, so there is nothing extra to
// protect, back up, or explain. The file appears the moment it has something
// to protect.
//
// A failure here is returned rather than swallowed, but callers are expected
// to carry on without a keyring: resolution does not depend on credentials,
// and a resolver that refuses to start because it could not create a file for
// a feature nobody is using would be trading a working DNS server for a
// tidier invariant.
func Open(dir string) (*Keyring, error) {
	if dir == "" {
		return nil, fmt.Errorf("secrets: no data directory given")
	}
	k := &Keyring{path: filepath.Join(dir, KeyFileName)}
	if err := k.load(); err != nil {
		k.err = err
		return k, err
	}
	return k, nil
}

// OpenWithKey builds an in-memory keyring from an explicit key. For tests, and
// for a future deployment that keeps the key somewhere other than a file.
func OpenWithKey(key []byte) (*Keyring, error) {
	k := &Keyring{}
	if err := k.adopt(key); err != nil {
		return nil, err
	}
	return k, nil
}

// Available reports whether the keyring can seal and open. When false, Err
// says why.
func (k *Keyring) Available() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.aead != nil
}

// Err returns why the keyring is unavailable, or nil.
func (k *Keyring) Err() error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.err
}

// KeyID identifies the key currently in use.
//
// Stored alongside every ciphertext so that a future key rotation can tell
// which rows have been re-sealed and which are still under the old key. It is
// a truncated hash of the key, not the key: it appears in the database and
// must not narrow a search for the real thing.
func (k *Keyring) KeyID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keyID
}

// Seal encrypts plaintext, binding it to owner.
//
// owner becomes AES-GCM's additional authenticated data. It is not encrypted —
// the caller already knows it — but it is authenticated, so a ciphertext moved
// from one provider's row to another fails to open instead of silently
// authenticating provider A with provider B's credential. Direct database
// edits and UPDATE bugs both produce that situation, and both should be loud.
func (k *Keyring) Seal(plaintext []byte, owner string) ([]byte, error) {
	k.mu.RLock()
	aead, err := k.aead, k.err
	k.mu.RUnlock()

	if aead == nil {
		if err == nil {
			err = ErrNoKey
		}
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secrets: read nonce: %w", err)
	}

	// nonce ‖ sealed. Prepending rather than storing two columns keeps the
	// database honest about what a ciphertext is: one opaque blob that is
	// meaningless without the key, rather than two fields somebody might
	// reasonably think could be handled separately.
	return aead.Seal(nonce, nonce, plaintext, []byte(owner)), nil
}

// Open decrypts a value sealed for owner.
func (k *Keyring) Open(sealed []byte, owner string) ([]byte, error) {
	k.mu.RLock()
	aead, err := k.aead, k.err
	k.mu.RUnlock()

	if aead == nil {
		if err == nil {
			err = ErrNoKey
		}
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, ErrOpenFailed
	}

	nonce, body := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	out, openErr := aead.Open(nil, nonce, body, []byte(owner))
	if openErr != nil {
		// The underlying error is deliberately not wrapped. crypto/cipher's
		// message is "message authentication failed", which is accurate and
		// says nothing an attacker can use — but wrapping it invites callers
		// to match on it, and the distinction this package wants callers to
		// make is ErrNoKey versus ErrOpenFailed.
		return nil, ErrOpenFailed
	}
	return out, nil
}

// load reads the key file, creating it if it does not exist.
func (k *Keyring) load() error {
	raw, err := os.ReadFile(k.path)
	switch {
	case err == nil:
		if len(raw) != keyLen {
			return fmt.Errorf("secrets: %s is %d bytes, want %d: %w",
				k.path, len(raw), keyLen, ErrNoKey)
		}
		return k.adopt(raw)
	case errors.Is(err, fs.ErrNotExist):
		return k.create()
	default:
		return fmt.Errorf("secrets: read %s: %w", k.path, err)
	}
}

// create generates a new key and writes it with mode 0600.
//
// Written to a temporary file and renamed, so a crash midway cannot leave a
// short key that would later be adopted as real. The temporary file is created
// with the final mode rather than chmod'ed afterwards: there must be no window
// in which the key is world-readable.
func (k *Keyring) create() error {
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("secrets: generate key: %w", err)
	}

	dir := filepath.Dir(k.path)
	tmp, err := os.CreateTemp(dir, ".secrets.key-*")
	if err != nil {
		return fmt.Errorf("secrets: create key file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed

	if err := tmp.Chmod(keyFileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("secrets: set key file mode: %w", err)
	}
	if _, err := tmp.Write(key); err != nil {
		tmp.Close()
		return fmt.Errorf("secrets: write key: %w", err)
	}
	// Durability matters more than speed for a file written once: a key that
	// reaches the directory entry but not the disk turns every stored
	// credential into ciphertext nobody can open.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("secrets: sync key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("secrets: close key: %w", err)
	}
	if err := os.Rename(tmpName, k.path); err != nil {
		return fmt.Errorf("secrets: install key file: %w", err)
	}
	return k.adopt(key)
}

// adopt installs a key, deriving its identifier.
func (k *Keyring) adopt(key []byte) error {
	if len(key) != keyLen {
		return fmt.Errorf("secrets: key is %d bytes, want %d", len(key), keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("secrets: build cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("secrets: build GCM: %w", err)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	k.aead = aead
	k.keyID = keyIdentifier(key)
	k.err = nil
	return nil
}

// keyIdentifier derives a short, non-reversing label for a key.
//
// It is the first 8 bytes of the key's SHA-256, hex encoded. That is enough to
// tell two keys apart in a database column and far too little to help anyone
// recover the key: reversing it means inverting SHA-256 on a 256-bit random
// input, and the truncation means even a successful preimage is one of an
// astronomical number of candidates.
func keyIdentifier(key []byte) string {
	sum := sha256Sum(key)
	return "k" + hex.EncodeToString(sum[:8])
}

// Hint returns the trailing characters of a secret, for a UI that has to show
// the operator *which* credential is stored without showing the credential.
//
// Four characters of an API key is not a meaningful disclosure: it is what a
// vendor's own console shows, and it is far too little to narrow a search for
// the rest. Anything shorter than nine characters gets no hint at all, because
// at that length four characters is a large fraction of the whole and the
// value is more likely to be something that is not really a key.
func Hint(secret string) string {
	const (
		show = 4
		min  = 9
	)
	if len(secret) < min {
		return ""
	}
	return secret[len(secret)-show:]
}
