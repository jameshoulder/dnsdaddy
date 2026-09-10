package trustanchors

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/miekg/dns"
)

// KeyState is a key's position in the RFC 5011 §4 state machine.
//
// The states are the RFC's and the spellings are ours. Which of them count as
// trust anchors is the whole point of the machine and is decided in one place:
// see Trusted.
type KeyState string

const (
	// StateAddPend: seen in a validly signed DNSKEY RRset, waiting out the
	// add hold-down. Not trusted. RFC 5011 §2.4.1.
	StateAddPend KeyState = "addpend"
	// StateValid: a trust anchor, present in the last RRset seen.
	StateValid KeyState = "valid"
	// StateMissing: a trust anchor that was absent from the last validly
	// signed RRset.
	//
	// Still trusted, and that is not an oversight. A key vanishing from the
	// RRset is not a revocation — it is what a temporarily broken publication
	// looks like — and RFC 5011 gives it a state of its own precisely so that
	// one bad answer does not cost a resolver its trust anchor. Only the
	// REVOKE bit, self-signed, takes a key out of service.
	StateMissing KeyState = "missing"
	// StateRevoked: seen with the REVOKE bit set in a self-signed RRset.
	// Untrusted from that moment. RFC 5011 §2.2.
	StateRevoked KeyState = "revoked"
	// StateRemoved: a revoked key whose remove hold-down has passed. Kept
	// only so that a key cannot be reintroduced by an attacker replaying an
	// older RRset.
	StateRemoved KeyState = "removed"
)

// Trusted reports whether a key in this state may act as a trust anchor.
//
// One function, called everywhere, because the difference between the states
// that are trusted and the states that are not is the entire security value of
// RFC 5011. A second reading of it somewhere else is how a revoked key gets
// used to validate an answer.
func (s KeyState) Trusted() bool { return s == StateValid || s == StateMissing }

// ManagedKey is one key at a trust point, with the timers §4 needs.
//
// The key material is stored in DNSKEY presentation form rather than as a
// parsed record, so the file an operator opens shows the same text BIND and
// unbound write and can be compared against IANA's published anchors by eye.
type ManagedKey struct {
	// Key is the DNSKEY in presentation form, for example
	// ". 172800 IN DNSKEY 257 3 8 AwEAAa...".
	Key string `json:"key"`
	// KeyTag, Algorithm and Flags are denormalised from Key so that a person
	// reading the file can see which key a line is about without decoding
	// base64. Nothing reads them: every decision parses Key.
	KeyTag    uint16 `json:"keyTag"`
	Algorithm uint8  `json:"algorithm"`
	Flags     uint16 `json:"flags"`

	State KeyState `json:"state"`
	// FirstSeen is when the key first appeared in a validly signed RRset.
	FirstSeen time.Time `json:"firstSeen"`
	// LastSeen is the most recent validly signed RRset it appeared in.
	LastSeen time.Time `json:"lastSeen,omitempty"`
	// AddHoldDownUntil is when an AddPend key may become Valid, if it has
	// been present continuously since FirstSeen. RFC 5011 §2.4.1.
	AddHoldDownUntil time.Time `json:"addHoldDownUntil,omitempty"`
	// RevokedAt is when the REVOKE bit was first seen, self-signed.
	RevokedAt time.Time `json:"revokedAt,omitempty"`
	// RemoveHoldDownUntil is when a Revoked key becomes Removed.
	// RFC 5011 §2.4.2.
	RemoveHoldDownUntil time.Time `json:"removeHoldDownUntil,omitempty"`
	// Seeded marks a key that became Valid by matching a configured DS
	// digest rather than by waiting out a hold-down.
	//
	// Recorded because the two are different provenances and an operator
	// auditing what their resolver trusts is entitled to tell them apart: a
	// seeded key is one they shipped, a held-down key is one the root zone
	// convinced this resolver to accept.
	Seeded bool `json:"seeded,omitempty"`
}

// DNSKEY parses the stored key.
func (k ManagedKey) DNSKEY() (*dns.DNSKEY, error) {
	rr, err := dns.NewRR(k.Key)
	if err != nil {
		return nil, fmt.Errorf("trustanchors: unparseable stored key: %w", err)
	}
	key, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, fmt.Errorf("trustanchors: stored record is a %s, not a DNSKEY",
			dns.TypeToString[rr.Header().Rrtype])
	}
	return key, nil
}

// TrustPoint is the managed state for one zone.
type TrustPoint struct {
	// Zone is the trust point, canonical.
	Zone string `json:"zone"`
	// Keys is every key this trust point has ever seen that has not been
	// forgotten, in key-tag order so the file is stable across writes.
	Keys []ManagedKey `json:"keys"`

	// LastRefresh is when a refresh was last attempted, LastSuccess when one
	// last completed with a validly signed RRset.
	//
	// Both, separately. A single "last updated" that moved on failure would
	// answer the wrong question: what an operator needs to know is how old
	// the evidence is, not how recently something tried.
	LastRefresh time.Time `json:"lastRefresh,omitempty"`
	LastSuccess time.Time `json:"lastSuccess,omitempty"`
	// LastError is why the last attempt failed, empty after a success.
	LastError string `json:"lastError,omitempty"`
	// NextRefresh is when the next attempt is due. RFC 5011 §2.3.
	NextRefresh time.Time `json:"nextRefresh,omitempty"`

	// NeedsIntervention marks a trust point that can no longer be maintained
	// automatically and requires an operator. See Manager.refresh.
	NeedsIntervention bool   `json:"needsIntervention,omitempty"`
	InterventionNote  string `json:"interventionNote,omitempty"`
}

// TrustedKeys returns the keys currently acting as trust anchors.
func (t TrustPoint) TrustedKeys() []ManagedKey {
	var out []ManagedKey
	for _, k := range t.Keys {
		if k.State.Trusted() {
			out = append(out, k)
		}
	}
	return out
}

// sortKeys puts the keys in a stable order, so two states that mean the same
// thing produce the same file and a diff of the file shows real changes.
func (t *TrustPoint) sortKeys() {
	sort.SliceStable(t.Keys, func(i, j int) bool {
		a, b := t.Keys[i], t.Keys[j]
		if a.KeyTag != b.KeyTag {
			return a.KeyTag < b.KeyTag
		}
		if a.Algorithm != b.Algorithm {
			return a.Algorithm < b.Algorithm
		}
		return a.Key < b.Key
	})
}

// Store persists a trust point between runs.
//
// An interface rather than a file path, because this package must keep working
// without a filesystem: the tests drive thirty days of hold-down in
// microseconds and would otherwise be writing temporary files to do it, and a
// deployment may want the state somewhere else entirely.
//
// Load returning ErrNoState means "nothing stored yet", which is a normal
// first run and not a failure.
type Store interface {
	Load() (TrustPoint, error)
	Save(TrustPoint) error
}

// ErrNoState reports that no trust point has been stored yet.
var ErrNoState = errors.New("trustanchors: no stored trust point")

// FileStore keeps the trust point in a JSON file.
//
// JSON rather than the managed-keys format BIND writes, because this file is
// ours to read and ours alone: nothing else parses it, and inventing a parser
// for somebody else's format would be a second place for a trust decision to
// be misread. An operator who wants the anchors in the published DS spelling
// has `dnsdaddy daddybound anchors`, which prints them.
type FileStore struct {
	Path string
}

// Load reads the stored trust point.
func (f FileStore) Load() (TrustPoint, error) {
	// #nosec G304 -- the path comes from the operator's own configuration and
	// is read at startup and on a refresh timer. There is no request-time
	// input here.
	raw, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return TrustPoint{}, ErrNoState
	}
	if err != nil {
		return TrustPoint{}, fmt.Errorf("trustanchors: reading %s: %w", f.Path, err)
	}
	var tp TrustPoint
	if err := json.Unmarshal(raw, &tp); err != nil {
		// Deliberately an error rather than a silent re-seed. A corrupt state
		// file might be a truncated write, and it might be somebody editing
		// what this resolver trusts; either way the caller decides what to do
		// about it, and Manager falls back to the configured anchors rather
		// than to nothing.
		return TrustPoint{}, fmt.Errorf("trustanchors: %s is not readable state: %w", f.Path, err)
	}
	return tp, nil
}

// Save writes the trust point, atomically.
//
// Through a temporary file and a rename, because the alternative is a torn
// write. A process killed halfway through overwriting this file in place
// leaves a resolver that, on its next start, cannot read what it trusts —
// which is the failure this whole slice exists to make survivable.
func (f FileStore) Save(tp TrustPoint) error {
	tp.sortKeys()
	raw, err := json.MarshalIndent(tp, "", "  ")
	if err != nil {
		return fmt.Errorf("trustanchors: encoding state: %w", err)
	}
	raw = append(raw, '\n')

	dir := filepath.Dir(f.Path)
	tmp, err := os.CreateTemp(dir, ".anchors-*.tmp")
	if err != nil {
		return fmt.Errorf("trustanchors: creating a temporary file in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer os.Remove(name) //nolint:errcheck // best effort; the rename below normally consumes it

	// 0600: the file records what this resolver trusts. It is not a secret,
	// but a file anyone can write is a file anyone can use to change that.
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close() //nolint:errcheck // the error below is the one that matters
		return fmt.Errorf("trustanchors: %s: %w", name, err)
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close() //nolint:errcheck // the error below is the one that matters
		return fmt.Errorf("trustanchors: writing %s: %w", name, err)
	}
	// Synced before the rename. A rename is atomic with respect to other
	// processes but says nothing about what reached the disk, and a power
	// loss between the two leaves the new name pointing at an empty file.
	if err := tmp.Sync(); err != nil {
		tmp.Close() //nolint:errcheck // the error below is the one that matters
		return fmt.Errorf("trustanchors: syncing %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("trustanchors: closing %s: %w", name, err)
	}
	if err := os.Rename(name, f.Path); err != nil {
		return fmt.Errorf("trustanchors: replacing %s: %w", f.Path, err)
	}
	return nil
}

// MemoryStore keeps the trust point in memory, for tests.
type MemoryStore struct {
	tp     TrustPoint
	loaded bool
	// SaveErr, when set, makes every Save fail. For proving that a resolver
	// keeps validating with the anchors it has when it cannot persist them.
	SaveErr error
	// Saves counts writes.
	Saves int
}

// Load returns the stored trust point.
func (m *MemoryStore) Load() (TrustPoint, error) {
	if !m.loaded {
		return TrustPoint{}, ErrNoState
	}
	return m.tp, nil
}

// Save records the trust point.
func (m *MemoryStore) Save(tp TrustPoint) error {
	if m.SaveErr != nil {
		return m.SaveErr
	}
	tp.sortKeys()
	m.tp, m.loaded = tp, true
	m.Saves++
	return nil
}
