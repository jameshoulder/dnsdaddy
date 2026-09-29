package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/secrets"
	"github.com/jameshoulder/dnsdaddy/internal/webhook"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

const (
	maxFiles               = 4096
	maxConfigBytes   int64 = 4 << 20
	maxStateBytes    int64 = 8 << 20
	maxManifestBytes int64 = 2 << 20
)

// Options contains only server-owned configuration; HTTP callers cannot name
// paths or choose which host files the backup reads.
type Options struct {
	Config     config.Config
	ConfigPath string
	Database   *sql.DB
	Version    string
	// FlushLearning persists a fresh bounded model checkpoint, if the local
	// learner is available. No query/provider work should be done here.
	FlushLearning func(context.Context) error
}

type Manager struct {
	opts    Options
	running atomic.Bool
}

func New(opts Options) *Manager { return &Manager{opts: opts} }

type File struct {
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	CapturedAt time.Time `json:"capturedAt"`
}

// Manifest is inside the authenticated encryption. It is not a public index
// to the configuration or credentials in a package.
type Manifest struct {
	FormatVersion      int       `json:"formatVersion"`
	ApplicationVersion string    `json:"applicationVersion"`
	CreatedAt          time.Time `json:"createdAt"`
	Files              []File    `json:"files"`
	// Paths map known configuration fields to an archived supporting file.
	Paths         map[string]string `json:"paths"`
	LocalFeedRoot string            `json:"localFeedRoot,omitempty"`
	Limitations   []string          `json:"limitations"`
}

type Status struct {
	Available       bool     `json:"available"`
	FormatVersion   int      `json:"formatVersion"`
	Encrypted       bool     `json:"encrypted"`
	RestoreMode     string   `json:"restoreMode"`
	Running         bool     `json:"running"`
	Included        []string `json:"included"`
	Excluded        []string `json:"excluded"`
	Limitations     []string `json:"limitations"`
	MaxArchiveBytes int64    `json:"maxArchiveBytes"`
}

func (m *Manager) Status() Status {
	return Status{Available: m != nil && m.opts.Database != nil, FormatVersion: FormatVersion, Encrypted: true,
		RestoreMode: "offline_new_directory", Running: m != nil && m.running.Load(),
		Included:        []string{"consistent SQLite snapshot (configuration, history, retained evidence, webhook outbox and API tokens)", "provider and webhook credential encryption key when present", "effective runtime configuration and original YAML when available", "native trust anchors and local learning checkpoint when present", "referenced TLS keys, certificates, custom anchors, local feeds and feed caches"},
		Excluded:        []string{"running process memory and unflushed query/observation queues", "active dashboard sessions (revoked during restore)", "retired session.key and initial-password.txt", "external log files, service units, firewall rules and reverse-proxy configuration"},
		Limitations:     []string{"Database and auxiliary files are separate committed snapshots, not one global transaction.", "Use a stopped service for an exact cross-file recovery point; live backup may omit in-flight observations.", "Restore never starts DNS or contacts external services. Review bind addresses, ACLs, TLS and API tokens before activating the recovered instance."},
		MaxArchiveBytes: MaxArchiveBytes}
}

// Create writes encrypted bytes to dst. It leaves source state unchanged.
// A SQLite VACUUM INTO snapshot contains WAL-committed data without copying
// a changing database file. Auxiliary files are pinned file descriptors and
// must not change during packaging. Temporary plaintext lives in a private
// directory and is removed on every return; it is never returned to HTTP.
func (m *Manager) Create(ctx context.Context, passphrase []byte, dst io.Writer) (Manifest, error) {
	if m == nil || m.opts.Database == nil {
		return Manifest{}, errors.New("recovery is unavailable")
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return Manifest{}, err
	}
	if !m.running.CompareAndSwap(false, true) {
		return Manifest{}, ErrBusy
	}
	defer m.running.Store(false)
	if m.opts.FlushLearning != nil {
		if err := m.opts.FlushLearning(ctx); err != nil {
			return Manifest{}, fmt.Errorf("checkpoint local learning state: %w", err)
		}
	}
	var pageCount, pageSize int64
	if err := m.opts.Database.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return Manifest{}, err
	}
	if err := m.opts.Database.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return Manifest{}, err
	}
	if pageCount < 0 || pageSize <= 0 || pageCount > (MaxArchiveBytes-(8<<20))/pageSize {
		return Manifest{}, ErrLimit
	}
	dir, err := os.MkdirTemp("", "dnsdaddy-backup-")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- Private staging directory needs owner traversal.
		return Manifest{}, err
	}
	dbPath := filepath.Join(dir, "dnsdaddy.db")
	if _, err := m.opts.Database.ExecContext(ctx, "VACUUM INTO ?", dbPath); err != nil {
		return Manifest{}, fmt.Errorf("consistent database snapshot: %w", err)
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		return Manifest{}, err
	}
	items := []*inputFile{}
	defer func() {
		for _, f := range items {
			f.file.Close()
		}
	}()
	manifest := Manifest{FormatVersion: FormatVersion, ApplicationVersion: m.opts.Version, CreatedAt: time.Now().UTC(), Paths: map[string]string{}, Limitations: m.Status().Limitations}
	var total int64
	add := func(name, source string, limit int64, optional bool) error {
		f, err := openRegular(source, limit)
		if errors.Is(err, os.ErrNotExist) && optional {
			return nil
		}
		if err != nil {
			return fmt.Errorf("capture %s: %w", name, err)
		}
		stat, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		total += stat.Size()
		if total > MaxArchiveBytes-(8<<20) || len(items) >= maxFiles {
			f.Close()
			return ErrLimit
		}
		items = append(items, &inputFile{name: name, file: f, stat: stat, captured: time.Now().UTC()})
		return nil
	}
	if err := add("data/dnsdaddy.db", dbPath, MaxArchiveBytes, false); err != nil {
		return Manifest{}, err
	}
	dataDir := m.opts.Config.DataDir
	for _, f := range []struct {
		name  string
		limit int64
	}{{secrets.KeyFileName, 4096}, {"daddybound-anchors.json", maxStateBytes}, {"daddybound-learning.json", maxStateBytes}} {
		if err := add("data/"+f.name, filepath.Join(dataDir, f.name), f.limit, true); err != nil {
			return Manifest{}, err
		}
	}
	modelPresent, anchorsPresent := false, false
	for _, f := range items {
		modelPresent = modelPresent || f.name == "data/daddybound-learning.json"
		anchorsPresent = anchorsPresent || f.name == "data/daddybound-anchors.json"
	}
	if !modelPresent {
		manifest.Limitations = append(manifest.Limitations, "No learning checkpoint was present; a recovered learner starts with an empty baseline.")
	}
	if !anchorsPresent {
		manifest.Limitations = append(manifest.Limitations, "No managed native anchor state was present; configured trust anchors are the recovery starting point.")
	}
	if m.opts.ConfigPath != "" {
		if err := add("source-config.yaml", m.opts.ConfigPath, maxConfigBytes, true); err != nil {
			return Manifest{}, err
		}
	}
	// All paths originate in effective server configuration, never the request.
	for _, f := range []struct{ key, name, source string }{
		{"dns.tls_cert_file", "refs/dns-tls-cert.pem", m.opts.Config.DNS.TLSCertFile},
		{"dns.tls_key_file", "refs/dns-tls-key.pem", m.opts.Config.DNS.TLSKeyFile},
		{"dns.local_dnssec_trust_anchor_file", "refs/custom-trust-anchors.txt", m.opts.Config.DNS.LocalDNSSECTrustAnchorFile},
	} {
		if f.source == "" {
			continue
		}
		if err := add(f.name, f.source, maxStateBytes, false); err != nil {
			return Manifest{}, err
		}
		manifest.Paths[f.key] = f.name
	}
	if err := addDirectory(filepath.Join(dataDir, "feeds"), "data/feeds", true, add); err != nil {
		return Manifest{}, err
	}
	if local := m.opts.Config.Feeds.LocalFeedDir; local != "" {
		absolute, err := filepath.Abs(local)
		if err != nil {
			return Manifest{}, err
		}
		manifest.LocalFeedRoot = absolute
		if err := addDirectory(absolute, "refs/local-feeds", false, add); err != nil {
			return Manifest{}, err
		}
		manifest.Paths["feeds.local_feed_dir"] = "refs/local-feeds"
	}
	// yaml.v3 treats custom integer durations as integers when marshaling.
	// Convert from the schema by reflection so every duration stays loadable
	// as a string and new configuration fields are preserved automatically.
	cfgBytes, err := yaml.Marshal(configValue(reflect.ValueOf(m.opts.Config)))
	if err != nil {
		return Manifest{}, err
	}
	runtimePath := filepath.Join(dir, "runtime-config.yaml")
	if err := os.WriteFile(runtimePath, cfgBytes, 0o600); err != nil {
		return Manifest{}, err
	}
	clear(cfgBytes)
	if err := add("config.yaml", runtimePath, maxConfigBytes, false); err != nil {
		return Manifest{}, err
	}
	if err := validateCredentials(ctx, dbPath, items); err != nil {
		return Manifest{}, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	manifest.Files = []File{}
	for _, f := range items {
		h := sha256.New()
		if _, err := io.Copy(h, &contextReader{ctx: ctx, r: f.file}); err != nil {
			return Manifest{}, err
		}
		if _, err := f.file.Seek(0, io.SeekStart); err != nil {
			return Manifest{}, err
		}
		f.hash = hex.EncodeToString(h.Sum(nil))
		manifest.Files = append(manifest.Files, File{Name: f.name, Size: f.stat.Size(), SHA256: f.hash, CapturedAt: f.captured})
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return Manifest{}, err
	}
	if int64(len(encoded)) > maxManifestBytes {
		return Manifest{}, ErrLimit
	}
	encrypted, err := newSealWriter(dst, passphrase)
	if err != nil {
		return Manifest{}, err
	}
	tarw := tar.NewWriter(encrypted)
	if err := writeTarBytes(tarw, "manifest.json", encoded, manifest.CreatedAt); err != nil {
		return Manifest{}, err
	}
	for _, f := range items {
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		if err := tarw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o600, Size: f.stat.Size(), ModTime: f.captured, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			return Manifest{}, err
		}
		h := sha256.New()
		if n, err := io.CopyN(io.MultiWriter(tarw, h), &contextReader{ctx: ctx, r: f.file}, f.stat.Size()); err != nil || n != f.stat.Size() {
			return Manifest{}, fmt.Errorf("read stable snapshot file %s: %w", f.name, err)
		}
		current, err := f.file.Stat()
		if err != nil {
			return Manifest{}, err
		}
		if current.Size() != f.stat.Size() || !current.ModTime().Equal(f.stat.ModTime()) || hex.EncodeToString(h.Sum(nil)) != f.hash {
			return Manifest{}, fmt.Errorf("snapshot file changed while reading: %s; retry backup", f.name)
		}
	}
	if err := tarw.Close(); err != nil {
		return Manifest{}, err
	}
	if err := encrypted.Close(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

type inputFile struct {
	name     string
	file     *os.File
	stat     fs.FileInfo
	captured time.Time
	hash     string
}
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// openRegular rejects symbolic links and devices. OpenRoot confines a racing
// path replacement to its already-opened parent, and SameFile ensures it is
// the regular inode inspected before opening, not a replacement.
func openRegular(name string, limit int64) (*os.File, error) {
	parent, err := os.OpenRoot(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	base := filepath.Base(name)
	before, err := parent.Lstat(base)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("source must be a regular file, not a symbolic link or device")
	}
	if before.Size() < 0 || before.Size() > limit {
		return nil, ErrLimit
	}
	f, err := parent.Open(base)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		f.Close()
		return nil, errors.New("source changed while opening")
	}
	return f, nil
}

func addDirectory(source, prefix string, optional bool, add func(string, string, int64, bool) error) error {
	st, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) && optional {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("backup source directory must not be a symbolic link")
	}
	return filepath.WalkDir(source, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("backup source contains a symbolic link")
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(source, p)
		if err != nil {
			return err
		}
		name := path.Join(prefix, filepath.ToSlash(rel))
		if !validArchiveName(name) {
			return errors.New("backup source filename is unsupported")
		}
		// Ignore unfinished atomic feed-cache downloads; only .list files are
		// effective feed caches. Local feed content has no extension rule.
		if prefix == "data/feeds" && !strings.HasSuffix(name, ".list") {
			return nil
		}
		return add(name, p, MaxArchiveBytes, false)
	})
}

func configValue(v reflect.Value) any {
	if v.Type() == reflect.TypeFor[config.Duration]() {
		return config.Duration(v.Int()).String()
	}
	switch v.Kind() {
	case reflect.Struct:
		m := map[string]any{}
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			m[name] = configValue(v.Field(i))
		}
		return m
	case reflect.Slice, reflect.Array:
		a := make([]any, v.Len())
		for i := 0; i < v.Len(); i++ {
			a[i] = configValue(v.Index(i))
		}
		return a
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return configValue(v.Elem())
	default:
		return v.Interface()
	}
}

func writeTarBytes(w *tar.Writer, name string, b []byte, t time.Time) error {
	if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: t, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		return err
	}
	return writeAll(w, b)
}

func validArchiveName(name string) bool {
	if name == "" || len(name) > 240 || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || path.Clean(name) != name {
		return false
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return false
		}
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || part == "." || part == "" || strings.Contains(part, ":") {
			return false
		}
	}
	return true
}

func sqliteReadOnly(p string) (*sql.DB, error) {
	u := url.URL{Scheme: "file", Path: p}
	q := u.Query()
	q.Set("mode", "ro")
	q.Add("_pragma", "busy_timeout(10000)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// OpenSource opens an existing database read-only while allowing VACUUM INTO
// to create its separate output. It runs no schema, seeds or migrations.
func OpenSource(p string) (*sql.DB, error) {
	f, err := openRegular(p, MaxArchiveBytes)
	if err != nil {
		return nil, err
	}
	f.Close()
	return sqliteReadOnly(p)
}

func validateCredentials(ctx context.Context, dbPath string, items []*inputFile) error {
	db, err := sqliteReadOnly(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT provider_id,ciphertext,key_id FROM api_provider_secrets")
	if err != nil {
		return err
	}
	defer rows.Close()
	var key []byte
	for _, f := range items {
		if f.name == "data/"+secrets.KeyFileName {
			key, err = io.ReadAll(io.LimitReader(f.file, 4097))
			if err != nil {
				return err
			}
			if _, err = f.file.Seek(0, io.SeekStart); err != nil {
				return err
			}
			break
		}
	}
	defer clear(key)
	var ring *secrets.Keyring
	// secrets.key contains exactly 32 raw bytes, as written by secrets.Keyring.
	if len(key) > 0 {
		ring, err = secrets.OpenWithKey(key)
		if err != nil {
			return errors.New("provider encryption key file is invalid")
		}
	}
	for rows.Next() {
		var id, keyID string
		var ciphertext []byte
		if err := rows.Scan(&id, &ciphertext, &keyID); err != nil {
			return err
		}
		if ring == nil {
			return errors.New("provider credentials exist but their encryption key is missing; backup refused")
		}
		if ring.KeyID() != keyID {
			return errors.New("provider credentials and encryption key do not match; backup refused")
		}
		plain, err := ring.Open(ciphertext, id)
		clear(plain)
		if err != nil {
			return errors.New("a provider credential cannot be decrypted with the included key; backup refused")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	// Webhooks can be configured without any reputation provider. Their
	// signing credential must also be recoverable with the included key.
	var hasWebhookTable int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='webhook_config'").Scan(&hasWebhookTable); err != nil {
		return err
	}
	if hasWebhookTable != 0 {
		var ciphertext []byte
		var keyID string
		err := db.QueryRowContext(ctx, "SELECT ciphertext,key_id FROM webhook_config WHERE id=1 AND length(coalesce(ciphertext,''))>0").Scan(&ciphertext, &keyID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if ring == nil || ring.KeyID() != keyID {
			return errors.New("webhook signing credential and encryption key do not match; backup refused")
		}
		plain, err := ring.Open(ciphertext, webhook.SecretIdentity)
		clear(plain)
		if err != nil {
			return errors.New("webhook signing credential cannot be decrypted with the included key; backup refused")
		}
	}
	return nil
}
