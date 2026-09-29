package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type RestoreResult struct {
	Destination        string    `json:"destination"`
	ConfigPath         string    `json:"configPath"`
	Files              int       `json:"files"`
	SessionsRevoked    int64     `json:"sessionsRevoked"`
	CreatedAt          time.Time `json:"createdAt"`
	ApplicationVersion string    `json:"applicationVersion"`
}

// Restore authenticates and verifies every file before declaring success.
// The destination must not exist. Files are created through an os.Root with
// O_EXCL and 0600; the archive supplies neither ownership nor permissions.
// Only manifest-allowlisted regular files are accepted. There is no archive
// compression, so a decompression bomb cannot amplify the supported 1 GiB
// plaintext ceiling. A failure removes the new destination.
func Restore(ctx context.Context, src io.Reader, passphrase []byte, destination string) (result RestoreResult, err error) {
	if err := ValidatePassphrase(passphrase); err != nil {
		return result, err
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return result, err
	}
	if abs == filepath.VolumeName(abs)+string(filepath.Separator) {
		return result, errors.New("restore destination must be a new directory")
	}
	parent, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return result, fmt.Errorf("open restore parent: %w", err)
	}
	defer parent.Close()
	base := filepath.Base(abs)
	if _, err := parent.Lstat(base); !errors.Is(err, os.ErrNotExist) {
		return result, errors.New("restore destination already exists; choose a new directory")
	}
	// Mkdir is exclusive. It cannot overwrite a file, directory or symlink
	// created by another actor after the existence check.
	if err := parent.Mkdir(base, 0o700); err != nil {
		return result, fmt.Errorf("create new restore directory: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = parent.RemoveAll(base)
		}
	}()
	root, err := parent.OpenRoot(base)
	if err != nil {
		return result, err
	}
	defer root.Close()
	decrypted, err := newOpenReader(&contextReader{ctx: ctx, r: src}, passphrase)
	if err != nil {
		return result, err
	}
	tarReader := tar.NewReader(decrypted)
	head, err := tarReader.Next()
	if err != nil {
		return result, fmt.Errorf("read backup manifest: %w", err)
	}
	if head.Name != "manifest.json" || head.Typeflag != tar.TypeReg || head.Size <= 0 || head.Size > maxManifestBytes || len(head.PAXRecords) > 0 {
		return result, errors.New("invalid backup manifest entry")
	}
	b, err := io.ReadAll(io.LimitReader(tarReader, maxManifestBytes+1))
	if err != nil {
		return result, err
	}
	var manifest Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return result, errors.New("invalid backup manifest")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return result, errors.New("invalid backup manifest trailer")
	}
	if manifest.FormatVersion != FormatVersion || len(manifest.Files) == 0 || len(manifest.Files) > maxFiles {
		return result, errors.New("unsupported backup manifest version or size")
	}
	expected := map[string]File{}
	var total int64
	for _, f := range manifest.Files {
		if !validArchiveName(f.Name) || !allowedFile(f.Name) || f.Size < 0 || f.Size > archiveFileLimit(f.Name) {
			return result, errors.New("unsafe or unsupported backup filename or size")
		}
		if _, ok := expected[f.Name]; ok {
			return result, errors.New("duplicate backup filename")
		}
		if digest, err := hex.DecodeString(f.SHA256); err != nil || len(digest) != sha256.Size {
			return result, errors.New("invalid backup checksum")
		}
		total += f.Size
		if total > MaxArchiveBytes-(8<<20) {
			return result, ErrLimit
		}
		expected[f.Name] = f
	}
	if _, ok := expected["config.yaml"]; !ok {
		return result, errors.New("backup has no runtime configuration")
	}
	if _, ok := expected["data/dnsdaddy.db"]; !ok {
		return result, errors.New("backup has no database")
	}
	seen := map[string]bool{}
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, err
		}
		want, ok := expected[h.Name]
		if !ok || seen[h.Name] || h.Typeflag != tar.TypeReg || h.Size != want.Size || len(h.PAXRecords) > 0 || h.Linkname != "" {
			return result, errors.New("backup contains an unexpected, duplicate or non-regular file")
		}
		if err := root.MkdirAll(filepath.Dir(h.Name), 0o700); err != nil {
			return result, err
		}
		file, err := root.OpenFile(h.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return result, err
		}
		hash := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(file, hash), tarReader)
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr != nil {
			return result, copyErr
		}
		if syncErr != nil {
			return result, syncErr
		}
		if closeErr != nil {
			return result, closeErr
		}
		if n != want.Size || hex.EncodeToString(hash.Sum(nil)) != want.SHA256 {
			return result, fmt.Errorf("backup checksum failed for %s", h.Name)
		}
		seen[h.Name] = true
	}
	// tar.Reader stops at its end markers. Consume and authenticate the
	// remaining record stream so removing the final GCM record cannot pass.
	// Only normal zero tar padding is permitted after the end markers.
	padding := make([]byte, 4096)
	for {
		n, readErr := decrypted.Read(padding)
		for _, v := range padding[:n] {
			if v != 0 {
				return result, errors.New("unexpected trailing backup data")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return result, readErr
		}
	}
	if len(seen) != len(expected) {
		return result, errors.New("backup is missing a manifest file")
	}
	if err := validateRestoredKey(ctx, filepath.Join(abs, "data/dnsdaddy.db"), root, expected); err != nil {
		return result, err
	}
	if err := rewriteConfiguration(root, abs, manifest); err != nil {
		return result, err
	}
	revoked, err := finishDatabase(ctx, filepath.Join(abs, "data/dnsdaddy.db"), abs, manifest)
	if err != nil {
		return result, err
	}
	// Keep provenance with the recovered instance, inside its private tree.
	if err := writeRootFile(root, "backup-manifest.json", b); err != nil {
		return result, err
	}
	note := fmt.Sprintf("DNS Daddy recovery completed at %s.\nSource backup created: %s\nSource application: %s\nActive dashboard sessions revoked: %d\n\nThe restored service has NOT been started. Review config.yaml, network bindings,\nACLs and external credentials. Preserve source-config.yaml for reference; it may\ncontain old passwords or host paths and is not the launch configuration.\n", time.Now().UTC().Format(time.RFC3339), manifest.CreatedAt.Format(time.RFC3339), manifest.ApplicationVersion, revoked)
	if err := writeRootFile(root, "RESTORE.txt", []byte(note)); err != nil {
		return result, err
	}
	if err := syncDirectory(abs); err != nil {
		return result, err
	}
	ok = true
	return RestoreResult{Destination: abs, ConfigPath: filepath.Join(abs, "config.yaml"), Files: len(seen), SessionsRevoked: revoked, CreatedAt: manifest.CreatedAt, ApplicationVersion: manifest.ApplicationVersion}, nil
}

func allowedFile(name string) bool {
	switch name {
	case "config.yaml", "source-config.yaml", "data/dnsdaddy.db", "data/secrets.key", "data/daddybound-anchors.json", "data/daddybound-learning.json", "refs/dns-tls-cert.pem", "refs/dns-tls-key.pem", "refs/custom-trust-anchors.txt":
		return true
	}
	return strings.HasPrefix(name, "data/feeds/") && strings.HasSuffix(name, ".list") || strings.HasPrefix(name, "refs/local-feeds/")
}

func archiveFileLimit(name string) int64 {
	switch name {
	case "config.yaml", "source-config.yaml":
		return maxConfigBytes
	case "data/secrets.key":
		return 4096
	case "data/daddybound-anchors.json", "data/daddybound-learning.json", "refs/dns-tls-cert.pem", "refs/dns-tls-key.pem", "refs/custom-trust-anchors.txt":
		return maxStateBytes
	default:
		return MaxArchiveBytes
	}
}

func writeRootFile(root *os.Root, name string, b []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := writeAll(f, b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func rewriteConfiguration(root *os.Root, destination string, m Manifest) error {
	f, err := root.Open("config.yaml")
	if err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	f.Close()
	if err != nil {
		return err
	}
	if int64(len(b)) > maxConfigBytes {
		return ErrLimit
	}
	defer clear(b)
	var document yaml.Node
	if err := yaml.Unmarshal(b, &document); err != nil {
		return errors.New("runtime configuration is not valid YAML")
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("runtime configuration must be a YAML mapping")
	}
	setYAMLPath(document.Content[0], []string{"data_dir"}, filepath.Join(destination, "data"))
	// The database preserves the current admin password hash. Reapplying an
	// old bootstrap password from a YAML file would silently undo a password
	// change made in the dashboard, so launch configuration clears it.
	setYAMLPath(document.Content[0], []string{"http", "admin_password"}, "")
	for key, name := range m.Paths {
		valid := map[string]string{"dns.tls_cert_file": "refs/dns-tls-cert.pem", "dns.tls_key_file": "refs/dns-tls-key.pem", "dns.local_dnssec_trust_anchor_file": "refs/custom-trust-anchors.txt", "feeds.local_feed_dir": "refs/local-feeds"}
		if valid[key] != name {
			return errors.New("backup has an unsupported configuration path mapping")
		}
		setYAMLPath(document.Content[0], strings.Split(key, "."), filepath.Join(destination, filepath.FromSlash(name)))
	}
	// A separate JSONL sink is derived output; keep future writes in the new
	// private tree rather than to the original host's absolute path.
	if n := yamlPath(document.Content[0], []string{"detection", "findings_file"}); n != nil && n.Value != "" {
		n.Value = filepath.Join(destination, "data", "findings.jsonl")
	}
	encoded, err := yaml.Marshal(&document)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return writeRootFile(root, "config.yaml", encoded)
}

func yamlPath(root *yaml.Node, parts []string) *yaml.Node {
	if len(parts) == 0 {
		return root
	}
	if root.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == parts[0] {
			return yamlPath(root.Content[i+1], parts[1:])
		}
	}
	return nil
}
func setYAMLPath(root *yaml.Node, parts []string, value string) {
	if len(parts) == 0 {
		root.Kind = yaml.ScalarNode
		root.Tag = "!!str"
		root.Value = value
		root.Content = nil
		return
	}
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == parts[0] {
			setYAMLPath(root.Content[i+1], parts[1:], value)
			return
		}
	}
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: parts[0]}, n)
	setYAMLPath(n, parts[1:], value)
}

func validateRestoredKey(ctx context.Context, dbPath string, root *os.Root, files map[string]File) error {
	var items []*inputFile
	if _, ok := files["data/secrets.key"]; ok {
		f, err := root.Open("data/secrets.key")
		if err != nil {
			return err
		}
		defer f.Close()
		items = append(items, &inputFile{name: "data/secrets.key", file: f})
	}
	return validateCredentials(ctx, dbPath, items)
}

func finishDatabase(ctx context.Context, dbPath, destination string, m Manifest) (int64, error) {
	u := url.URL{Scheme: "file", Path: dbPath}
	q := u.Query()
	q.Set("mode", "rw")
	q.Add("_pragma", "foreign_keys(ON)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return 0, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return 0, errors.New("restored SQLite database failed its integrity check")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	deleted, err := tx.ExecContext(ctx, "DELETE FROM sessions")
	if err != nil {
		return 0, err
	}
	revoked, err := deleted.RowsAffected()
	if err != nil {
		return 0, err
	}
	if m.LocalFeedRoot != "" {
		rows, err := tx.QueryContext(ctx, "SELECT id,url FROM feeds WHERE url LIKE 'file:%'")
		if err != nil {
			return 0, err
		}
		type pair struct{ id, url string }
		var updates []pair
		for rows.Next() {
			var id, raw string
			if err := rows.Scan(&id, &raw); err != nil {
				rows.Close()
				return 0, err
			}
			u, err := url.Parse(raw)
			if err != nil {
				rows.Close()
				return 0, errors.New("invalid stored local feed URL")
			}
			rel, err := filepath.Rel(m.LocalFeedRoot, u.Path)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
				rows.Close()
				return 0, errors.New("local feed lies outside the backed-up source directory")
			}
			u.Path = filepath.Join(destination, "refs", "local-feeds", rel)
			updates = append(updates, pair{id, u.String()})
		}
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return 0, rowErr
		}
		for _, p := range updates {
			if _, err := tx.ExecContext(ctx, "UPDATE feeds SET url=? WHERE id=?", p.url, p.id); err != nil {
				return 0, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=DELETE"); err != nil {
		return 0, err
	}
	return revoked, nil
}

func syncDirectory(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
