package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"gopkg.in/yaml.v3"
)

var ErrAdminNotReady = errors.New("backup refused: administrator credentials must be active; complete existing password activation or secure recovery first")

const AdminPendingProof = "pending_password_proof"

// AdminRecoveryNoticeName is relative to the confined administrator data directory.
const AdminRecoveryNoticeName = "ADMIN_RECOVERY_REQUIRED.json"

func snapshotAdminStatus(ctx context.Context, path string) (string, error) {
	db, err := sqliteReadOnly(path)
	if err != nil {
		return "", store.ErrAdminStorage
	}
	defer db.Close()
	c, err := store.SnapshotCredential(ctx, db)
	if err != nil {
		return "", err
	}
	if c.State == store.AuthActive {
		return store.AuthActive, nil
	}
	if c.State == store.AuthBootstrapPending && c.Hash != "" && c.Source == "generated" {
		return AdminPendingProof, nil
	}
	return store.AuthRecoveryRequired, nil
}

// Preserve original YAML on disk, but export only a normalized reference copy.
// Comments/aliases/unknown fields must not hide an excluded bootstrap password.
func sanitizedConfig(b []byte) ([]byte, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(b, &node); err != nil {
		return nil, errors.New("backup source configuration is invalid or ambiguous")
	}
	var check func(*yaml.Node) bool
	check = func(n *yaml.Node) bool {
		if n.Kind == yaml.AliasNode || n.Anchor != "" {
			return false
		}
		for _, c := range n.Content {
			if !check(c) {
				return false
			}
		}
		return true
	}
	if !check(&node) {
		return nil, errors.New("backup source configuration aliases are unsupported; use explicit fields")
	}
	var cfg config.Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, errors.New("backup source configuration is invalid or unsupported")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("backup source configuration must contain one document")
	}
	cfg.HTTP.AdminPassword = ""
	return yaml.Marshal(configValue(reflect.ValueOf(cfg)))
}
func stageSanitizedSource(source, destination string) error {
	f, err := openRegular(source, maxConfigBytes)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	defer clear(b)
	if err != nil {
		return err
	}
	if int64(len(b)) > maxConfigBytes {
		return ErrLimit
	}
	clean, err := sanitizedConfig(b)
	if err != nil {
		return err
	}
	defer clear(clean)
	return os.WriteFile(destination, clean, 0600)
}
