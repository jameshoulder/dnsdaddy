package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/backup"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/version"
)

func runBackup(args []string) error {
	fs := newFlagSet("backup")
	configPath := fs.String("config", envOr("DNSDADDY_CONFIG", "/etc/dnsdaddy/config.yaml"), "configuration file")
	output := fs.String("output", "", "new encrypted backup filename (must not exist)")
	passFile := fs.String("passphrase-file", "", "private regular file containing the backup passphrase (owner permissions only)")
	passStdin := fs.Bool("passphrase-stdin", false, "read passphrase from standard input instead of a file")
	timeout := fs.Duration("timeout", 5*time.Minute, "maximum backup duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *output == "" || *timeout <= 0 {
		return errors.New("usage: dnsdaddy backup -config FILE -output NEW_FILE -passphrase-file PRIVATE_FILE")
	}
	passphrase, err := readRecoveryPassphrase(*passFile, *passStdin, os.Stdin)
	if err != nil {
		return err
	}
	defer clear(passphrase)
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	db, err := backup.OpenSource(cfg.DBPath())
	if err != nil {
		return fmt.Errorf("open existing backup source: %w", err)
	}
	defer db.Close()
	f, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create new backup output: %w", err)
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(*output)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	m := backup.New(backup.Options{Config: cfg, ConfigPath: *configPath, Database: db, Version: version.String()})
	manifest, err := m.Create(ctx, passphrase, f)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(*output))
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	dir.Close()
	if syncErr != nil {
		return syncErr
	}
	ok = true
	fmt.Fprintf(os.Stdout, "Encrypted backup created: %s\nFiles: %d\nRecovery point: %s\nRestore only into a new directory with dnsdaddy restore.\n", *output, len(manifest.Files), manifest.CreatedAt.Format(time.RFC3339))
	return nil
}

func runRestore(args []string) error {
	fs := newFlagSet("restore")
	input := fs.String("input", "", "encrypted .ddbackup file")
	destination := fs.String("destination", "", "new restore directory (must not exist)")
	passFile := fs.String("passphrase-file", "", "private passphrase file (owner permissions only)")
	passStdin := fs.Bool("passphrase-stdin", false, "read passphrase from standard input instead of a file")
	timeout := fs.Duration("timeout", 5*time.Minute, "maximum restore duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *input == "" || *destination == "" || *timeout <= 0 {
		return errors.New("usage: dnsdaddy restore -input FILE -destination NEW_DIRECTORY -passphrase-file PRIVATE_FILE")
	}
	passphrase, err := readRecoveryPassphrase(*passFile, *passStdin, os.Stdin)
	if err != nil {
		return err
	}
	defer clear(passphrase)
	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() > backup.MaxArchiveBytes+(1<<20) {
		return errors.New("backup input must be a regular file within the supported size limit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := backup.Restore(ctx, f, passphrase, *destination)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Recovery files verified: %s\nLaunch configuration: %s\nDashboard sessions revoked: %d\n\nThe service has not been started. Review the recovered configuration, network\nbindings, TLS, ACLs and API tokens, then deliberately switch the service over.\n", result.Destination, result.ConfigPath, result.SessionsRevoked)
	return nil
}

func readRecoveryPassphrase(filename string, stdin bool, r io.Reader) ([]byte, error) {
	if (filename == "" && !stdin) || (filename != "" && stdin) {
		return nil, errors.New("choose exactly one of -passphrase-file or -passphrase-stdin; passphrases are never command-line arguments")
	}
	if !stdin {
		before, err := os.Lstat(filename)
		if err != nil {
			return nil, err
		}
		if !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("passphrase file must be a regular file with owner-only permissions (for example chmod 600)")
		}
		f, err := os.Open(filename) // #nosec G304 -- Operator-selected private regular file; inode is verified below before the bounded read.
		if err != nil {
			return nil, err
		}
		defer f.Close()
		after, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if !os.SameFile(before, after) {
			return nil, errors.New("passphrase file changed while opening")
		}
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, 1027))
	if err != nil {
		return nil, err
	}
	// Remove one line ending, preserving intentional leading/trailing spaces.
	passphrase := []byte(strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"))
	clear(b)
	if err := backup.ValidatePassphrase(passphrase); err != nil {
		clear(passphrase)
		return nil, err
	}
	return passphrase, nil
}
