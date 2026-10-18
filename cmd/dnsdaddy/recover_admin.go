//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/api"
	"github.com/jameshoulder/dnsdaddy/internal/backup"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"golang.org/x/sys/unix"
)

var errRecoveryInput = errors.New("offline recovery requires a private existing data tree, stopped service and bounded existing-password proof on stdin")

func recoveryOwned(info os.FileInfo, dir bool) bool {
	if info == nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return false
	}
	if dir {
		return info.IsDir() && info.Mode().Perm()&0022 == 0
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 && st.Nlink == 1
}
func runRecoverAdmin(args []string, input io.Reader, output io.Writer) error {
	fs := newFlagSet("recover-admin")
	dir := fs.String("data-dir", "", "existing private data directory (service must be stopped)")
	proof := fs.Bool("password-stdin", false, "read existing password from stdin; never an argument or environment variable")
	stopped := fs.Bool("service-stopped", false, "operator confirms the service is stopped; no process inspection is performed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *dir == "" || !*proof || !*stopped {
		return errRecoveryInput
	}
	path, err := filepath.Abs(*dir)
	if err != nil {
		return errRecoveryInput
	}
	before, err := os.Lstat(path)
	if err != nil || !recoveryOwned(before, true) {
		return errRecoveryInput
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return errRecoveryInput
	}
	defer root.Close()
	pinned, err := root.Stat(".")
	if err != nil || !os.SameFile(before, pinned) {
		return errRecoveryInput
	}
	parent, err := root.Open(".")
	if err != nil {
		return errRecoveryInput
	}
	defer parent.Close()
	// Serializes cooperating offline recovery commands without a lock-file race.
	// This advisory directory lock does not prove that the daemon is stopped.
	if err := unix.Flock(int(parent.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errRecoveryInput
	}
	named, err := root.Lstat("dnsdaddy.db")
	if err != nil || !recoveryOwned(named, false) {
		return errRecoveryInput
	}
	fd, err := unix.Openat(int(parent.Fd()), "dnsdaddy.db", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errRecoveryInput
	}
	file := os.NewFile(uintptr(fd), "recovery database")
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !recoveryOwned(opened, false) || !os.SameFile(named, opened) {
		return errRecoveryInput
	}
	// SQLite opens the configured pathname and journals. Private owner-controlled
	// tree/ancestors and a stopped service are mandatory; same-UID/root compromise
	// is outside this CLI's filesystem trust boundary. Never create/migrate a DB.
	for _, name := range []string{"dnsdaddy.db-wal", "dnsdaddy.db-shm", "dnsdaddy.db-journal"} {
		info, e := root.Lstat(name)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return errRecoveryInput
		}
		if e == nil && !recoveryOwned(info, false) {
			return errRecoveryInput
		}
	}
	raw, err := io.ReadAll(io.LimitReader(input, 75))
	defer clear(raw)
	if err != nil || len(raw) >= 75 {
		return errRecoveryInput
	}
	password := bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r"))
	if len(password) == 0 || len(password) > 72 {
		return errRecoveryInput
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.OpenAdminRecovery(ctx, filepath.Join(path, "dnsdaddy.db"))
	if err != nil {
		return store.ErrAdminStorage
	}
	defer st.Close()
	current, e := root.Lstat("dnsdaddy.db")
	currentDir, de := os.Stat(path)
	if e != nil || de != nil || !os.SameFile(current, opened) || !os.SameFile(currentDir, pinned) {
		return errRecoveryInput
	}
	auth := api.NewOfflineRecoveryAuth(st)
	err = auth.RecoverPendingAdmin(ctx, password)
	already := errors.Is(err, api.ErrRecoveryAlreadyActive)
	if err != nil && !already {
		return err
	}
	// Commit has happened. Notes are not authorization or credential authority.
	if e := root.Remove(backup.AdminRecoveryNoticeName); e != nil && !errors.Is(e, os.ErrNotExist) {
		return errors.New("administrator credentials are active; recovery note cleanup failed")
	}
	if e := parent.Sync(); e != nil {
		return errors.New("administrator credentials are active; recovery note durability is unconfirmed")
	}
	message := "Existing administrator credentials activated; hash preserved and all sessions revoked.\n"
	if already {
		message = "Administrator credentials already active; no credential or session change made.\n"
	}
	if _, e := io.WriteString(output, message); e != nil {
		return errors.New("administrator credentials are active; status output failed")
	}
	return nil
}
