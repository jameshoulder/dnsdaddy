//go:build unix

package api

import (
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const initialPasswordName = "initial-password.txt"

func initialPasswordContent(password string) string {
	return "DNS Daddy initial admin password: " + password + "\n\nChange it from Settings, then delete this file.\n"
}

// The data directory is trusted configuration. Refuse unsafe ownership/write
// permissions for secret delivery; root-relative operations prevent path escape.
func passwordRoot(dir string) (*os.Root, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, ErrPasswordBootstrap
	}
	info, err := root.Stat(".")
	if err != nil || !privateOwnedFile(info, true) {
		root.Close()
		return nil, ErrPasswordBootstrap
	}
	return root, nil
}
func privateOwnedFile(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Getuid()) {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode().Perm()&0o022 == 0
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && stat.Nlink == 1
}
func writeInitialPassword(dir, password string) error {
	root, err := passwordRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(initialPasswordName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrPasswordBootstrap
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !privateOwnedFile(info, false) {
		return ErrPasswordBootstrap
	}
	content := initialPasswordContent(password)
	n, err := io.WriteString(file, content)
	if err != nil || n != len(content) {
		return ErrPasswordBootstrap
	}
	if err = file.Sync(); err != nil {
		return ErrPasswordBootstrap
	}
	if err = file.Close(); err != nil {
		return ErrPasswordBootstrap
	}
	parent, err := root.Open(".")
	if err != nil {
		return ErrPasswordBootstrap
	}
	defer parent.Close()
	if err = parent.Sync(); err != nil {
		return ErrPasswordBootstrap
	}
	return nil
}
func readInitialPassword(dir string) (string, error) {
	root, err := passwordRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	before, err := root.Lstat(initialPasswordName)
	if err != nil || !privateOwnedFile(before, false) {
		return "", ErrPasswordBootstrap
	}
	// O_NONBLOCK prevents a racing FIFO replacement from hanging startup;
	// O_NOFOLLOW refuses even an in-root symlink at the final component.
	parent, err := root.Open(".")
	if err != nil {
		return "", ErrPasswordBootstrap
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), initialPasswordName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	var file *os.File
	if err == nil {
		file = os.NewFile(uintptr(fd), initialPasswordName)
	}
	if err != nil {
		return "", ErrPasswordBootstrap
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !privateOwnedFile(after, false) || !os.SameFile(before, after) {
		return "", ErrPasswordBootstrap
	}
	content, err := io.ReadAll(io.LimitReader(file, 513))
	if err != nil || len(content) > 512 {
		return "", ErrPasswordBootstrap
	}
	line, _, ok := strings.Cut(string(content), "\n")
	if !ok {
		return "", ErrPasswordBootstrap
	}
	password, ok := strings.CutPrefix(line, "DNS Daddy initial admin password: ")
	if !ok || validateNewPassword(password) != nil || string(content) != initialPasswordContent(password) {
		return "", ErrPasswordBootstrap
	}
	// Refuse replacement during the read as well.
	end, err := root.Lstat(initialPasswordName)
	if err != nil || !os.SameFile(after, end) || !privateOwnedFile(end, false) {
		return "", ErrPasswordBootstrap
	}
	if err := file.Sync(); err != nil {
		return "", ErrPasswordBootstrap
	}
	if err := parent.Sync(); err != nil {
		return "", ErrPasswordBootstrap
	}
	return password, nil
}
