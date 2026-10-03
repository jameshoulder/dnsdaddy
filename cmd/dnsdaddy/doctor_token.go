package main

import (
	"errors"
	"io"
	"os"
	"strings"
)

// readDoctorToken avoids placing credentials in arguments or creating a session.
// It refuses links/non-regular/over-broad files before reading and limits input.
// The containing directory and local host remain part of the trust boundary.
func readDoctorToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	bad := errors.New("doctor token must be in a readable, owner-only regular file containing a dnsd_ API token")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return "", bad
	}
	f, err := os.Open(path)
	if err != nil {
		return "", bad
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0o077 != 0 {
		return "", bad
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return "", bad
	}
	token := strings.TrimSpace(string(b))
	if !strings.HasPrefix(token, "dnsd_") || len(token) <= len("dnsd_") {
		return "", bad
	}
	for _, c := range token {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return "", bad
		}
	}
	return token, nil
}
