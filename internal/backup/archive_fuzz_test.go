package backup

import (
	"path"
	"strings"
	"testing"
)

// Archive entry names come from encrypted backup material after authentication.
// Path traversal and control characters must never be accepted as archive paths.
func FuzzValidArchiveName(f *testing.F) {
	for _, seed := range []string{
		"manifest.json",
		"data/dnsdaddy.db",
		"../etc/passwd",
		"/etc/passwd",
		"..",
		"a/../../b",
		"ok:colon",
		"has\\slash",
		string([]byte{'a', 0x00, 'b'}),
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		ok := validArchiveName(name)
		if !ok {
			return
		}
		// Every accepted name must satisfy the same invariants the helper claims.
		if name == "" {
			t.Fatal("empty name accepted")
		}
		if path.IsAbs(name) || path.Clean(name) != name {
			t.Fatalf("accepted unclean or absolute path %q", name)
		}
		if strings.ContainsAny(name, "\\\x00") {
			t.Fatalf("accepted name with backslash or NUL: %q", name)
		}
		for _, c := range name {
			if c <= 0x1f || (c >= 0x7f && c <= 0x9f) {
				t.Fatalf("accepted control character in %q", name)
			}
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." || part == "." || part == "" || strings.Contains(part, ":") {
				t.Fatalf("accepted traversal or colon component in %q", name)
			}
		}
	})
}

func FuzzValidatePassphrase(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("short"))
	f.Add([]byte("a-sufficiently-long-passphrase-for-testing"))
	f.Fuzz(func(t *testing.T, p []byte) {
		_ = ValidatePassphrase(p)
	})
}
