package backup

import "testing"

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
		if name == "" && ok {
			t.Fatal("empty name accepted")
		}
		if (name == ".." || name == "/etc/passwd" || name == "../etc/passwd") && ok {
			t.Fatalf("traversal name %q accepted", name)
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
