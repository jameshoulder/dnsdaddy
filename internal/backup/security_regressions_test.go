package backup

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestSecurityRestoreRejectsUnknownEmptyManifestMapping(t *testing.T) {
    dir := t.TempDir()
    if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("data_dir: /elsewhere\nhttp:\n  admin_password: old\n"), 0o600); err != nil {
        t.Fatal(err)
    }
    root, err := os.OpenRoot(dir)
    if err != nil {
        t.Fatal(err)
    }
    defer root.Close()

    for _, path := range []string{"unexpected.field", "data_dir", "http.admin_password"} {
        err := rewriteConfiguration(root, dir, Manifest{Paths: map[string]string{path: ""}})
        if err == nil {
            t.Fatalf("restore accepted unsupported mapping %q with empty value", path)
        }
    }
}

func TestSecurityRestoreForcesCredentialAndDataLocation(t *testing.T) {
    dir := t.TempDir()
    if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("data_dir: /old\nhttp:\n  admin_password: old\n"), 0o600); err != nil {
        t.Fatal(err)
    }
    root, err := os.OpenRoot(dir)
    if err != nil {
        t.Fatal(err)
    }
    defer root.Close()

    if err := rewriteConfiguration(root, dir, Manifest{Paths: map[string]string{
        "dns.tls_cert_file": "refs/dns-tls-cert.pem",
    }}); err != nil {
        t.Fatal(err)
    }
    b, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
    if err != nil {
        t.Fatal(err)
    }
    if !strings.Contains(string(b), filepath.Join(dir, "data")) || strings.Contains(string(b), "admin_password: old") {
        t.Fatalf("restore did not enforce recovered database location and cleared bootstrap password: %s", b)
    }
}
