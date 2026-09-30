package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Exercise only the real installer's configuration phase in a temporary
// directory. Platform changes, service installation and downloads never run.
func TestNativeInstallerUsesTheChosenHTTPBindAndPreservesExistingConfig(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "install.sh"))
	must(t, err)
	script := string(b)
	start := strings.Index(script, "# --- 5. configuration")
	end := strings.Index(script, "# --- 6. systemd unit")
	if start < 0 || end <= start {
		t.Fatal("cannot locate native installer's configuration phase")
	}
	phase := "set -euo pipefail\nlog() { :; }\n" + script[start:end] + "\nprintf 'DISPLAY=%s\\n' \"$HTTP_LISTEN\"\n"
	for _, tc := range []struct {
		name, chosen, existing, want string
		withoutSample                bool
	}{
		{name: "fresh default", want: "127.0.0.1:8080"},
		{name: "fresh explicit LAN", chosen: "192.168.1.50:9090", want: "192.168.1.50:9090"},
		{name: "curl install inherits binary defaults", withoutSample: true, want: "127.0.0.1:8080"},
		{name: "curl install explicit LAN", withoutSample: true, chosen: "192.168.1.50:9090", want: "192.168.1.50:9090"},
		{name: "existing relies on default", existing: "http: {}\n", want: "127.0.0.1:8080"},
		{name: "existing explicit bind", existing: "http:\n  listen: \"192.168.2.5:8080\"\n", chosen: "192.168.1.50:9090", want: "192.168.2.5:8080"},
		{name: "existing custom resolver choices", existing: "dns:\n  upstreams: [\"192.168.1.2\"]\n  local_dnssec_validation: observe\nhttp: {}\n", want: "127.0.0.1:8080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			configDir := filepath.Join(root, "config")
			must(t, os.MkdirAll(configDir, 0o755))
			must(t, os.MkdirAll(filepath.Join(root, "deploy"), 0o755))
			if !tc.withoutSample {
				copyFile(t, filepath.Join(repoRoot(t), "dnsdaddy.example.yaml"), filepath.Join(root, "dnsdaddy.example.yaml"), 0o644)
			}
			path := filepath.Join(configDir, "config.yaml")
			if tc.existing != "" {
				must(t, os.WriteFile(path, []byte(tc.existing), 0o644))
			}
			cmd := exec.Command("bash", "-c", phase)
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "DNSDADDY_") {
					cmd.Env = append(cmd.Env, value)
				}
			}
			cmd.Env = append(cmd.Env, "CONFIG_DIR="+configDir, "SCRIPT_DIR="+filepath.Join(root, "deploy"), "DATA_DIR="+filepath.Join(root, "data"))
			if tc.chosen != "" {
				cmd.Env = append(cmd.Env, "DNSDADDY_HTTP_LISTEN="+tc.chosen)
			}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("configuration phase: %v\n%s", err, out)
			}
			contains(t, string(out), "DISPLAY="+tc.want)
			got, err := os.ReadFile(path)
			must(t, err)
			if tc.existing != "" {
				if string(got) != tc.existing {
					t.Fatalf("existing native configuration was changed:\n%s", got)
				}
				return
			}
			var cfg struct {
				DNS struct {
					Upstreams             []string `yaml:"upstreams"`
					LocalDNSSECValidation string   `yaml:"local_dnssec_validation"`
					ResolutionTransport   string   `yaml:"resolution_transport"`
				} `yaml:"dns"`
				HTTP struct {
					Listen string `yaml:"listen"`
				} `yaml:"http"`
			}
			must(t, yaml.Unmarshal(got, &cfg))
			if cfg.HTTP.Listen != tc.want {
				t.Fatalf("saved listener=%q want=%q", cfg.HTTP.Listen, tc.want)
			}
			if cfg.DNS.LocalDNSSECValidation != "" || cfg.DNS.ResolutionTransport != "" {
				t.Fatalf("new native install locks the dashboard's resolver choices: %+v", cfg.DNS)
			}
			if tc.withoutSample && len(cfg.DNS.Upstreams) != 0 {
				t.Fatalf("curl install duplicates upstream defaults and can drift from the binary: %v", cfg.DNS.Upstreams)
			}
		})
	}
}
