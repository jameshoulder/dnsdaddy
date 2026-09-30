package deploy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type composeService struct {
	Command     []string           `yaml:"command"`
	Environment map[string]*string `yaml:"environment"`
	Ports       []string           `yaml:"ports"`
	Volumes     []string           `yaml:"volumes"`
}

func loadCompose(t *testing.T, name string) map[string]composeService {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), name))
	must(t, err)
	var doc struct {
		Services map[string]composeService `yaml:"services"`
	}
	must(t, yaml.Unmarshal(b, &doc))
	return doc.Services
}

func TestComposeOptionalSettingsArePassedWithoutInventingModes(t *testing.T) {
	env := loadCompose(t, "docker-compose.yml")["dnsdaddy"].Environment
	for _, key := range []string{
		"DNSDADDY_UPSTREAMS", "DNSDADDY_UPSTREAM_MODE", "DNSDADDY_CONFIG",
		"DNSDADDY_RESOLUTION_TRANSPORT", "DNSDADDY_ENCRYPTED_UPSTREAMS",
		"DNSDADDY_LOCAL_DNSSEC_VALIDATION", "DNSDADDY_ADMIN_PASSWORD",
		"DNSDADDY_DETECTION_ENABLED", "DNSDADDY_DETECTION_MIN_SEVERITY",
		"DNSDADDY_DETECTION_FINDINGS_FILE", "DNSDADDY_DETECTION_EXCLUDED_DOMAINS",
		"DNSDADDY_DETECTION_RETENTION_DAYS", "DNSDADDY_QUERY_LOG",
		"DNSDADDY_LOG_CLIENT_IP", "DNSDADDY_RETENTION_DAYS",
	} {
		value, present := env[key]
		if !present {
			t.Errorf("%s is not passed to the container; its documented .env setting is ignored", key)
		} else if value != nil {
			t.Errorf("%s has a Compose default %q; omit the value so explicit settings pass through without overwriting YAML or saved choices", key, *value)
		}
	}
}

func TestEncryptedComposeExampleKeepsPublishedPortsAndPersistentData(t *testing.T) {
	base := loadCompose(t, "docker-compose.yml")["dnsdaddy"]
	overlay := loadCompose(t, "deploy/docker-compose.encrypted.yml")["dnsdaddy"]
	if _, pinned := overlay.Environment["DNSDADDY_LOCAL_DNSSEC_VALIDATION"]; pinned {
		t.Error("encrypted starter pins the resolver mode instead of retaining selectable Forward/Learn/Live")
	}
	for key, want := range map[string]string{
		"DNSDADDY_DNS_LISTEN_UDP": ":5353",
		"DNSDADDY_DNS_LISTEN_TCP": ":5353",
		"DNSDADDY_HTTP_LISTEN":    ":8080",
		"DNSDADDY_DATA_DIR":       "/var/lib/dnsdaddy",
	} {
		v := overlay.Environment[key]
		if v == nil || *v != want {
			t.Errorf("overlay %s=%v want %s; the standalone sample must use the container's published listeners and volume", key, v, want)
		}
	}
	if len(overlay.Ports) != 0 {
		t.Error("encrypted example changes published ports instead of retaining the base exposure boundary")
	}
	wantMount := "./dnsdaddy.encrypted.example.yaml:/etc/dnsdaddy/config.yaml:ro"
	if len(overlay.Volumes) != 1 || overlay.Volumes[0] != wantMount {
		t.Fatalf("encrypted config mount=%v, want %s", overlay.Volumes, wantMount)
	}
	contains(t, strings.Join(base.Volumes, "\n"), "dnsdaddy-data:/var/lib/dnsdaddy")
	contains(t, strings.Join(base.Ports, "\n"), "53:5353/udp")
	contains(t, strings.Join(base.Ports, "\n"), "53:5353/tcp")
	if strings.Join(overlay.Command, " ") != "-config /etc/dnsdaddy/config.yaml" {
		t.Fatalf("overlay does not load its mounted example: %v", overlay.Command)
	}
}

// When the Compose CLI is available, resolve the real model without starting
// Docker. This covers both .env interpolation and omission (an empty string
// would overwrite mounted YAML and unintentionally pin a dashboard setting).
func TestComposeResolvesEnvAndLeavesOmittedModesUnset(t *testing.T) {
	var compose []string
	if docker, err := exec.LookPath("docker"); err == nil {
		if exec.Command(docker, "compose", "version").Run() == nil {
			compose = []string{docker, "compose"}
		}
	}
	if len(compose) == 0 {
		if standalone, err := exec.LookPath("docker-compose"); err == nil {
			if exec.Command(standalone, "version").Run() == nil {
				compose = []string{standalone}
			}
		}
	}
	if len(compose) == 0 {
		t.Skip("Docker Compose CLI is not available")
	}
	root := t.TempDir()
	copyFile(t, filepath.Join(repoRoot(t), "docker-compose.yml"), filepath.Join(root, "docker-compose.yml"), 0o644)
	must(t, os.MkdirAll(filepath.Join(root, "deploy"), 0o755))
	copyFile(t, filepath.Join(repoRoot(t), "deploy", "docker-compose.encrypted.yml"), filepath.Join(root, "deploy", "docker-compose.encrypted.yml"), 0o644)
	resolve := func(withEncryptedExample bool) map[string]any {
		t.Helper()
		args := append(append([]string{}, compose[1:]...), "--project-directory", root, "-f", "docker-compose.yml")
		if withEncryptedExample {
			args = append(args, "-f", "deploy/docker-compose.encrypted.yml")
		}
		args = append(args, "config", "--format", "json")
		cmd := exec.Command(compose[0], args...)
		cmd.Dir = root
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "DNSDADDY_") && !strings.HasPrefix(e, "COMPOSE_") {
				cmd.Env = append(cmd.Env, e)
			}
		}
		b, err := cmd.Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				t.Fatalf("compose config: %v\n%s", err, exitErr.Stderr)
			}
			t.Fatalf("compose config: %v", err)
		}
		var model struct {
			Services map[string]struct {
				Environment map[string]any `json:"environment"`
			} `json:"services"`
		}
		must(t, json.Unmarshal(b, &model))
		return model.Services["dnsdaddy"].Environment
	}
	for _, withEncryptedExample := range []bool{false, true} {
		got := resolve(withEncryptedExample)
		for _, key := range []string{"DNSDADDY_RESOLUTION_TRANSPORT", "DNSDADDY_LOCAL_DNSSEC_VALIDATION", "DNSDADDY_ENCRYPTED_UPSTREAMS"} {
			if value := got[key]; value != nil {
				t.Errorf("omitted %s resolves to %#v instead of remaining unset (encrypted overlay=%v)", key, value, withEncryptedExample)
			}
		}
	}
	values := map[string]string{
		"DNSDADDY_UPSTREAMS":               "tls://1.1.1.1:853#cloudflare-dns.com",
		"DNSDADDY_RESOLUTION_TRANSPORT":    "encrypted",
		"DNSDADDY_LOCAL_DNSSEC_VALIDATION": "enforce",
		"DNSDADDY_ENCRYPTED_UPSTREAMS":     `[{"protocol":"doh2","address":"https://cloudflare-dns.com/dns-query","bootstrapIPs":["1.1.1.1"]}]`,
	}
	var file strings.Builder
	for key, value := range values {
		file.WriteString(key + "='" + value + "'\n")
	}
	must(t, os.WriteFile(filepath.Join(root, ".env"), []byte(file.String()), 0o600))
	for _, withEncryptedExample := range []bool{false, true} {
		got := resolve(withEncryptedExample)
		for key, want := range values {
			if got[key] != want {
				t.Errorf(".env %s resolved to %#v, want %q (encrypted overlay=%v)", key, got[key], want, withEncryptedExample)
			}
		}
	}
}
