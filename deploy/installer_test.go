// Package deploy holds tests for the shipped installers.
//
// The installer is the first thing anybody runs and the thing most likely to
// be run exactly once, on a machine nobody can reproduce. So it is tested the
// same way the Go code is: by driving the real script, against stubbed system
// commands, and asserting on what it printed and what it wrote.
//
// Nothing here touches the host. Every command the script can invoke —
// docker, ip, ss, systemctl — is replaced by a shim on PATH that records its
// arguments and prints whatever the scenario needs. A stray real `docker
// compose up` from a test run would be a bug in this file, so the shims are
// the whole PATH rather than a prefix on it.
package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// install is one scripted run of the installer.
type install struct {
	t    *testing.T
	root string // temporary copy of the repository
	bin  string // stub commands, and the only PATH entry with them
	env  []string
	// Paths denied to the unprivileged uid, applied after nonRootPrefix's
	// readability sweep. Mode 000 and 0555 deny the owner too, so these hold
	// whether privileges were dropped or were never held — which matters,
	// because on CI the test process is unprivileged and owns the fixture.
	unreadable []string
	unwritable []string
	// Where caddyfileAt pointed the installer, so a test can read back what
	// was actually written rather than asserting only on stdout.
	caddyfile string
}

func newInstall(t *testing.T) *install {
	t.Helper()

	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}

	root := t.TempDir()
	repo := repoRoot(t)

	must(t, os.MkdirAll(filepath.Join(root, "deploy"), 0o755))
	copyFile(t, filepath.Join(repo, "deploy", "install-docker.sh"),
		filepath.Join(root, "deploy", "install-docker.sh"), 0o755)
	copyFile(t, filepath.Join(repo, ".env.example"), filepath.Join(root, ".env.example"), 0o644)
	copyFile(t, filepath.Join(repo, "docker-compose.yml"), filepath.Join(root, "docker-compose.yml"), 0o644)

	// The stub log is created up front, and writable, so that a run which
	// records nothing and a run which records a lot differ only in its
	// contents — never in whether the fixture gained a file. It is harness
	// scaffolding that happens to live inside the tree, which is why the
	// dry-run snapshot below excludes it by name.
	must(t, os.WriteFile(filepath.Join(root, "compose.log"), nil, 0o666))

	in := &install{t: t, root: root, bin: filepath.Join(root, "stubbin")}
	must(t, os.MkdirAll(in.bin, 0o755))
	in.writeDefaultStubs()
	return in
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(wd) // this package lives in deploy/
}

// stub writes an executable shim. The body is bash.
func (in *install) stub(name, body string) {
	in.t.Helper()
	path := filepath.Join(in.bin, name)
	if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\n"+body+"\n"), 0o755); err != nil {
		in.t.Fatalf("write stub %s: %v", name, err)
	}
}

// writeDefaultStubs describes a healthy machine: Docker installed and running,
// one private address, nothing on port 53, and a service that comes up.
func (in *install) writeDefaultStubs() {
	in.stub("docker", `
case "$1 $2" in
  "--version ")        echo "Docker version 27.1.1, build abc" ;;
  "compose version")   [[ "${3:-}" == "--short" ]] && echo "2.29.1" || echo "Docker Compose version v2.29.1" ;;
  "info ")             exit "${STUB_DOCKER_INFO_EXIT:-0}" ;;
  "inspect --format")  echo "sha256:${STUB_PREVIOUS_IMAGE:-0000000000000000000000000000000000000000000000000000000000000000}" ;;
  *) ;;
esac
if [[ "$1" == "compose" ]]; then
  printf '%s\n' "$*" >> "$STUB_LOG"
  case "$2" in
    ps)   [[ "${STUB_STACK_RUNNING:-0}" == "1" ]] && echo "abc123def456"; exit 0 ;;
    up)   exit "${STUB_COMPOSE_UP_EXIT:-0}" ;;
    down) exit "${STUB_COMPOSE_DOWN_EXIT:-0}" ;;
    exec)
      # docker compose exec -T dnsdaddy <cmd> [args...]
      shift 4
      case "${1:-}" in
        wget)
          [[ "${STUB_HEALTHY:-1}" == "1" ]] || exit 1
          printf '{"status":"ok"}\n'
          
          ;;
        cat)
          [[ -n "${STUB_ADMIN_PASSWORD:-}" ]] || exit 1
          printf 'DNS Daddy initial admin password: %s\n' "$STUB_ADMIN_PASSWORD"
          ;;
        dnsdaddy)
          printf 'DNS Daddy doctor — test\n'
          exit "${STUB_DOCTOR_EXIT:-0}"
          ;;
      esac
      ;;
  esac
fi
exit 0`)

	in.stub("ip", `
if [[ "$*" == *"route get"* ]]; then
  echo "1.1.1.1 via 192.168.1.1 dev ${STUB_IFACE:-eth0} src ${STUB_PRIMARY_IP:-192.168.1.75} uid 0"
  exit 0
fi
if [[ "$*" == *"addr show"* ]]; then
  # The family flag matters. Answering the same list for -4 and -6 made
  # host_addresses6 report IPv4 addresses as this machine's IPv6 ones, which
  # silently turned the AAAA check into a comparison that could never match.
  # A host with no IPv6 stack is the default here, because that is the common
  # case and the one the check has to handle correctly.
  if [[ "$*" == *" -6"* || "$*" == "-6 "* ]]; then
    for a6 in ${STUB_IPV6_ADDRS:-}; do
      echo "4: ${STUB_IFACE:-eth0}    inet6 ${a6}/64 scope global"
    done
    exit 0
  fi
  echo "2: ${STUB_IFACE:-eth0}    inet ${STUB_PRIMARY_IP:-192.168.1.75}/24 scope global"
  for extra in ${STUB_EXTRA_IPS:-}; do
    echo "3: eth1    inet ${extra}/24 scope global"
  done
  exit 0
fi
exit 0`)

	// Nothing listening. A scenario that wants a busy port overrides this.
	in.stub("ss", `exit 0`)

	// Caddy. The default version is the real current release, because the
	// IP-address path is gated on 2.11+ — that is the first Caddy whose
	// CertMagic knows Let's Encrypt issues IP certificates.
	//
	// STUB_CADDY_VERSION drives the version gate; STUB_CADDY_VALIDATE_EXIT
	// rejects the generated config, which is how the parse-error path is
	// reached without needing an old Caddy binary.
	in.stub("caddy", `
case "${1:-}" in
  version)  echo "${STUB_CADDY_VERSION:-v2.11.4 h1:stub}" ;;
  validate) printf '%s\n' "${STUB_CADDY_VALIDATE_MSG:-}"; exit "${STUB_CADDY_VALIDATE_EXIT:-0}" ;;
esac
exit 0`)

	// curl, which is how the installer decides whether HTTPS actually works.
	//
	//   STUB_CURL_STRICT_EXIT  a request with the system trust store
	//   STUB_CURL_LAX_EXIT     the same request with -k
	//
	// The pair is the whole point: strict failing while lax succeeds is a
	// certificate the machine does not trust, which is what Caddy's internal
	// CA looks like from here. Both default to failure, because an installer
	// that reports HTTPS working when nothing answered is the bug.
	// The stub distinguishes what a real curl would, because the installer now
	// asks it several different questions and treating them as one made the
	// posture checks meaningless: a stub that succeeds for every URL "proves"
	// the backend is exposed on 8080 in a test where nothing is listening at
	// all.
	//
	//   STUB_CURL_STRICT_EXIT   HTTPS with the system trust store
	//   STUB_CURL_LAX_EXIT      the same request with -k
	//   STUB_CURL_8080_EXIT     the public :8080 probe. Defaults to failure,
	//                           which is the correct posture: the backend is
	//                           on loopback and must not answer from outside.
	//   STUB_CURL_HTTP_CODE     what plain HTTP returns, for the redirect check
	//   STUB_CURL_HEALTH_BODY   what the health endpoint returns through Caddy
	in.stub("curl", `
lax=0; want_code=0; url=""
for a in "$@"; do
  case "$a" in
    -*k*)          lax=1 ;;
    '%{http_code}') want_code=1 ;;
    http://*|https://*) url="$a" ;;
  esac
done
case "$url" in
  *:8080*) exit "${STUB_CURL_8080_EXIT:-1}" ;;
esac
if [[ $want_code -eq 1 ]]; then
  printf '%s' "${STUB_CURL_HTTP_CODE:-301}"
  exit 0
fi
if [[ $lax -eq 1 ]]; then exit "${STUB_CURL_LAX_EXIT:-1}"; fi
if [[ "${STUB_CURL_STRICT_EXIT:-1}" != "0" ]]; then exit "${STUB_CURL_STRICT_EXIT:-1}"; fi
case "$url" in
  */api/v1/health) printf '%s' "${STUB_CURL_HEALTH_BODY:-{\"status\":\"ok\"}}" ;;
esac
exit 0`)

	// Installing Caddy must not reach the network from a test.
	in.stub("apt-get", `exit "${STUB_APT_EXIT:-1}"`)
	in.stub("gpg", `exit 0`)
	// getent, which is how the installer learns what a hostname resolves to.
	// Both families, because the check looks at A and AAAA separately and a
	// stub that only modelled one would let the other go untested.
	//
	//   STUB_GETENT_V4  addresses to return for ahostsv4, space separated
	//   STUB_GETENT_V6  addresses to return for ahostsv6
	//   STUB_GETENT_EXIT  exit status when neither is set (default: not found)
	in.stub("getent", `
case "${1:-}" in
  ahostsv4)
    [[ -n "${STUB_GETENT_V4:-}" ]] || exit "${STUB_GETENT_EXIT:-2}"
    for a in ${STUB_GETENT_V4}; do printf '%s STREAM %s\n' "$a" "${2:-}"; done
    exit 0 ;;
  ahostsv6)
    [[ -n "${STUB_GETENT_V6:-}" ]] || exit "${STUB_GETENT_EXIT:-2}"
    for a in ${STUB_GETENT_V6}; do printf '%s STREAM %s\n' "$a" "${2:-}"; done
    exit 0 ;;
esac
exit "${STUB_GETENT_EXIT:-2}"`)

	in.stub("systemctl", `
case "$*" in
  *"list-unit-files docker.service"*) exit "${STUB_DOCKER_UNIT_EXIT:-0}" ;;
  *"is-active"*)                      exit "${STUB_SYSTEMCTL_ACTIVE_EXIT:-0}" ;;
esac
exit 0`)

	// The script's own dependencies, taken from the real system so the shims
	// do not have to reimplement coreutils.
	for _, name := range []string{
		"bash", "sh", "sed", "grep", "awk", "cut", "tr", "head", "tail", "sort",
		"paste", "cp", "cat", "uname", "hostname", "sleep", "rm", "mkdir",
		"dirname", "basename", "pwd", "seq", "env", "id", "expr", "wc", "ls", "stat",
		"date", "chmod", "chown", "touch", "mv", "find", "readlink", "printf", "test",
	} {
		if path, err := exec.LookPath(name); err == nil {
			_ = os.Symlink(path, filepath.Join(in.bin, name))
		}
	}
}

func (in *install) setenv(kv ...string) { in.env = append(in.env, kv...) }

// run executes the installer and returns its combined output and exit code.
func (in *install) run(args ...string) (string, int) {
	in.t.Helper()
	return in.runWith(nil, args...)
}

// runAsNonRoot runs the installer as an unprivileged uid, which is the only way
// to make a write into the repository directory actually fail: as root it
// succeeds whatever the mode bits say. ok is false when that uid is out of
// reach (root, and no setpriv).
func (in *install) runAsNonRoot(args ...string) (out string, code int, ok bool) {
	in.t.Helper()
	prefix, ok := nonRootPrefix(in.t, in.root)
	if !ok {
		return "", 0, false
	}
	// After the sweep, never before it: nonRootPrefix makes the whole fixture
	// readable and writable, which would undo these.
	for _, path := range in.unreadable {
		path := path
		in.t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
		must(in.t, os.Chmod(path, 0))
	}
	for _, path := range in.unwritable {
		path := path
		in.t.Cleanup(func() { _ = os.Chmod(path, 0o755) })
		must(in.t, os.Chmod(path, 0o555))
	}
	out, code = in.runWith(prefix, args...)
	return out, code, true
}

func (in *install) denyRead(path string)  { in.unreadable = append(in.unreadable, path) }
func (in *install) denyWrite(path string) { in.unwritable = append(in.unwritable, path) }

func (in *install) envPath() string { return filepath.Join(in.root, ".env") }

func (in *install) runWith(prefix []string, args ...string) (string, int) {
	in.t.Helper()

	argv := append(append([]string{}, prefix...),
		"bash", filepath.Join(in.root, "deploy", "install-docker.sh"))
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Args = append(cmd.Args, args...)
	cmd.Dir = in.root
	cmd.Env = append([]string{
		"PATH=" + in.bin,
		"HOME=" + in.root,
		"STUB_LOG=" + filepath.Join(in.root, "compose.log"),
		"TERM=dumb",
		// The real default is two minutes, which is right for a cold start on
		// a single vCPU and wrong for a test asserting on the failure path.
		"DNSDADDY_INSTALL_HEALTH_TIMEOUT=4",
	}, in.env...)

	out, err := cmd.CombinedOutput()
	code := 0
	var exitErr *exec.ExitError
	if err != nil {
		if ok := asExitError(err, &exitErr); ok {
			code = exitErr.ExitCode()
		} else {
			in.t.Fatalf("run installer: %v\n%s", err, out)
		}
	}
	return string(out), code
}

func asExitError(err error, dst **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*dst = e
		return true
	}
	return false
}

func (in *install) writeEnv(content string) {
	in.t.Helper()
	must(in.t, os.WriteFile(filepath.Join(in.root, ".env"), []byte(content), 0o644))
}

func (in *install) readEnv() string {
	in.t.Helper()
	b, err := os.ReadFile(filepath.Join(in.root, ".env"))
	if err != nil {
		in.t.Fatalf("read .env: %v", err)
	}
	return string(b)
}

func (in *install) envExists() bool {
	_, err := os.Stat(filepath.Join(in.root, ".env"))
	return err == nil
}

func (in *install) composeLog() string {
	b, _ := os.ReadFile(filepath.Join(in.root, "compose.log"))
	return string(b)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, from, to string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatalf("read %s: %v", from, err)
	}
	if err := os.WriteFile(to, b, mode); err != nil {
		t.Fatalf("write %s: %v", to, err)
	}
}

func contains(t *testing.T, out, want string) {
	t.Helper()
	if !strings.Contains(out, want) {
		t.Errorf("output does not contain %q:\n%s", want, out)
	}
}

func notContains(t *testing.T, out, unwanted string) {
	t.Helper()
	if strings.Contains(out, unwanted) {
		t.Errorf("output unexpectedly contains %q:\n%s", unwanted, out)
	}
}

// --- .env handling -----------------------------------------------------------

// Nobody should have to run `cp .env.example .env` before they can install
// something. That step existed only because the installer would not do it.
func TestCreatesEnvWhenAbsent(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !in.envExists() {
		t.Fatal(".env was not created")
	}
	contains(t, out, "Created .env")
}

// An existing .env is the operator's file. Settings the installer does not own
// must survive untouched.
func TestPreservesExistingEnv(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")
	in.writeEnv("# my notes\nDNSDADDY_UPSTREAMS=tls://9.9.9.9:853#dns.quad9.net\nTZ=Europe/London\n")

	out, code := in.run("--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	got := in.readEnv()
	for _, want := range []string{"# my notes", "DNSDADDY_UPSTREAMS=tls://9.9.9.9:853#dns.quad9.net", "TZ=Europe/London"} {
		if !strings.Contains(got, want) {
			t.Errorf(".env lost %q:\n%s", want, got)
		}
	}
	contains(t, out, "Keeping your existing .env")
}

// --- Docker detection --------------------------------------------------------

func TestDockerMissingGivesTheExactCommand(t *testing.T) {
	in := newInstall(t)
	must(t, os.Remove(filepath.Join(in.bin, "docker")))

	out, code := in.run("--yes")
	if code == 0 {
		t.Fatal("the installer continued without Docker")
	}
	contains(t, out, "Docker is not installed")
	contains(t, out, "get.docker.com")
	notContains(t, out, "Docker failed")
}

func TestDaemonDownNamesTheServiceToStart(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_DOCKER_INFO_EXIT=1", "STUB_SYSTEMCTL_ACTIVE_EXIT=3")

	out, code := in.run("--yes")
	if code == 0 {
		t.Fatal("the installer continued with no Docker daemon")
	}
	contains(t, out, "The Docker daemon is not running")
	contains(t, out, "systemctl enable --now docker")
}

// A daemon that is running but unreachable is a permissions problem, not a
// stopped service, and telling somebody to start a service that is already
// started wastes their time.
func TestUnreachableDaemonSuggestsTheDockerGroup(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_DOCKER_INFO_EXIT=1", "STUB_SYSTEMCTL_ACTIVE_EXIT=0")

	out, code := in.run("--yes")
	if code == 0 {
		t.Fatal("the installer continued with an unreachable daemon")
	}
	contains(t, out, "usermod -aG docker")
}

// --- ports -------------------------------------------------------------------

func TestPortFiftyThreeBusyNamesTheOwnerAndTheRemedy(t *testing.T) {
	in := newInstall(t)
	in.stub("ss", `echo 'UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolved",pid=1,fd=1))'`)

	out, code := in.run("--yes")
	if code == 0 {
		t.Fatal("the installer continued with port 53 taken")
	}
	contains(t, out, "port 53 is already in use")
	contains(t, out, "systemd-resolved")
	contains(t, out, "DNSStubListener=no")
	// It must not do it for them: this changes how the machine resolves names.
	contains(t, out, "will NOT change that for you")
}

// Another resolver is a different conversation from systemd-resolved's stub.
func TestPiHoleOnPortFiftyThreeSuggestsCoexistence(t *testing.T) {
	in := newInstall(t)
	in.stub("ss", `echo 'LISTEN 0 0 0.0.0.0:53 0.0.0.0:* users:(("pihole-FTL",pid=9,fd=4))'`)

	out, _ := in.run("--yes")
	contains(t, out, "Pi-hole")
	contains(t, out, "docs/pi-hole.md")
}

// ss sees the socket but cannot name the process without privilege. Reporting
// the port as free there would send the operator into a bind failure.
func TestUnnamedListenerIsStillReportedAsInUse(t *testing.T) {
	in := newInstall(t)
	in.stub("ss", `echo 'LISTEN 0 0 0.0.0.0:53 0.0.0.0:*'`)

	out, code := in.run("--yes")
	if code == 0 {
		t.Fatal("an unnamed listener on port 53 was treated as a free port")
	}
	contains(t, out, "run with sudo to name the process")
}

// The dashboard port being taken is a warning, not a stop: DNS still works.
func TestDashboardPortBusyIsAWarningNotAFailure(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")
	in.stub("ss", `
if [[ "$*" == *"-t"* ]]; then
  echo 'LISTEN 0 0 0.0.0.0:8080 0.0.0.0:* users:(("caddy",pid=7,fd=3))'
fi
exit 0`)

	out, code := in.run("--yes")
	if code != 0 {
		t.Fatalf("a busy dashboard port stopped the install: exit %d\n%s", code, out)
	}
	contains(t, out, "port 8080 is in use")
}

// --- deployment mode ---------------------------------------------------------

// The conservative default, and the reason it is conservative: a private
// address on the NIC is not evidence that a host has no public address.
func TestNonInteractiveDefaultsToLoopback(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "Dashboard stays on 127.0.0.1:8080")
	if strings.Contains(in.readEnv(), "\nDNSDADDY_DASHBOARD_BIND=") {
		t.Errorf("--yes published the dashboard on an address:\n%s", in.readEnv())
	}
	contains(t, out, "ssh -L 8080:127.0.0.1:8080")
}

// Choosing LAN explicitly publishes on that address and nowhere else.
//
// --lan rather than a menu answer, and that is the point: it is never
// inferred. An operator has to say it, in a flag or at a prompt, because
// nothing visible from inside the machine distinguishes a homelab box from a
// cloud instance with a public address NATed onto a private NIC.
func TestLANModePublishesOnTheHostAddress(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--lan", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "http://192.168.1.75:8080")
	if !strings.Contains(in.readEnv(), "DNSDADDY_DASHBOARD_BIND=192.168.1.75") {
		t.Errorf(".env does not publish the dashboard on the LAN address:\n%s", in.readEnv())
	}
	// And it must never be the wildcard: Docker's port publishing bypasses
	// ufw, so a firewall rule would not contain it.
	notContains(t, in.readEnv(), "DNSDADDY_DASHBOARD_BIND=0.0.0.0")
}

// The rule that a real security issue came from: a public address on the NIC
// must never be published, whatever the operator asks for.
func TestLANModeRefusesAPublicAddress(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_PRIMARY_IP=203.0.113.20", "STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--lan", "--yes")
	if code == 0 {
		t.Fatal("--lan published the dashboard on a public address")
	}
	contains(t, out, "Refusing to publish the dashboard on a public address")
	if in.envExists() && strings.Contains(in.readEnv(), "DNSDADDY_DASHBOARD_BIND=203.0.113.20") {
		t.Error("a public address was written to .env")
	}
}

// --yes on its own must never publish anything. Automation gets the closed
// answer unless it says otherwise in so many words.
func TestYesAloneNeverPublishesTheDashboard(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_PRIMARY_IP=10.0.0.5", "STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.Contains(in.readEnv(), "\nDNSDADDY_DASHBOARD_BIND=") {
		t.Errorf("--yes published the dashboard on a private address it merely detected:\n%s", in.readEnv())
	}
}

// Several addresses is the normal case on a homelab box, and picking the first
// thing `hostname -I` printed is how the dashboard ends up on the wrong VLAN.
func TestMultipleAddressesAreReported(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_EXTRA_IPS=10.8.0.4 172.20.0.9", "STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "10.8.0.4")
	contains(t, out, "172.20.0.9")
	contains(t, out, "Use the one your clients can reach")
}

// --- readiness and the closing report ----------------------------------------

func TestWaitsForHealthThenRunsDoctor(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "DNS Daddy is responding")
	contains(t, out, "DNS Daddy doctor")
	if !strings.Contains(in.composeLog(), "compose up -d") {
		t.Errorf("the stack was never started; compose log:\n%s", in.composeLog())
	}
}

// "container started" and then exiting is the behaviour this replaces: a
// container that starts and dies looks identical for the first few seconds.
func TestFailedHealthCheckIsReportedAndExitsNonZero(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_HEALTHY=0")

	out, code := in.run("--yes")
	if code == 0 {
		t.Fatal("a service that never became ready exited 0")
	}
	contains(t, out, "did not become ready")
	contains(t, out, "docker compose logs")
}

// The old answer was `docker compose logs | grep password`, which is poor UX
// and means a credential in the log for the life of the container.
func TestAdminPasswordIsPrintedFromTheDataVolume(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=hunter2-but-longer-and-random")

	out, code := in.run("--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "hunter2-but-longer-and-random")
	notContains(t, out, "logs dnsdaddy | grep")
}

// On an upgrade no password is generated, and claiming one was would be worse
// than saying nothing.
func TestNoPasswordIsInventedWhenNoneWasGenerated(t *testing.T) {
	in := newInstall(t)

	out, code := in.run("--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "Already set")
}

// A test command that is guaranteed to be answered REFUSED is worse than no
// test command: it sends the operator to debug a network fault that does not
// exist. On a VPS the shipped ACL covers loopback and the private ranges only,
// so that is exactly what `nslookup` from a public client would get.
func TestVPSInstallGivesTheDashboardStepNotAFailingTest(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--vps", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "No external clients are permitted yet")
	contains(t, out, "Allow this network to use DNS Daddy")
	contains(t, out, "nothing to restart")
	// And it must not present the refusal as a fault.
	contains(t, out, "that is DNS Daddy working")
}

// On a LAN the shipped ACL already covers the client, so the test works and
// the operator should be given it.
func TestLANInstallGivesTheExactTestCommand(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--lan", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "nslookup example.com 192.168.1.75")
	contains(t, out, "dig @192.168.1.75 example.com")
	notContains(t, out, "No external clients are permitted yet")
}

// Over SSH the kernel knows where the operator connected from, which is the
// one address on this machine that honestly answers "which public address
// should I allow?" — a NATed cloud NIC does not know its own.
func TestSSHClientAddressIsOfferedOnAVPSInstall(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234", "SSH_CLIENT=203.0.113.77 51234 22")

	out, code := in.run("--vps", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "203.0.113.77")
	contains(t, out, "as this machine sees it")
}

// It must not be printed when there is no reliable source for it — guessing
// from a local interface address is the inference that caused a real problem.
func TestNoClientAddressIsInventedWithoutSSH(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--vps", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	notContains(t, out, "That is where this SSH session")
}

func TestSummaryIsPrintedAtTheEnd(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	summary := out[strings.LastIndex(out, "Summary"):]
	for _, want := range []string{"PASS", "Docker daemon is running", "DNS Daddy is responding"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary is missing %q:\n%s", want, summary)
		}
	}
}

// --- upgrade -----------------------------------------------------------------

func TestUpgradePreservesEnvAndRebuilds(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("TZ=Europe/London\nDNSDADDY_UPSTREAMS=tls://1.1.1.1:853#cloudflare-dns.com\n")

	out, code := in.run("--upgrade", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "Keeping your existing .env")
	contains(t, in.readEnv(), "TZ=Europe/London")
	if !strings.Contains(in.composeLog(), "--build") {
		t.Errorf("upgrade did not rebuild; compose log:\n%s", in.composeLog())
	}
	// Nothing may delete the volume.
	if strings.Contains(in.composeLog(), "down -v") {
		t.Errorf("upgrade removed the data volume:\n%s", in.composeLog())
	}
}

// An address the operator set by hand is a deliberate choice, and an upgrade
// is not the moment to overrule it.
func TestUpgradePreservesAHandSetDashboardBind(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("DNSDADDY_DASHBOARD_BIND=192.168.1.75\n")

	out, code := in.run("--upgrade", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "left as-is")
	contains(t, in.readEnv(), "DNSDADDY_DASHBOARD_BIND=192.168.1.75")
}

// But a value this installer generated is not a choice the operator made. An
// earlier version inferred "private NIC means private host" and could publish
// a management API on a public address; upgrading past it has to close that.
func TestUpgradeClosesAPublicBindThisInstallerGenerated(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("# managed by install-docker.sh\nDNSDADDY_DASHBOARD_BIND=203.0.113.20\n")

	out, code := in.run("--upgrade", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "public address")
	contains(t, out, "returns to loopback")
	if strings.Contains(in.readEnv(), "\nDNSDADDY_DASHBOARD_BIND=203.0.113.20") {
		t.Errorf("the public bind is still active:\n%s", in.readEnv())
	}
	contains(t, out, "change the admin password")
}

// A private bind this installer wrote is exactly what it was asked to write,
// so an upgrade leaves it alone.
func TestUpgradeKeepsAManagedPrivateBind(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("# managed by install-docker.sh\nDNSDADDY_DASHBOARD_BIND=192.168.1.75\n")

	out, code := in.run("--upgrade", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "stays published on 192.168.1.75:8080")
	contains(t, in.readEnv(), "DNSDADDY_DASHBOARD_BIND=192.168.1.75")
}

// A failed upgrade has to say what to go back to, and must not have destroyed
// anything on the way.
func TestFailedUpgradeReportsTheRecoveryPath(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_HEALTHY=0", "STUB_PREVIOUS_IMAGE=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	in.writeEnv("TZ=UTC\n")

	out, code := in.run("--upgrade", "--yes")
	if code == 0 {
		t.Fatal("a failed upgrade exited 0")
	}
	contains(t, out, "did not come up healthy")
	contains(t, out, "Your data is untouched")
	contains(t, out, "deadbeef")
	contains(t, in.readEnv(), "TZ=UTC")
}

// --- uninstall ---------------------------------------------------------------

func TestUninstallKeepsDataByDefault(t *testing.T) {
	in := newInstall(t)

	out, code := in.run("--uninstall")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "Your data is kept")
	if strings.Contains(in.composeLog(), "down -v") {
		t.Errorf("uninstall deleted the volume without being asked:\n%s", in.composeLog())
	}
}

// Destroying a year of query history must not be one tab-completion away, and
// must never happen unattended.
func TestPurgeRefusesWithoutAnInteractiveConfirmation(t *testing.T) {
	in := newInstall(t)

	out, code := in.run("--uninstall", "--purge", "--yes")
	if code == 0 {
		t.Fatal("--purge --yes deleted data without a confirmation")
	}
	contains(t, out, "Refusing to delete data")
	if strings.Contains(in.composeLog(), "down -v") {
		t.Errorf("the volume was removed anyway:\n%s", in.composeLog())
	}
}

// --- dry run -----------------------------------------------------------------

// A dry run has to be safe to point at a production box, so it must not start,
// stop or write anything.
func TestDryRunChangesNothing(t *testing.T) {
	in := newInstall(t)

	out, code := in.run("--dry-run")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "Dry run complete. Nothing was changed.")
	if in.envExists() {
		t.Error("--dry-run created .env")
	}
	if log := in.composeLog(); strings.Contains(log, "up") || strings.Contains(log, "down") {
		t.Errorf("--dry-run ran compose:\n%s", log)
	}
}

func TestDryRunWorksWithoutADaemon(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_DOCKER_INFO_EXIT=1")

	out, code := in.run("--dry-run")
	if code != 0 {
		t.Fatalf("--dry-run needs a running daemon: exit %d\n%s", code, out)
	}
	contains(t, out, "ignored for --dry-run")
}

func TestDryRunReportsAnExistingPublishedDashboard(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("DNSDADDY_DASHBOARD_BIND=192.168.1.75\n")

	out, code := in.run("--dry-run")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "comment out DNSDADDY_DASHBOARD_BIND")
	contains(t, in.readEnv(), "DNSDADDY_DASHBOARD_BIND=192.168.1.75")
}

// --- misc --------------------------------------------------------------------

func TestUnknownOptionIsRejected(t *testing.T) {
	in := newInstall(t)
	out, code := in.run("--wat")
	if code != 2 {
		t.Errorf("exit %d, want 2\n%s", code, out)
	}
}

func TestHelpDescribesEveryMode(t *testing.T) {
	in := newInstall(t)
	out, code := in.run("--help")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{"--upgrade", "--uninstall", "--dry-run", "--yes"} {
		contains(t, out, want)
	}
}

// --- Codex review regressions -------------------------------------------------

// With Docker's userland proxy — the default on a great many installs — the
// published port 53 is held by `docker-proxy`, not by anything called
// dnsdaddy. Matching on the socket's process name made --upgrade refuse to run
// on its most common deployment, which is to say: unusable.
func TestUpgradeProceedsWhenDockerProxyHoldsPortFiftyThree(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_STACK_RUNNING=1", "STUB_ADMIN_PASSWORD=test-password-1234")
	in.stub("ss", `echo 'LISTEN 0 0 0.0.0.0:53 0.0.0.0:* users:(("docker-proxy",pid=9,fd=4))'`)
	in.writeEnv("TZ=UTC\n")

	out, code := in.run("--upgrade", "--yes")
	if code != 0 {
		t.Fatalf("--upgrade refused to run behind docker-proxy: exit %d\n%s", code, out)
	}
	contains(t, out, "held by this DNS Daddy deployment")
	if !strings.Contains(in.composeLog(), "--build") {
		t.Errorf("the upgrade never rebuilt; compose log:\n%s", in.composeLog())
	}
}

// The exemption is for upgrades of a running stack, and nothing else. A fresh
// install with something on port 53 must still stop.
func TestFreshInstallStillStopsWhenDockerHoldsPortFiftyThree(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_STACK_RUNNING=1")
	in.stub("ss", `echo 'LISTEN 0 0 0.0.0.0:53 0.0.0.0:* users:(("docker-proxy",pid=9,fd=4))'`)

	out, code := in.run("--yes")
	if code == 0 {
		t.Fatal("a fresh install carried on into a bind failure")
	}
	contains(t, out, "port 53 is already in use")
	contains(t, out, "docker ps --filter publish=53")
}

// Nor when the stack is not actually running: --upgrade must not wave through
// a port held by an unrelated resolver.
func TestUpgradeStillStopsWhenTheStackIsNotRunning(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_STACK_RUNNING=0")
	in.stub("ss", `echo 'UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolved",pid=1,fd=1))'`)

	out, code := in.run("--upgrade", "--yes")
	if code == 0 {
		t.Fatal("--upgrade ignored a port held by systemd-resolved")
	}
	contains(t, out, "port 53 is already in use")
}

// An older managed assignment followed by a hand-set override: env_value takes
// the last one, so env_is_managed has to as well. Getting that wrong meant an
// upgrade commented out every active assignment and silently closed a
// dashboard address the operator had opened on purpose.
func TestHandSetOverrideAfterAManagedLineIsNotTreatedAsManaged(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("# managed by install-docker.sh\n" +
		"DNSDADDY_DASHBOARD_BIND=192.168.1.10\n" +
		"DNSDADDY_DASHBOARD_BIND=203.0.113.20\n")

	out, code := in.run("--upgrade", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "left alone")
	if !strings.Contains(in.readEnv(), "\nDNSDADDY_DASHBOARD_BIND=203.0.113.20") {
		t.Errorf("the operator's own override was commented out:\n%s", in.readEnv())
	}
}

// And the mirror image still works: when the last assignment IS the managed
// one, an upgrade may still close a public address it generated.
func TestManagedLineAfterAHandSetOneIsStillReconciled(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("DNSDADDY_DASHBOARD_BIND=192.168.1.10\n" +
		"# managed by install-docker.sh\n" +
		"DNSDADDY_DASHBOARD_BIND=203.0.113.20\n")

	out, code := in.run("--upgrade", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "returns to loopback")
	if strings.Contains(in.readEnv(), "\nDNSDADDY_DASHBOARD_BIND=203.0.113.20") {
		t.Errorf("a public bind this installer generated is still active:\n%s", in.readEnv())
	}
}

// "Your LAN is already permitted" is a claim about the effective ACL, and it
// is only true of the shipped one. An operator who has set
// DNSDADDY_ALLOWED_CLIENT_CIDRS is permitted whatever that lists, and this
// installer preserves an existing .env rather than overwriting it — so the
// deployment choice says nothing about what is actually admitted, and telling
// them their LAN works could hand them a test command that answers REFUSED.
func TestLANInstallDoesNotClaimTheLANIsPermittedWhenTheACLIsSet(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")
	in.writeEnv("DNSDADDY_ALLOWED_CLIENT_CIDRS=203.0.113.0/24\n")

	out, code := in.run("--lan", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	notContains(t, out, "Your LAN is already permitted")
	contains(t, out, "CLIENT ACCESS above shows it")

	// The test command is still given: the operator may well be in that list,
	// and withholding it would trade one unmeasured claim for a dead end.
	contains(t, out, "nslookup example.com 192.168.1.75")
}

// The installer invites a VPS operator to consider DNSDADDY_ALLOWED_CLIENT_CIDRS
// and used to say only that "the two combine". True, and it omits the half that
// matters: a range in the bootstrap list is permitted whatever the dashboard
// says, so unticking the box cannot withdraw it. That is the same one-way door
// production-deploy.sh was walking operators through automatically, offered
// here for them to walk through by hand.
func TestVPSInstallSaysABootstrapRangeCannotBeRevokedFromTheDashboard(t *testing.T) {
	in := newInstall(t)
	in.setenv("STUB_ADMIN_PASSWORD=test-password-1234")

	out, code := in.run("--vps", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "DNSDADDY_ALLOWED_CLIENT_CIDRS")
	contains(t, out, "cannot withdraw it")
	contains(t, out, "add it as a Network and leave it out of .env")
}

// Closing a dashboard this installer published on a public address is the one
// thing this branch exists to do. If the edit cannot be made — a read-only
// repository directory, most plainly — the upgrade must not carry on: compose
// would read the unchanged file and republish the very address the run just
// promised to close. env_disable returning "nothing to disable" and "could not
// disable" as the same status is what made that possible.
//
// Only an unprivileged uid can demonstrate it: root's writes succeed whatever
// the mode bits say, which is precisely why this went unnoticed.
func TestUpgradeAbortsWhenItCannotCloseAPublicBind(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("# managed by install-docker.sh\nDNSDADDY_DASHBOARD_BIND=203.0.113.20\n")
	// sed -i rewrites .env by creating a sibling and renaming, so it is the
	// directory that has to refuse the write. Appending to the already-created
	// stub log does not need that permission, so the stubs still work.
	in.denyWrite(in.root)

	out, code, ok := in.runAsNonRoot("--upgrade", "--yes")
	if !ok {
		t.Skip("cannot reach an unprivileged uid: test process is root and setpriv is missing")
	}
	if code == 0 {
		t.Fatalf("upgrade succeeded without closing the published dashboard\n%s", out)
	}
	contains(t, out, "Could not close the published dashboard")
	notContains(t, out, "returns to loopback")
	// And it did not lie about the state it left behind.
	contains(t, in.readEnv(), "DNSDADDY_DASHBOARD_BIND=203.0.113.20")
}

// A .env that cannot be read is not a .env that says nothing. Read through
// grep's "could not open" as though it were "no match", and an unprivileged
// upgrade reports the dashboard safely on loopback while the file it never
// managed to open publishes it to the internet — a false all-clear about the
// one exposure this installer takes most seriously.
func TestUpgradeRefusesToGuessAtAnUnreadableEnv(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("# managed by install-docker.sh\nDNSDADDY_DASHBOARD_BIND=203.0.113.20\n")
	in.denyRead(in.envPath())

	out, code, ok := in.runAsNonRoot("--upgrade", "--yes", "--dry-run")
	if !ok {
		t.Skip("cannot reach an unprivileged uid: test process is root and setpriv is missing")
	}
	if code == 0 {
		t.Fatalf("upgrade reported success over a .env it could not read\n%s", out)
	}
	contains(t, out, "Could not read")
	notContains(t, out, "loopback")
}

// The upgrade path is not the only one that closes a published dashboard: a
// fresh install reusing an existing .env does it too, in reconcile_env. Both
// callers have to treat "could not disable" as a failure, or the installer
// reports the dashboard back on loopback and hands compose the unchanged bind
// — publishing it while saying it did not.
func TestFreshInstallAbortsWhenItCannotCloseAPublishedBind(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("DNSDADDY_DASHBOARD_BIND=203.0.113.20\n")
	in.denyWrite(in.root)

	out, code, ok := in.runAsNonRoot("--yes")
	if !ok {
		t.Skip("cannot reach an unprivileged uid: test process is root and setpriv is missing")
	}
	if code == 0 {
		t.Fatalf("fresh install succeeded without closing the published dashboard\n%s", out)
	}
	notContains(t, out, "returns to loopback")
	notContains(t, in.composeLog(), "up -d")
}

// The installer makes the same promise its sibling does — "Dry run complete.
// Nothing was changed." — and TestDryRunChangesNothing checks two specific
// ways it could be broken: .env appearing, and compose running. Those are the
// two that were thought of. This asserts the promise itself over the whole
// fixture, so a third way fails a test rather than waiting to be noticed.
func TestDryRunChangesNothingOnDisk(t *testing.T) {
	in := newInstall(t)

	before := snapshot(t, in.root)
	out, code := in.run("--dry-run")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	after := snapshot(t, in.root)
	// compose.log is this harness's recording of what the script invoked, not
	// something the script wrote on its own account.
	delete(before, "compose.log")
	delete(after, "compose.log")

	for path, was := range before {
		switch now, still := after[path]; {
		case !still:
			t.Errorf("the dry run deleted %s", path)
		case now != was:
			t.Errorf("the dry run changed %s:\n  before %s\n  after  %s", path, was, now)
		}
	}
	for path := range after {
		if _, existed := before[path]; !existed {
			t.Errorf("the dry run created %s", path)
		}
	}
}

// env_set is the other half of env_disable's problem. A fresh --lan install
// over a readable but unwritable .env cannot delete the old line or append the
// new one, and reported the address it had been asked for regardless — while
// compose would read the old, public one. An exit status only says the command
// ran, so the value is read back.
func TestFreshInstallAbortsWhenItCannotWriteTheBind(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("DNSDADDY_DASHBOARD_BIND=203.0.113.20\n")
	in.denyWrite(in.root)

	out, code, ok := in.runAsNonRoot("--lan", "--yes")
	if !ok {
		t.Skip("cannot reach an unprivileged uid: test process is root and setpriv is missing")
	}
	if code == 0 {
		t.Fatalf("install succeeded without writing the bind it announced\n%s", out)
	}
	contains(t, out, "Could not write DNSDADDY_DASHBOARD_BIND")
	notContains(t, in.composeLog(), "up -d")
}

// A dry run that finds a public bind this installer wrote must say it would
// close it. Staying silent shows the operator an unsafe address and no plan to
// deal with it, which reads as "this run intends to leave it published" — and
// it is the one security-relevant edit of the upgrade, so it is the one most
// worth reviewing before it happens.
func TestDryRunUpgradeSaysItWouldCloseAPublicBind(t *testing.T) {
	in := newInstall(t)
	in.writeEnv("# managed by install-docker.sh\nDNSDADDY_DASHBOARD_BIND=203.0.113.20\n")

	out, code := in.run("--upgrade", "--yes", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "public address")
	contains(t, out, "comment out DNSDADDY_DASHBOARD_BIND=203.0.113.20")
	// And it is still a dry run: the line is untouched.
	contains(t, in.readEnv(), "\nDNSDADDY_DASHBOARD_BIND=203.0.113.20")
}

// --- Deployment modes ---------------------------------------------------------

// The security invariant of the whole VPS story: neither public mode may put
// the management interface on a public address. HTTPS mode is the dangerous
// one, because it is the mode whose purpose is "reachable from a browser" —
// the tempting implementation is to publish 8080 and put TLS in front later.
//
// docker-compose.yml reads "${DNSDADDY_DASHBOARD_BIND:-127.0.0.1}:8080:8080",
// so this asserts on the value that decides it. If a future change sets that
// variable in HTTPS mode, this fails.
func TestHttpsModeNeverPublishesTheDashboardBackend(t *testing.T) {
	in := newInstall(t)
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com")

	// Not a dry run. A dry run writes no .env, so every assertion below would
	// pass against an empty string — which is exactly what happened the first
	// time this was written, and it is the one test in this file that must not
	// be able to do that.
	out, code := in.run("--https", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !in.envExists() {
		t.Fatal(".env was never written, so this test would assert nothing")
	}
	env := in.readEnv()
	for _, forbidden := range []string{
		"DNSDADDY_DASHBOARD_BIND=0.0.0.0",
		"DNSDADDY_DASHBOARD_BIND=::",
	} {
		if strings.Contains(env, forbidden) {
			t.Errorf("HTTPS mode set %s — the management API would be published in plaintext:\n%s",
				forbidden, env)
		}
	}
	// Not merely "not 0.0.0.0": an active bind of any kind publishes it.
	for _, line := range strings.Split(env, "\n") {
		if strings.HasPrefix(line, "DNSDADDY_DASHBOARD_BIND=") &&
			strings.TrimPrefix(line, "DNSDADDY_DASHBOARD_BIND=") != "" {
			t.Errorf("HTTPS mode published the dashboard backend: %q", line)
		}
	}
	notContains(t, out, "http://"+"dns.example.com")
}

// HTTPS mode is configured for TLS, and says so in the terms the app needs:
// a base URL it can build links from, and cookies that will not be sent over
// plaintext.
func TestHttpsModeConfiguresTheAppForTLS(t *testing.T) {
	in := newInstall(t)
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com")

	out, code := in.run("--https", "--yes", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "dns.example.com")
	contains(t, out, "backend stays on loopback")
}

// Everything the operator types here ends up in a generated Caddyfile, so what
// is refused — and why — is a security boundary rather than a usability one.
//
// The failure names the specific reason in each case. A shared "that is not
// one" would pass whether or not the script had understood what it was
// looking at, which is the mistake the earlier version of this test made.
func TestHttpsModeRefusesWhatCannotBeServed(t *testing.T) {
	cases := []struct {
		value  string
		reason string
	}{
		// Shape.
		{"localhost", "not a hostname or an IP address"},        // single label
		{"", "not a hostname or an IP address"},                 //
		{"dns example com", "not a hostname or an IP address"},  // whitespace
		{"-dns.example.com", "not a hostname or an IP address"}, // leading hyphen
		{"999.1.1.1", "not a hostname or an IP address"},        // octet out of range
		{"1.2.3", "not a hostname or an IP address"},            // short quad
		{"fe80::1%eth0", "not a hostname or an IP address"},     // zoned link-local

		// Right shape, wrong address: a certificate is not issued for these,
		// and finding that out here beats finding it out from ACME.
		{"192.0.2.10", "not a publicly routable address"},  // TEST-NET-1
		{"10.0.0.5", "not a publicly routable address"},    // RFC 1918
		{"127.0.0.1", "not a publicly routable address"},   // loopback
		{"100.64.0.9", "not a publicly routable address"},  // CGNAT
		{"169.254.1.1", "not a publicly routable address"}, // link-local
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			in := newInstall(t)
			in.setenv("DNSDADDY_HTTPS_HOSTNAME=" + tc.value)

			out, code := in.run("--https", "--yes", "--dry-run")
			if code == 0 {
				t.Fatalf("accepted %q\n%s", tc.value, out)
			}
			contains(t, out, tc.reason)
		})
	}
}

// A Caddyfile site address is a shell-free but structured format: a brace or a
// newline in it closes the site block and opens whatever comes next. None of
// these may reach the file, and the validators are whitelists precisely so
// that the list below does not have to be exhaustive to be safe.
func TestHttpsModeRefusesCaddyfileAndShellInjection(t *testing.T) {
	for _, bad := range []string{
		"dns.example.com { respond \"pwned\" }",
		"dns.example.com\nadmin 0.0.0.0:2019",
		"dns.example.com;curl evil.example",
		"dns.example.com$(id)",
		"dns.example.com`id`",
		"dns.example.com|id",
		"$(reboot)",
		"dns.example.com respond 200",
		"*.example.com",
		"dns.example.com:8080",
	} {
		t.Run(bad, func(t *testing.T) {
			in := newInstall(t)
			in.setenv("DNSDADDY_HTTPS_HOSTNAME=" + bad)

			out, code := in.run("--https", "--yes", "--dry-run")
			if code == 0 {
				t.Fatalf("accepted %q as an HTTPS target\n%s", bad, out)
			}
		})
	}
}

// A pasted URL is a mistake, not an attack. Strip what can be stripped
// unambiguously and carry on, rather than making somebody retype it.
func TestHttpsModeNormalisesAPastedURL(t *testing.T) {
	for _, given := range []string{
		"https://dns.example.com",
		"http://dns.example.com",
		"https://dns.example.com/",
		"  dns.example.com  ",
	} {
		t.Run(given, func(t *testing.T) {
			in := newInstall(t)
			in.setenv("DNSDADDY_HTTPS_HOSTNAME=" + given)

			out, code := in.run("--https", "--yes", "--dry-run")
			if code != 0 {
				t.Fatalf("rejected %q, which is unambiguously dns.example.com\n%s", given, out)
			}
			contains(t, out, "HTTPS hostname: dns.example.com")
		})
	}
}

// A public IPv4 address is accepted and classified as one, which is what makes
// the ACME issuer be pinned and the certificate be checked.
func TestHttpsModeAcceptsAPublicIPAddress(t *testing.T) {
	in := newInstall(t)
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=66.228.32.228")

	out, code := in.run("--https", "--yes", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "HTTPS address: 66.228.32.228")
	contains(t, out, "ipv4")
	// And it says it will verify rather than assume.
	contains(t, out, "publicly trusted certificate")
}

// Something already serving 80/443 is not a DNS Daddy failure, and must not be
// treated as one: the resolver is installed and running either way. The TLS
// front end is what gets skipped, and the other service is left alone.
func TestHttpsModeStandsDownWhenAnotherWebServerHoldsThePorts(t *testing.T) {
	in := newInstall(t)
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com")
	in.stub("ss", `
# apache2 on 80, nothing on 443.
if [[ "$*" == *-t* ]]; then
  echo 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("apache2",pid=700,fd=4))'
fi
exit 0`)

	out, code := in.run("--https", "--yes", "--dry-run")
	if code != 0 {
		t.Fatalf("a busy port 80 failed the whole install\n%s", out)
	}
	contains(t, out, "apache2")
	// Never: the installer does not stop, disable or reconfigure it.
	notContains(t, in.composeLog(), "apache")
	for _, forbidden := range []string{"systemctl stop apache", "systemctl disable apache", "a2dissite"} {
		notContains(t, out, forbidden)
	}
}

// The reported confusion, as a test. A public-VPS install with Apache already
// on port 80: the dashboard is correctly on loopback, so browsing to the host
// IP reaches Apache, and the installer used to say nothing at all about it.
// Silence there is what made a working install look like a failed one.
func TestTunnelModeExplainsAnExistingWebServerOnPort80(t *testing.T) {
	in := newInstall(t)
	in.stub("ss", `
if [[ "$*" == *-t* ]]; then
  echo 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("apache2",pid=700,fd=4))'
fi
exit 0`)

	out, code := in.run("--vps", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "apache2")
	// The sentence whose absence caused the confusion.
	contains(t, out, "reaches that server, not DNS Daddy")
	contains(t, out, "has not changed it")
	// And the dashboard is still reachable the safe way.
	contains(t, out, "ssh -L 8080:127.0.0.1:8080")
	// Apache is left entirely alone.
	for _, forbidden := range []string{"systemctl stop apache", "systemctl disable apache", "a2dissite", "apt-get remove apache"} {
		notContains(t, out, forbidden)
	}
}

// And with nothing on 80, no such section appears: an installer that warns
// about a web server that is not there teaches the reader to skip warnings.
func TestNoWebServerSectionWhenPortsAreFree(t *testing.T) {
	in := newInstall(t)

	out, code := in.run("--vps", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	notContains(t, out, "Existing web server")
}

// --- Option 3 fails closed ---------------------------------------------------
//
// The mandatory property: when HTTPS cannot be completed, the deployment must
// end up in option 2's posture — loopback only, reachable over an SSH tunnel —
// and never in plaintext on a public address. These tests drive the real script
// through each way it can fail and check what it left behind.

// caddyfileAt points the installer at a temporary Caddyfile and returns its
// path, so the rollback paths can be exercised without touching /etc.
func (in *install) caddyfileAt() string {
	path := filepath.Join(in.root, "caddy", "Caddyfile")
	in.caddyfile = path
	in.setenv("DNSDADDY_CADDYFILE=" + path)
	return path
}

// readCaddyfile returns what the installer left behind, or "" if it wrote
// nothing. Empty rather than fatal: several tests assert that a failed attempt
// leaves no configuration at all, and that is a legitimate outcome.
func (in *install) readCaddyfile() string {
	if in.caddyfile == "" {
		in.t.Fatal("readCaddyfile without caddyfileAt")
	}
	b, err := os.ReadFile(in.caddyfile)
	if err != nil {
		return ""
	}
	return string(b)
}

func TestHttpsFailureLeavesTheDashboardOnLoopback(t *testing.T) {
	// Every distinct reason the HTTPS step can fail. In all of them the
	// dashboard must be exactly where SSH-tunnel mode leaves it.
	cases := []struct {
		name string
		env  []string
	}{
		{"caddy cannot be installed", []string{"STUB_APT_EXIT=1", "PATH_WITHOUT_CADDY=1"}},
		{"generated config does not validate", []string{"STUB_CADDY_VALIDATE_EXIT=1"}},
		{"no certificate ever arrives", []string{"STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1"}},
		{"an untrusted certificate is served", []string{"STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=0"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := newInstall(t)
			in.setenv("DNSDADDY_HTTPS_HOSTNAME=66.228.32.228", "DNSDADDY_HTTPS_TIMEOUT=1")
			in.setenv(tc.env...)
			in.caddyfileAt()
			if len(tc.env) > 0 && tc.env[len(tc.env)-1] == "PATH_WITHOUT_CADDY=1" {
				must(t, os.Remove(filepath.Join(in.bin, "caddy")))
			}

			out, _ := in.run("--https", "--yes")
			if !in.envExists() {
				t.Fatal(".env was never written, so this test would assert nothing")
			}
			env := in.readEnv()

			// 1. The backend is not published, in any spelling.
			for _, line := range strings.Split(env, "\n") {
				if strings.HasPrefix(line, "DNSDADDY_DASHBOARD_BIND=") &&
					strings.TrimPrefix(line, "DNSDADDY_DASHBOARD_BIND=") != "" {
					t.Errorf("a failed HTTPS setup published the dashboard: %q", line)
				}
			}

			// 2. Secure cookies are not left on. This is what makes the
			//    fallback usable rather than merely safe: over an SSH tunnel
			//    the dashboard is plain HTTP on loopback, and a browser will
			//    not return a Secure cookie there — login would fail with no
			//    error that points at the cause.
			for _, line := range strings.Split(env, "\n") {
				if strings.HasPrefix(line, "DNSDADDY_SECURE_COOKIES=always") {
					t.Errorf("a failed HTTPS setup left %q active; the SSH-tunnel fallback "+
						"cannot log in with that set", line)
				}
			}

			// 3. The operator is told what to do, with the real command.
			contains(t, out, "ssh -L 8080:127.0.0.1:8080")
			contains(t, out, "http://127.0.0.1:8080")
			// 4. And is never handed a plaintext public URL.
			notContains(t, out, "http://66.228.32.228:8080")
		})
	}
}

func TestHttpsRefusesToTreatAnUntrustedCertificateAsSuccess(t *testing.T) {
	// The specific outcome the IP path exists to prevent: Caddy falls back to
	// its own internal CA, TLS answers, and a browser shows a warning on the
	// management interface. An installer that called that "ready" would be
	// training people to click through certificate warnings on the one page
	// that must never have one.
	in := newInstall(t)
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=66.228.32.228", "DNSDADDY_HTTPS_TIMEOUT=1")
	in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=0") // TLS up, untrusted
	in.caddyfileAt()

	out, _ := in.run("--https", "--yes")

	notContains(t, out, "https://66.228.32.228 is serving")
	contains(t, out, "HTTPS setup could not be completed")
	contains(t, out, "not publicly trusted")
	// And it fell back rather than leaving the browser to meet that
	// certificate: the tunnel is what the operator is handed instead.
	contains(t, out, "ssh -L 8080:127.0.0.1:8080")
	notContains(t, out, "http://66.228.32.228:8080")
}

func TestHttpsSuccessIsOnlyClaimedAfterATrustedCertificate(t *testing.T) {
	in := newInstall(t)
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CURL_STRICT_EXIT=0", "STUB_CURL_LAX_EXIT=0")
	in.caddyfileAt()

	out, code := in.run("--https", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "Certificate is trusted by this machine's CA store")
	contains(t, out, "https://dns.example.com")
	// And the backend still is not published.
	env := in.readEnv()
	for _, line := range strings.Split(env, "\n") {
		if strings.HasPrefix(line, "DNSDADDY_DASHBOARD_BIND=") &&
			strings.TrimPrefix(line, "DNSDADDY_DASHBOARD_BIND=") != "" {
			t.Errorf("successful HTTPS published the backend anyway: %q", line)
		}
	}
}

func TestAnExistingCaddyfileIsBackedUpAndRestoredOnFailure(t *testing.T) {
	// Somebody's existing Caddy configuration is not this installer's to lose.
	const existing = "example.org {\n\trespond \"someone else's site\"\n}\n"

	in := newInstall(t)
	path := in.caddyfileAt()
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, []byte(existing), 0o644))

	in.setenv("DNSDADDY_HTTPS_HOSTNAME=66.228.32.228", "DNSDADDY_HTTPS_TIMEOUT=1")
	in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=0")

	out, _ := in.run("--https", "--yes")

	got, err := os.ReadFile(path)
	must(t, err)
	if string(got) != existing {
		t.Errorf("the existing Caddyfile was not restored after a failed HTTPS setup.\n"+
			"want:\n%s\ngot:\n%s\noutput:\n%s", existing, got, out)
	}

	// And a copy was kept, named so it is findable.
	entries, err := os.ReadDir(filepath.Dir(path))
	must(t, err)
	var backups int
	for _, e := range entries {
		if strings.Contains(e.Name(), "dnsdaddy-bak-") {
			backups++
		}
	}
	if backups == 0 {
		t.Error("no backup of the existing Caddyfile was made before replacing it")
	}
}

func TestAGeneratedCaddyfileIsRemovedWhenThereWasNothingBefore(t *testing.T) {
	// Nothing was there, HTTPS failed, so nothing should be left: an abandoned
	// site block for a management interface is what nobody thinks to look for.
	in := newInstall(t)
	path := in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=66.228.32.228", "DNSDADDY_HTTPS_TIMEOUT=1")
	in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=0")

	in.run("--https", "--yes")

	if _, err := os.Stat(path); err == nil {
		body, _ := os.ReadFile(path)
		t.Errorf("a Caddyfile was left behind after a failed HTTPS setup:\n%s", body)
	}
}

func TestTheGeneratedCaddyfileProxiesOnlyLoopback(t *testing.T) {
	in := newInstall(t)
	path := in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CURL_STRICT_EXIT=0", "STUB_CURL_LAX_EXIT=0")

	out, code := in.run("--https", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}

	body, err := os.ReadFile(path)
	must(t, err)
	conf := string(body)

	if !strings.Contains(conf, "reverse_proxy 127.0.0.1:8080") {
		t.Errorf("the generated Caddyfile does not proxy loopback:\n%s", conf)
	}
	// Anything else as an upstream would mean the backend was expected on a
	// non-loopback address, which is the whole thing this mode avoids.
	for _, forbidden := range []string{"0.0.0.0:8080", "reverse_proxy dns.example.com"} {
		if strings.Contains(conf, forbidden) {
			t.Errorf("the generated Caddyfile contains %q:\n%s", forbidden, conf)
		}
	}
	for _, header := range []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	} {
		if !strings.Contains(conf, header) {
			t.Errorf("the generated Caddyfile does not set %s:\n%s", header, conf)
		}
	}
}

func TestAnIPCaddyfilePinsThePublicIssuer(t *testing.T) {
	// If Caddy is left to decide, it uses its internal CA for an address it
	// considers unnameable — a certificate no browser trusts, in front of the
	// management interface. Naming the public issuer means the attempt either
	// produces a real certificate or fails visibly.
	in := newInstall(t)
	path := in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=66.228.32.228", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CURL_STRICT_EXIT=0", "STUB_CURL_LAX_EXIT=0")

	out, code := in.run("--https", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}

	body, err := os.ReadFile(path)
	must(t, err)
	conf := string(body)
	for _, want := range []string{"issuer acme", "profile shortlived"} {
		if !strings.Contains(conf, want) {
			t.Errorf("an IP site does not pin %q, so Caddy may fall back to its internal CA:\n%s",
				want, conf)
		}
	}
	if !strings.Contains(conf, "66.228.32.228 {") {
		t.Errorf("the site address is not the IP address:\n%s", conf)
	}
}

func TestACaddyTooOldForTheACMEProfileIsReportedAsSuch(t *testing.T) {
	// Capability, not a version number. The installer does not try to know
	// which Caddy releases support the profile subdirective; it writes the
	// config and lets `caddy validate` answer.
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=66.228.32.228", "DNSDADDY_HTTPS_TIMEOUT=1")
	in.setenv("STUB_CADDY_VALIDATE_EXIT=1",
		"STUB_CADDY_VALIDATE_MSG=unrecognized subdirective profile")

	out, _ := in.run("--https", "--yes")
	contains(t, out, "does not understand the ACME 'profile' setting")
}

// --- Caddy version gating ----------------------------------------------------

// Public IP-address certificates need Caddy 2.11 or newer. Before that release
// its bundled CertMagic held a map of public CAs to whether they issue IP
// certificates, and Let's Encrypt was marked false — so the request was refused
// locally and no ACME order was ever sent.
//
// Verified empirically against certmagic v0.25.3 as shipped in Caddy v2.11.4:
// PreCheck with the Let's Encrypt production directory returns nil for a public
// IPv4 and a public IPv6 subject, and an error for the same subjects against
// ZeroSSL. See docs/deployment-matrix.md for the transcript.
func TestIPModeRefusesACaddyTooOldForIPCertificates(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=66.228.32.228", "DNSDADDY_HTTPS_TIMEOUT=1")
	in.setenv("STUB_CADDY_VERSION=v2.6.2")

	out, _ := in.run("--https", "--yes")

	contains(t, out, "too old for IP-address certificates")
	contains(t, out, "caddyserver.com/docs/install")
	// And it fails closed like every other HTTPS failure.
	env := in.readEnv()
	for _, line := range strings.Split(env, "\n") {
		if strings.HasPrefix(line, "DNSDADDY_DASHBOARD_BIND=") &&
			strings.TrimPrefix(line, "DNSDADDY_DASHBOARD_BIND=") != "" {
			t.Errorf("an old Caddy left the dashboard published: %q", line)
		}
		if strings.HasPrefix(line, "DNSDADDY_SECURE_COOKIES=always") {
			t.Error("an old Caddy left secure cookies on; the SSH-tunnel fallback could not log in")
		}
	}
	contains(t, out, "ssh -L 8080:127.0.0.1:8080")
}

// The same old Caddy is fine for a hostname, which is the far more common
// deployment. Refusing it there would be an obstacle rather than a safeguard.
func TestHostnameModeAcceptsAnOlderCaddy(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CADDY_VERSION=v2.6.2", "STUB_CURL_STRICT_EXIT=0", "STUB_CURL_LAX_EXIT=0")

	out, code := in.run("--https", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	notContains(t, out, "too old for IP-address certificates")
	contains(t, out, "Certificate is trusted by this machine's CA store")
}

// caddy_version_at_least is the comparison the gate depends on, and an
// off-by-one there either blocks a working deployment or lets a broken one
// through.
//
// The function is extracted from the real script and sourced on its own —
// sourcing the whole installer would run its main body. What is under test is
// therefore the exact text that ships, not a reimplementation of it.
func TestCaddyVersionComparison(t *testing.T) {
	repo := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(repo, "deploy", "install-docker.sh"))
	must(t, err)

	src := string(body)
	from := strings.Index(src, "caddy_version_at_least() {")
	if from < 0 {
		t.Fatal("caddy_version_at_least is no longer defined in install-docker.sh")
	}
	to := strings.Index(src[from:], "\n}\n")
	if to < 0 {
		t.Fatal("could not find the end of caddy_version_at_least")
	}
	fn := src[from : from+to+3]

	cases := []struct {
		version string
		ok      bool
	}{
		{"v2.11.4 h1:abc", true},
		{"v2.11.0", true},
		{"v2.12.0", true},
		{"v3.0.0", true},
		{"2.11.4", true},
		{"v2.10.2", false},
		{"v2.6.2", false},
		{"v1.99.0", false},
		{"(devel)", false}, // unparseable must not pass
		{"", false},
	}

	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			script := "caddy() { echo " + shellQuote(tc.version) + "; }\n" + fn +
				"\nif caddy_version_at_least 2 11; then echo YES; else echo NO; fi\n"
			out, err := exec.Command("bash", "-c", script).CombinedOutput()
			if err != nil && !strings.Contains(string(out), "NO") && !strings.Contains(string(out), "YES") {
				t.Fatalf("running the extracted function failed: %v\n%s", err, out)
			}
			got := strings.Contains(string(out), "YES")
			if got != tc.ok {
				t.Errorf("caddy_version_at_least(2,11) for %q = %v, want %v\n%s",
					tc.version, got, tc.ok, out)
			}
		})
	}
}

// shellQuote wraps a value in single quotes for embedding in a generated
// script, escaping any single quote it contains.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// The kernel truncates process names to 15 characters (TASK_COMM_LEN), so the
// 16-character "systemd-resolved" is reported by ss and /proc as
// "systemd-resolve". A pattern written with the trailing d silently never
// matched, and the operator got generic advice instead of the DNSStubListener
// recipe — on the most common port-53 conflict, on the most common platform
// for this product. Found by running the installer on a real Ubuntu 24.04.
func TestSystemdResolvedIsRecognisedByItsTruncatedName(t *testing.T) {
	for _, owner := range []string{
		"systemd-resolve",                         // what the kernel actually reports
		"systemd-resolved",                        // the full name, e.g. from a units listing
		`users:(("systemd-resolve",pid=1,fd=12))`, // the shape ss prints
	} {
		t.Run(owner, func(t *testing.T) {
			in := newInstall(t)
			in.stub("ss", `
if [[ "$*" == *-l* ]]; then
  echo 'udp   UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*    users:(("`+strings.TrimSuffix(strings.TrimPrefix(owner, `users:(("`), `",pid=1,fd=12))`)+`",pid=1,fd=12))'
  echo 'tcp   LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*  users:(("`+strings.TrimSuffix(strings.TrimPrefix(owner, `users:(("`), `",pid=1,fd=12))`)+`",pid=1,fd=12))'
fi
exit 0`)

			out, code := in.run("--vps", "--yes")
			if code == 0 {
				t.Fatalf("the installer continued with port 53 held\n%s", out)
			}
			// The tailored advice, not the generic fallback.
			contains(t, out, "DNSStubListener=no")
			contains(t, out, "systemd-resolved is running")
		})
	}
}

// --- HTTPS diagnosis, hostname DNS, and the measured success posture --------

// The failure that started this work: on a real VPS the installer said "No
// certificate was issued ... usually means ports 80 and 443 are not reachable"
// whatever had actually happened, because curl was the only evidence it
// gathered. Caddy logs the ACME problem document the CA returned. These pin
// that it is read, and that each cause produces the advice that matches it.
func TestACMEFailureIsDiagnosedFromCaddysOwnLog(t *testing.T) {
	cases := []struct {
		name   string
		log    string
		expect string
		advice string
		absent string
	}{
		{
			name:   "refused challenge is a firewall, not a mystery",
			log:    `{"level":"error","logger":"http.acme_client","msg":"challenge failed","identifier":"66.228.32.228","problem":{"type":"urn:ietf:params:acme:error:connection","detail":"66.228.32.228: Connection refused"}}`,
			expect: "the connection was refused",
			advice: "cloud firewall",
			// The old guess must not survive alongside the real answer.
			absent: "usually means ports 80 and 443",
		},
		{
			name:   "a timed out challenge is named as such",
			log:    `{"level":"error","problem":{"type":"urn:ietf:params:acme:error:connection","detail":"66.228.32.228: Timeout during connect (likely firewall problem)"}}`,
			expect: "the challenge timed out",
			advice: "dropping inbound 80/443",
		},
		{
			name:   "a rate limit says wait, not retry",
			log:    `{"level":"error","msg":"could not get certificate","error":"urn:ietf:params:acme:error:rateLimited - too many certificates already issued"}`,
			expect: "rate-limited",
			advice: "Wait before retrying",
		},
		{
			name:   "an unresolvable name is a DNS problem",
			log:    `{"level":"error","problem":{"type":"urn:ietf:params:acme:error:dns","detail":"no such host"}}`,
			expect: "could not resolve",
			advice: "dig +short",
		},
		{
			name:   "a Caddy too old for IP certificates says so",
			log:    `{"level":"error","msg":"[66.228.32.228] Obtain: subject '66.228.32.228' cannot have public IP certificate from https://acme-v02.api.letsencrypt.org/directory"}`,
			expect: "predates Let's Encrypt's IP support",
			advice: "caddyserver.com/docs/install",
		},
		{
			name:   "a challenge answered by something else is not a firewall",
			log:    `{"level":"error","problem":{"type":"urn:ietf:params:acme:error:unauthorized","detail":"Invalid response"}}`,
			expect: "but not this Caddy",
			advice: "Another host or proxy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := newInstall(t)
			in.caddyfileAt()
			in.setenv("DNSDADDY_HTTPS_HOSTNAME=66.228.32.228", "DNSDADDY_HTTPS_TIMEOUT=5")
			// Nothing answers: exactly the state the VPS was left in, where
			// both curl probes fail and only the log knows why.
			in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1")
			in.setenv("DNSDADDY_CADDY_LOG_CMD=printf '%s' " + shellQuote(tc.log))

			out, code := in.run("--https", "--yes")
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			contains(t, out, tc.expect)
			contains(t, out, tc.advice)
			if tc.absent != "" {
				notContains(t, out, tc.absent)
			}
			// Whatever the cause, the posture is the same: never published.
			notContains(t, out, "http://66.228.32.228:8080")
			contains(t, out, "ssh -L 8080:127.0.0.1:8080")
		})
	}
}

// The CA's own words are quoted, because a diagnosis the operator cannot check
// is one they have to take on trust.
func TestTheCAsOwnErrorIsQuotedBack(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=66.228.32.228", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1")
	in.setenv(`DNSDADDY_CADDY_LOG_CMD=printf '%s' '{"problem":{"type":"urn:ietf:params:acme:error:connection","detail":"66.228.32.228: Connection refused"}}'`)

	out, _ := in.run("--https", "--yes")
	contains(t, out, "Caddy reported: 66.228.32.228: Connection refused")
	contains(t, out, "journalctl -u caddy")
}

// Hostname mode compares public DNS against this machine, and says plainly
// which of the two is wrong. It never changes a DNS record: the installer has
// no business editing somebody's zone and could not do it correctly anyway.
func TestHostnameResolvingHereIsReportedAsAMatch(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_GETENT_V4=192.168.1.75", "STUB_CURL_STRICT_EXIT=0", "STUB_CURL_LAX_EXIT=0")

	out, code := in.run("--https", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "dns.example.com resolves to 192.168.1.75, which is an address on this machine")
}

func TestHostnamePointingElsewhereIsReportedWithBothAddresses(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_GETENT_V4=203.0.113.10", "STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1")

	out, _ := in.run("--https", "--yes")
	// Both sides of the comparison, because "does not match" without the two
	// values leaves the operator to go and find them.
	contains(t, out, "dns.example.com currently resolves to 203.0.113.10")
	contains(t, out, "This machine appears to be 192.168.1.75")
	contains(t, out, "This installer does not change DNS records")
	// NAT is a legitimate reason for the mismatch and is not treated as fatal.
	contains(t, out, "behind NAT")
}

func TestAHostnameThatDoesNotResolveDoesNotPretendPropagationIsInstant(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_GETENT_EXIT=2", "STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1")

	out, _ := in.run("--https", "--yes")
	contains(t, out, "dns.example.com does not resolve from this machine")
	contains(t, out, "cannot tell you when it has")
}

// A stale AAAA on a host with no IPv6 is worth saying, because Let's Encrypt
// prefers IPv6 when one exists and will send the challenge somewhere this
// machine is not. The A-only version of this check passed it silently.
func TestAnAAAARecordOnAHostWithoutIPv6IsFlagged(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_GETENT_V4=192.168.1.75", "STUB_GETENT_V6=2001:db8::1")
	in.setenv("STUB_CURL_STRICT_EXIT=0", "STUB_CURL_LAX_EXIT=0")

	out, _ := in.run("--https", "--yes")
	contains(t, out, "has an AAAA record")
	contains(t, out, "prefers IPv6")
}

// HSTS is a one-year commitment. It goes out after a certificate has actually
// been served, not on the strength of an attempt that might fail.
func TestHSTSIsWrittenOnlyAfterTheCertificateIsProven(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CURL_STRICT_EXIT=0", "STUB_CURL_LAX_EXIT=0", "STUB_GETENT_V4=192.168.1.75")

	out, code := in.run("--https", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "HSTS enabled now that the certificate is proven")
	if got := in.readCaddyfile(); !strings.Contains(got, "Strict-Transport-Security") {
		t.Errorf("a proven certificate should leave HSTS in the Caddyfile:\n%s", got)
	}
}

func TestAFailedCertificateLeavesNoHSTSBehind(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=66.228.32.228", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1")
	in.setenv(`DNSDADDY_CADDY_LOG_CMD=printf '%s' '{"problem":{"type":"urn:ietf:params:acme:error:connection","detail":"refused"}}'`)

	out, _ := in.run("--https", "--yes")
	notContains(t, out, "HSTS enabled")
	if got := in.readCaddyfile(); strings.Contains(got, "Strict-Transport-Security") {
		t.Errorf("a failed attempt pinned an HSTS policy anyway:\n%s", got)
	}
}

// The distinction the operator most needs and the installer most easily blurs:
// what this machine measured, versus what no code running here can know.
func TestReachabilitySeparatesLocalFromExternal(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=dns.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CURL_STRICT_EXIT=0", "STUB_CURL_LAX_EXIT=0", "STUB_GETENT_V4=192.168.1.75")

	out, _ := in.run("--https", "--yes")
	contains(t, out, "measured on this machine")
	contains(t, out, "cannot be confirmed from here")
	contains(t, out, "UNKNOWN  whether inbound TCP 80 and 443 reach this machine")
	contains(t, out, "does not change firewall rules")
	// Opening 53 is not the same as running an open resolver, and saying so
	// here is what stops the next person conflating them.
	contains(t, out, "does not make this")
	contains(t, out, "open resolver")
}

// --- Rollback fidelity, log windowing, and the pending path -----------------

// Re-running --https over a deployment that already works must not leave the
// app worse off than it found it.
//
// The failure path restores the previous Caddyfile — which, on a working
// deployment, is a Caddyfile that still terminates TLS and still proxies to
// this app. Blanket-disabling the HTTPS env alongside it left the proxy up and
// the app believing it was on plain HTTP: no Secure flag on session cookies of
// a live public site, and every client collapsing to the proxy's own address
// because the trusted-proxy list was gone.
func TestARerunThatFailsKeepsAWorkingHTTPSDeploymentIntact(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	// An .env that a previous successful HTTPS install would have left.
	in.writeEnv(strings.Join([]string{
		"DNSDADDY_BASE_URL=https://admin.example.com",
		"DNSDADDY_SECURE_COOKIES=always",
		"DNSDADDY_TRUSTED_PROXY_CIDRS=172.17.0.0/16",
	}, "\n"))

	in.setenv("DNSDADDY_HTTPS_HOSTNAME=admin.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1", "STUB_GETENT_V4=192.168.1.75")
	in.setenv(`DNSDADDY_CADDY_LOG_CMD=printf '%s' '{"problem":{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates"}}'`)

	out, code := in.run("--https", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}

	env := in.readEnv()
	for _, want := range []string{
		"DNSDADDY_BASE_URL=https://admin.example.com",
		"DNSDADDY_SECURE_COOKIES=always",
		"DNSDADDY_TRUSTED_PROXY_CIDRS=172.17.0.0/16",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("a failed re-run dropped %q from a working deployment:\n%s", want, env)
		}
	}
	// And it still must not publish the backend.
	for _, line := range strings.Split(env, "\n") {
		if strings.HasPrefix(line, "DNSDADDY_DASHBOARD_BIND=") &&
			strings.TrimPrefix(line, "DNSDADDY_DASHBOARD_BIND=") != "" {
			t.Errorf("a failed re-run published the backend: %q", line)
		}
	}
}

// The same rollback on a FIRST install still goes to the tunnel, because there
// was no working HTTPS configuration to preserve. Without this the fix above
// would just be a way to leave secure cookies on where they break login.
func TestAFailedFirstInstallStillRevertsToTheTunnel(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=admin.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1", "STUB_GETENT_V4=192.168.1.75")
	in.setenv(`DNSDADDY_CADDY_LOG_CMD=printf '%s' '{"problem":{"type":"urn:ietf:params:acme:error:connection","detail":"refused"}}'`)

	out, _ := in.run("--https", "--yes")
	contains(t, out, "ssh -L 8080:127.0.0.1:8080")

	env := in.readEnv()
	for _, line := range strings.Split(env, "\n") {
		if strings.HasPrefix(line, "DNSDADDY_SECURE_COOKIES=always") {
			t.Errorf("a failed first install left %q active; tunnel login would fail silently", line)
		}
	}
}

// A hostname whose issuance is simply slow must stay pending rather than being
// rolled back. The gate for that used to test whether the failure message was
// empty — but every timeout writes one, so the branch could never run and slow
// issuance was always treated as a hard failure.
func TestSlowHostnameIssuanceStaysPendingRatherThanRollingBack(t *testing.T) {
	in := newInstall(t)
	caddyfile := in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=admin.example.com", "DNSDADDY_HTTPS_TIMEOUT=1")
	in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1", "STUB_GETENT_V4=192.168.1.75")
	// Caddy has logged nothing recognisable: no cause, so nothing to act on.
	in.setenv("DNSDADDY_CADDY_LOG_CMD=printf ''")

	out, code := in.run("--https", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "No certificate arrived for admin.example.com")
	contains(t, out, "That is usually DNS")
	contains(t, out, "dig +short admin.example.com")
	// The site must NOT stay configured. Leaving it would let a later
	// background retry publish the dashboard over HTTPS while the app is back
	// in tunnel configuration: no Secure flag on the session cookie, and every
	// client appearing to come from the proxy. Both halves move together or
	// neither does.
	if body, err := os.ReadFile(caddyfile); err == nil && strings.Contains(string(body), "admin.example.com") {
		t.Errorf("a pending attempt left a public site configured:\n%s", body)
	}
	// But .env still goes back, or the tunnel it offers cannot be logged into.
	env := in.readEnv()
	for _, line := range strings.Split(env, "\n") {
		if strings.HasPrefix(line, "DNSDADDY_SECURE_COOKIES=always") {
			t.Errorf("pending left %q active; the tunnel it offers would not accept a login", line)
		}
	}
}

// A diagnosed hostname failure is NOT pending: it does not improve by waiting,
// so it rolls back and says what to change.
func TestADiagnosedHostnameFailureRollsBack(t *testing.T) {
	in := newInstall(t)
	caddyfile := in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=admin.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1", "STUB_GETENT_V4=192.168.1.75")
	in.setenv(`DNSDADDY_CADDY_LOG_CMD=printf '%s' '{"problem":{"type":"urn:ietf:params:acme:error:connection","detail":"admin.example.com: Connection refused"}}'`)

	out, _ := in.run("--https", "--yes")
	notContains(t, out, "keeps trying in the background")
	contains(t, out, "the connection was refused")
	if body, err := os.ReadFile(caddyfile); err == nil && strings.Contains(string(body), "admin.example.com") {
		t.Errorf("a diagnosed failure left the site configured:\n%s", body)
	}
}

// The log reader must not diagnose from the previous run's errors. A fixed
// ten-minute window did exactly that, so re-running after opening a firewall —
// the expected recovery — could roll back an attempt that was going fine.
func TestTheLogWindowStartsAtThisAttempt(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.setenv("DNSDADDY_HTTPS_HOSTNAME=admin.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	// The failure path, so the diagnosis actually runs and journalctl is
	// actually invoked. Written against the success path first, this test
	// passed with the old fixed window still in place: the log was never read
	// at all, so there were no arguments to assert on.
	in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1", "STUB_GETENT_V4=192.168.1.75")

	argsLog := filepath.Join(in.root, "journalctl-args.txt")
	in.setenv("JOURNAL_ARGS_LOG=" + argsLog)
	// Records how it was called and returns nothing, so no cause is diagnosed
	// and the installer keeps polling — which is when the window matters.
	in.stub("journalctl", `printf '%s\n' "$*" >> "$JOURNAL_ARGS_LOG"`)

	out, code := in.run("--https", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}

	recorded, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatalf("journalctl was never invoked, so the log was not consulted at all: %v", err)
	}
	got := string(recorded)
	if strings.Contains(got, "-10 min") {
		t.Errorf("the log was read with a fixed window rather than this attempt's start:\n%s", got)
	}
	// A timestamp, which is what confines the read to this attempt.
	if !regexp.MustCompile(`--since \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`).MatchString(got) {
		t.Errorf("expected --since with this attempt's timestamp, got:\n%s", got)
	}
}

// The snapshot has to remember whether a key existed, not just what it held.
//
// An .env carrying only DNSDADDY_BASE_URL is enough for https_env_was_working
// to choose the restore path. If the restore then skips the keys that were
// absent, it leaves the DNSDADDY_SECURE_COOKIES=always that reconcile_env just
// wrote — and after the Caddyfile is rolled back the operator is sent to a
// plain-HTTP tunnel their browser will not send that cookie over.
func TestRestoringAnEnvPutsBackKeysThatWereAbsent(t *testing.T) {
	in := newInstall(t)
	in.caddyfileAt()
	in.writeEnv("DNSDADDY_BASE_URL=https://admin.example.com")

	in.setenv("DNSDADDY_HTTPS_HOSTNAME=admin.example.com", "DNSDADDY_HTTPS_TIMEOUT=5")
	in.setenv("STUB_CURL_STRICT_EXIT=1", "STUB_CURL_LAX_EXIT=1", "STUB_GETENT_V4=192.168.1.75")
	in.setenv(`DNSDADDY_CADDY_LOG_CMD=printf '%s' '{"problem":{"type":"urn:ietf:params:acme:error:connection","detail":"refused"}}'`)

	out, code := in.run("--https", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}

	env := in.readEnv()
	for _, line := range strings.Split(env, "\n") {
		if strings.HasPrefix(line, "DNSDADDY_SECURE_COOKIES=") {
			t.Errorf("a key absent before the run was left set afterwards: %q\n%s", line, env)
		}
		if strings.HasPrefix(line, "DNSDADDY_TRUSTED_PROXY_CIDRS=") {
			t.Errorf("a key absent before the run was left set afterwards: %q\n%s", line, env)
		}
	}
	// The one that WAS there is still there.
	if !strings.Contains(env, "DNSDADDY_BASE_URL=https://admin.example.com") {
		t.Errorf("the key that existed before the run was lost:\n%s", env)
	}
}
