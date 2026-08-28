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
  echo "2: ${STUB_IFACE:-eth0}    inet ${STUB_PRIMARY_IP:-192.168.1.75}/24 scope global"
  for extra in ${STUB_EXTRA_IPS:-}; do
    echo "3: eth1    inet ${extra}/24 scope global"
  done
  exit 0
fi
exit 0`)

	// Nothing listening. A scenario that wants a busy port overrides this.
	in.stub("ss", `exit 0`)

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
	// directory that has to refuse the write. The stub log is pre-created
	// because appending to an existing file does not need that permission.
	must(t, os.WriteFile(filepath.Join(in.root, "compose.log"), nil, 0o666))
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
