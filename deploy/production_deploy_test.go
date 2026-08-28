// Tests for deploy/production-deploy.sh.
//
// This file exists because that script produced two P1s in consecutive review
// rounds — one of them introduced by the fix for the other — and both fixes
// rested on reading it, because nothing here could run it. It decides which
// client ranges a production deployment admits, so "reviewed by eye" is not a
// standard it should be held to.
//
// Same shape as installer_test.go: the real script, driven against a stubbed
// PATH. sqlite3 is stubbed rather than real because the environment has no
// sqlite3 binary; the stub answers the three queries the script asks and is
// driven by environment variables, which is enough to exercise every branch of
// the ACL derivation — the part both P1s were in.
//
// --dry-run throughout: step 9 is skipped by it and every mutating step goes
// through act(), so the script runs to completion without a Docker daemon.
package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type prodDeploy struct {
	t    *testing.T
	root string
	vol  string
	bin  string
	env  []string
	// Paths to make unreadable to the unprivileged uid, applied after the
	// readability fixups below. Mode 000 denies the owner too, so this works
	// whether runAsNonRoot dropped privileges or never had any.
	unreadable []string
}

func newProdDeploy(t *testing.T) *prodDeploy {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}

	root := t.TempDir()
	repo := repoRoot(t)

	must(t, os.MkdirAll(filepath.Join(root, "repo", "deploy"), 0o755))
	copyFile(t, filepath.Join(repo, "deploy", "production-deploy.sh"),
		filepath.Join(root, "repo", "deploy", "production-deploy.sh"), 0o755)
	must(t, os.WriteFile(filepath.Join(root, "repo", "docker-compose.yml"), []byte("services: {}\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "repo", ".env"), []byte("DNSDADDY_BASE_URL=https://dns.example.com\n"), 0o644))

	// The data volume, with a database big enough to clear the sanity check.
	vol := filepath.Join(root, "vol")
	must(t, os.MkdirAll(vol, 0o755))
	must(t, os.WriteFile(filepath.Join(vol, "dnsdaddy.db"), make([]byte, 100_000), 0o644))

	p := &prodDeploy{t: t, root: root, vol: vol, bin: filepath.Join(root, "stubbin")}
	must(t, os.MkdirAll(p.bin, 0o755))
	p.writeStubs()
	return p
}

func (p *prodDeploy) stub(name, body string) {
	p.t.Helper()
	must(p.t, os.WriteFile(filepath.Join(p.bin, name), []byte("#!/usr/bin/env bash\n"+body), 0o755))
}

func (p *prodDeploy) writeStubs() {
	p.stub("docker", `
case "$1" in
  compose) exit 0 ;;
  inspect)
    for a in "$@"; do
      case "$a" in
        *State.Status*) echo running; exit 0 ;;
        *Mounts*)       echo "bind - $STUB_VOL"; exit 0 ;;
        *Config.Env*)   exit 0 ;;
      esac
    done
    exit 0 ;;
esac
exit 0
`)
	p.stub("systemctl", `exit 0`)

	// The three queries the script asks, answered from the environment.
	p.stub("sqlite3", `
q="${@: -1}"
case "$q" in
  *"allow_resolver FROM networks"*)
    # The probe for whether this database predates per-network access.
    [[ "${STUB_LEGACY:-0}" == "1" ]] && exit 1
    echo 0; exit 0 ;;
  *"n.allow_resolver = 1"*)
    [[ "${STUB_LEGACY:-0}" == "1" ]] && exit 1
    printf '%s' "${STUB_PERMITTED:-}" | tr ',' '\n'; exit 0 ;;
  *"n.enabled = 1"*)
    printf '%s' "${STUB_ALL:-}" | tr ',' '\n'; exit 0 ;;
esac
exit 0
`)
	p.stub("curl", `exit 0`)
	p.stub("dig", `exit 0`)
}

func (p *prodDeploy) setenv(kv ...string) { p.env = append(p.env, kv...) }

func (p *prodDeploy) run(args ...string) (string, int) {
	p.t.Helper()
	return p.exec(nil, args...)
}

// runAsNonRoot runs the script as an unprivileged user. The test process itself
// may be either — root in a container, unprivileged on a CI runner — so this
// drops privileges when it has them and runs directly when it has none, and the
// caller asserts the same thing either way. ok is false when neither is
// possible (root, but no setpriv to drop with).
func (p *prodDeploy) runAsNonRoot(args ...string) (out string, code int, ok bool) {
	p.t.Helper()
	if os.Geteuid() != 0 {
		p.lockDown()
		out, code = p.exec(nil, args...)
		return out, code, true
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		return "", 0, false
	}
	// nobody must be able to traverse the fixture and read the script. TempDir
	// hands back <parent>/001 with the parent at 0700, so that one is separate.
	must(p.t, os.Chmod(filepath.Dir(p.root), 0o755))
	must(p.t, filepath.WalkDir(p.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if d.IsDir() {
			mode = 0o755
		} else if info, ierr := d.Info(); ierr == nil && info.Mode()&0o100 != 0 {
			mode = 0o755
		}
		return os.Chmod(path, mode)
	}))
	p.lockDown()
	out, code = p.exec([]string{setpriv, "--reuid=65534", "--regid=65534", "--clear-groups"}, args...)
	return out, code, true
}

// lockDown denies the paths a test asked to be unreadable, last, so the
// readability sweep above cannot undo them. TempDir's own cleanup cannot list a
// mode-000 directory, so each is restored first — Cleanup runs LIFO and TempDir
// registered its removal earlier, so these run before it.
func (p *prodDeploy) lockDown() {
	p.t.Helper()
	for _, path := range p.unreadable {
		path := path
		p.t.Cleanup(func() { _ = os.Chmod(path, 0o755) })
		must(p.t, os.Chmod(path, 0))
	}
}

func (p *prodDeploy) exec(prefix []string, args ...string) (string, int) {
	p.t.Helper()
	repo := filepath.Join(p.root, "repo")
	argv := append(append([]string{}, prefix...),
		append([]string{"bash", filepath.Join(repo, "deploy", "production-deploy.sh")}, args...)...)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = repo
	cmd.Env = append([]string{
		"PATH=" + p.bin + ":/usr/bin:/bin",
		"HOME=" + p.root,
		"REPO=" + repo,
		"BACKUP_DIR=" + p.root,
		"STUB_VOL=" + p.vol,
	}, p.env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		p.t.Fatalf("run: %v\n%s", err, out)
	}
	return string(out), code
}

// The permitted ranges decide whether it is safe to deploy. They must not be
// copied into the bootstrap list, because the bootstrap list is combined with
// the dashboard's permissions by union and a union has no deny rules — so a
// promoted range goes on admitting its clients after the operator unticks the
// box, and the revocation control silently stops working.
func TestPermittedRangesAreNotPromotedIntoTheBootstrapList(t *testing.T) {
	p := newProdDeploy(t)
	p.setenv("STUB_PERMITTED=10.0.10.0/24,192.168.4.0/24")

	out, code := p.run("--dry-run")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "bootstrap ACL set to: 127.0.0.0/8,172.16.0.0/12")
	contains(t, out, "left in the database")
	notContains(t, out, "bootstrap ACL set to: 127.0.0.0/8,172.16.0.0/12,10.0.10.0/24")
}

// The legacy path is the exception, and getting it wrong takes a working
// deployment dark. A database predating allow_resolver migrates every network
// unpermitted, so nothing grants those ranges back: dropping them from .env
// answers REFUSED to every client the deployment was already serving.
func TestLegacyRangesStayInTheBootstrapListBecauseNothingElseGrantsThem(t *testing.T) {
	p := newProdDeploy(t)
	p.setenv("STUB_LEGACY=1", "STUB_ALL=10.0.10.0/24")

	out, code := p.run("--dry-run")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "predates per-network resolver access")
	contains(t, out, "bootstrap ACL set to: 127.0.0.0/8,172.16.0.0/12,10.0.10.0/24")
	// And it says what that costs, rather than quietly leaving them unrevocable.
	contains(t, out, "make them revocable again")
}

// No permitted networks and no explicit opt-in: refuse to deploy rather than
// serve the whole internet.
func TestNoPermittedNetworksFailsClosed(t *testing.T) {
	p := newProdDeploy(t)

	out, code := p.run("--dry-run")
	if code == 0 {
		t.Fatalf("deployed with no client ranges configured\n%s", out)
	}
	contains(t, out, "refusing to deploy an open resolver")
}

// The opt-in path exists, is explicit, and says what it is doing.
func TestPublicResolverRequiresTheExplicitFlag(t *testing.T) {
	p := newProdDeploy(t)

	out, code := p.run("--dry-run", "--allow-public-resolver")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "PUBLIC RESOLVER MODE")
	contains(t, out, "DNSDADDY_ALLOW_PUBLIC_RESOLVER")
}

// The script must not invent ranges from the query log, which on an open
// resolver is full of scanners.
func TestTheQueryLogIsNeverUsedAsASourceOfRanges(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "production-deploy.sh"))
	must(t, err)
	if strings.Contains(string(b), "FROM query_log") || strings.Contains(string(b), "FROM queries") {
		t.Error("the deploy script reads the query log; on a resolver that is currently open " +
			"that whitelists whoever has been abusing it")
	}
}

// A real deploy needs root; only --dry-run is exempt. Without this guard a
// deploy run without sudo half-executes — docker, apt-get and systemctl failing
// one at a time against a live container — instead of refusing up front.
func TestARealDeployStillRefusesToRunWithoutRoot(t *testing.T) {
	p := newProdDeploy(t)
	p.setenv("STUB_PERMITTED=10.0.10.0/24")

	out, code, ok := p.runAsNonRoot() // deliberately not --dry-run
	if !ok {
		t.Skip("cannot reach an unprivileged uid: test process is root and setpriv is missing")
	}
	if code == 0 {
		t.Fatalf("a real deploy ran as an unprivileged user\n%s", out)
	}
	contains(t, out, "run with sudo")
}

// And the dry run is exempt, which is what lets the tests above run at all on a
// CI runner. It says so rather than pretending it is a full deploy.
func TestADryRunDoesNotNeedRoot(t *testing.T) {
	p := newProdDeploy(t)
	p.setenv("STUB_PERMITTED=10.0.10.0/24")

	out, code, ok := p.runAsNonRoot("--dry-run")
	if !ok {
		t.Skip("cannot reach an unprivileged uid: test process is root and setpriv is missing")
	}
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, out, "not running as root")
}

// "*** DRY RUN — nothing will be changed ***" has to be true of the filesystem
// too. On a host with no .env yet, an unguarded touch in step 6 leaves an empty
// one behind; on a host with one, an unguarded chmod restamps its mode. Both
// were invisible while the script could only be run as root against a machine
// it was about to change anyway.
func TestADryRunDoesNotCreateEnv(t *testing.T) {
	p := newProdDeploy(t)
	p.setenv("STUB_PERMITTED=10.0.10.0/24")
	env := filepath.Join(p.root, "repo", ".env")
	must(t, os.Remove(env))

	out, code := p.run("--dry-run")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if _, err := os.Stat(env); !os.IsNotExist(err) {
		t.Errorf("the dry run created .env, having said it would change nothing\n%s", out)
	}
}

// The standard deployment keeps the database in a named volume under Docker's
// root-owned store, so an unprivileged dry run cannot read it however freely it
// may run. What it must not do is call that a wrong path: the old message was
// "this is not the data volume", which sends the operator hunting for a path
// problem they do not have while the database sits right where it belongs. The
// rest of this suite cannot catch it — the fixture is made readable so the
// other tests can run at all.
func TestAnUnreadableVolumeSaysSoRatherThanBlamingThePath(t *testing.T) {
	p := newProdDeploy(t)
	p.setenv("STUB_PERMITTED=10.0.10.0/24")
	p.unreadable = append(p.unreadable, p.vol)

	out, code, ok := p.runAsNonRoot("--dry-run")
	if !ok {
		t.Skip("cannot reach an unprivileged uid: test process is root and setpriv is missing")
	}
	if code == 0 {
		t.Fatalf("dry run claimed to read a volume it has no permission to read\n%s", out)
	}
	contains(t, out, "Docker's own volume directory")
	notContains(t, out, "this is not the data volume")
}
