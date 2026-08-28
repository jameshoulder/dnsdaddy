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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

	// TMPDIR points inside the fixture so that a temp file counts as a write.
	// It did not, and a mktemp added two commits ago sat in a dry run for two
	// review rounds with a test watching the wrong tree: the promise is that
	// the run creates nothing, not that it creates nothing *here*.
	must(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o777))

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
	// The legacy case emits the message a real sqlite3 emits, not a bare
	// non-zero exit. That distinction is the whole point: the script may only
	// treat a failure as "old database" when it can see the column is missing,
	// and a stub that failed silently could not tell the two apart either.
	p.stub("sqlite3", `
q="${@: -1}"
if [[ -n "${STUB_SQL_ERROR:-}" ]]; then
  echo "$STUB_SQL_ERROR" >&2; exit 1
fi
case "$q" in
  *"n.allow_resolver = 1"*)
    if [[ "${STUB_LEGACY:-0}" == "1" ]]; then
      echo "Error: in prepare, no such column: n.allow_resolver (1)" >&2; exit 1
    fi
    printf '%s' "${STUB_PERMITTED:-}" | tr ',' '\n'; exit 0 ;;
  *"n.enabled = 1"*)
    printf '%s' "${STUB_ALL:-}" | tr ',' '\n'; exit 0 ;;
esac
exit 0
`)
	// go is deliberately on this PATH. The script runs `go vet` and `go test`
	// when it finds one, and that branch never ran here — go lives in
	// /usr/local/go/bin, off the harness PATH — while it did run on CI, where
	// it wrote a build cache during a dry run. A stub PATH that cannot reach a
	// command the script looks for hides whatever that branch does.
	if path, err := exec.LookPath("go"); err == nil {
		_ = os.Symlink(path, filepath.Join(p.bin, "go"))
	}
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
	prefix, ok := nonRootPrefix(p.t, p.root)
	if !ok {
		return "", 0, false
	}
	p.lockDown()
	out, code = p.exec(prefix, args...)
	return out, code, true
}

// nonRootPrefix makes tree reachable by an unprivileged uid and returns the
// argv prefix that runs a command as one. Both harnesses in this package need
// it, because this container runs as root and a CI runner does not — a
// difference that once silently disabled four of five tests here. ok is false
// when the test process is root and there is no setpriv to drop with.
//
// Note what the sweep costs: a fixture made wholly readable cannot express
// "readable directory, unreadable file", which is a real deployment shape and
// was a real bug. Deny those paths after calling this, not before.
func nonRootPrefix(t *testing.T, tree string) ([]string, bool) {
	t.Helper()
	if os.Geteuid() != 0 {
		return nil, true
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		return nil, false
	}
	// TempDir hands back <parent>/001 with the parent at 0700, so that one is
	// separate from the walk below.
	must(t, os.Chmod(filepath.Dir(tree), 0o755))
	must(t, filepath.WalkDir(tree, func(path string, d os.DirEntry, err error) error {
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
	return []string{setpriv, "--reuid=65534", "--regid=65534", "--clear-groups"}, true
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
		"TMPDIR=" + filepath.Join(p.root, "tmp"),
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

// The directory being listable says nothing about the database being readable:
// a bind mount can be 0755 over a root-owned 0600 file. Neither -f nor stat
// needs read access, so this case reaches step 4 claiming "database present",
// where sqlite3's suppressed errors turn it into "no client CIDRs configured"
// — telling operators to go and add networks they have already added, about a
// file the script never opened. It fails closed, which is right; it explains
// itself wrongly, which is not.
func TestAnUnreadableDatabaseInAReadableVolumeSaysSo(t *testing.T) {
	p := newProdDeploy(t)
	p.setenv("STUB_PERMITTED=10.0.10.0/24")
	p.unreadable = append(p.unreadable, filepath.Join(p.vol, "dnsdaddy.db"))

	out, code, ok := p.runAsNonRoot("--dry-run")
	if !ok {
		t.Skip("cannot reach an unprivileged uid: test process is root and setpriv is missing")
	}
	if code == 0 {
		t.Fatalf("dry run claimed to read a database it has no permission to read\n%s", out)
	}
	contains(t, out, "not readable by this user")
	notContains(t, out, "database present")
	notContains(t, out, "no client CIDRs configured")
}

// Only one SQLite failure means "this database predates per-network access":
// the column is not there. Everything else — SQLITE_BUSY under a live
// container, a corrupt page, an unreadable -wal sidecar — used to reach the
// same branch, because the query's error was discarded and an empty result
// was taken as proof of an old schema.
//
// That is not a cosmetic misdiagnosis. The legacy branch is the one that puts
// ranges into the bootstrap list, where the dashboard can no longer withdraw
// them, so a transient failure here followed by a working fallback query
// quietly makes every enabled range unrevocable — the same defect a previous
// round of this PR already had to fix once.
func TestASqliteFailureIsNotMistakenForALegacySchema(t *testing.T) {
	p := newProdDeploy(t)
	p.setenv("STUB_SQL_ERROR=Error: database is locked (5)", "STUB_ALL=10.0.10.0/24")

	out, code := p.run("--dry-run")
	if code == 0 {
		t.Fatalf("deployed over a database it could not read\n%s", out)
	}
	contains(t, out, "database is locked")
	notContains(t, out, "predates per-network resolver access")
	notContains(t, out, "bootstrap ACL set to: 127.0.0.0/8,172.16.0.0/12,10.0.10.0/24")
}

// snapshot records every path under dir with the things a mutation would
// change. Enough to catch a create, a delete, a rewrite, a chmod, or a bare
// touch.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	must(t, filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out[rel] = fmt.Sprintf("mode=%v size=%d mtime=%d",
			info.Mode(), info.Size(), info.ModTime().UnixNano())
		return nil
	}))
	return out
}

// "*** DRY RUN — nothing will be changed ***" is a promise the script makes in
// prose, in its own output, at the top of every dry run. Until now nothing
// enforced it, and it was already false twice in this PR's history: step 6's
// touch created an .env on hosts that had none, and its chmod restamped the
// mode of one that did. Both sat outside act(), which is the mechanism the
// promise actually rests on, and both were found by accident rather than by a
// test.
//
// So this asserts the promise directly, over the whole fixture rather than one
// file: no path appears, disappears, or changes mode, size or mtime. A comment
// saying "every mutating step goes through act()" cannot fail; this can.
func TestADryRunChangesNothingOnDisk(t *testing.T) {
	p := newProdDeploy(t)
	p.setenv("STUB_PERMITTED=10.0.10.0/24")

	before := snapshot(t, p.root)
	out, code := p.run("--dry-run")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	after := snapshot(t, p.root)

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

// Step 5 picks the dashboard hostname from four sources in turn, each guarded
// by -f and then read with sed. A file that exists but cannot be read fails
// that read, and the run concluded "no hostname configured" — which is not a
// measurement, it is the absence of one. It then acts on it: Caddy left
// inactive, the dashboard put on loopback, and a raw `sed: can't read` leaked
// into the output as the only clue.
//
// A dry run exists to preview the real run, so a preview that reports a plan
// the real run would not follow is the defect, whatever the exit code.
func TestAnUnreadableHostnameSourceIsNotReportedAsNoHostname(t *testing.T) {
	p := newProdDeploy(t)
	p.setenv("STUB_PERMITTED=10.0.10.0/24")
	p.unreadable = append(p.unreadable, filepath.Join(p.root, "repo", ".env"))

	out, code, ok := p.runAsNonRoot("--dry-run")
	if !ok {
		t.Skip("cannot reach an unprivileged uid: test process is root and setpriv is missing")
	}
	if code == 0 {
		t.Fatalf("the preview finished, having failed to determine the hostname\n%s", out)
	}
	notContains(t, out, "can't read")
	contains(t, out, "could not be read")
	notContains(t, out, "no hostname configured — Caddy will be installed but left inactive")
	// Warning and carrying on is not enough: the steps below the hostname print
	// concrete plans that depend on it, and a preview must not describe a plan
	// the real run may not follow.
	notContains(t, out, "DNSDADDY_SECURE_COOKIES")
	notContains(t, out, "caddy")
}

// The two deploy scripts share a vocabulary — ok, warn, die, step — and each
// has helpers the other lacks: note and pass belong to the installer, act and
// step to production-deploy. Code has moved between them during this change,
// and calling a helper the file does not define is invisible to bash -n, to
// the linters, and to every test that does not reach the branch: it is a
// runtime "command not found".
//
// It is not hypothetical. A warning branch here called note(), which only the
// installer defines, and under set -e that path exited 127 for two commits —
// aborting by accident, in a shape that made the regression test for it pass
// for the wrong reason.
//
// This checks calls written at the start of a line, which is where helpers are
// invoked and where prose mentioning the same word is not. It would have caught
// that bug.
func TestNoScriptCallsAHelperItDoesNotDefine(t *testing.T) {
	repo := repoRoot(t)
	scripts := map[string]string{}
	for _, name := range []string{"install-docker.sh", "production-deploy.sh"} {
		b, err := os.ReadFile(filepath.Join(repo, "deploy", name))
		must(t, err)
		scripts[name] = string(b)
	}

	defines := regexp.MustCompile(`(?m)^([a-z_][a-z0-9_]*)\(\)`)
	calls := regexp.MustCompile(`(?m)^[ \t]*([a-z_][a-z0-9_]*)[ \t]`)

	defined := map[string]map[string]bool{}
	every := map[string]bool{}
	for name, body := range scripts {
		defined[name] = map[string]bool{}
		for _, m := range defines.FindAllStringSubmatch(body, -1) {
			defined[name][m[1]] = true
			every[m[1]] = true
		}
	}

	for name, body := range scripts {
		for i, line := range strings.Split(body, "\n") {
			m := calls.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if every[m[1]] && !defined[name][m[1]] {
				t.Errorf("%s:%d calls %s(), which this script does not define — "+
					"it is defined only in the other one, so this is a runtime "+
					"\"command not found\" in whatever branch reaches it:\n  %s",
					name, i+1, m[1], strings.TrimSpace(line))
			}
		}
	}
}
