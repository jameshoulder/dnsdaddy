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
	repo := filepath.Join(p.root, "repo")
	cmd := exec.Command("bash", append([]string{filepath.Join(repo, "deploy", "production-deploy.sh")}, args...)...)
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
