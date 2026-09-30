package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Drive the real check using synthetic command responses; these tests never
// query external DNS or inspect a real Docker daemon.
func newHealthcheck(t *testing.T) *install {
	t.Helper()
	in := newInstall(t)
	copyFile(t, filepath.Join(repoRoot(t), "deploy", "healthcheck.sh"),
		filepath.Join(in.root, "deploy", "healthcheck.sh"), 0o755)
	in.stub("docker", `
[[ "${2:-}" == "${STUB_EXPECT_CONTAINER:-dnsdaddy}" ]] || exit 1
case "$1" in
  inspect)
    case "$*" in
      *State.Status*) echo running ;;
      *State.Health*) echo healthy ;;
      *RestartCount*) echo 0 ;;
    esac ;;
  exec)
    if [[ -v STUB_HEALTH_DETAIL ]]; then printf '%s' "$STUB_HEALTH_DETAIL"
    else printf '{"status":"ok","protecting":true,"blocklistSize":100}\n'; fi ;;
esac`)
	in.stub("curl", `printf '{"status":"ok"}\n'`)
	in.stub("dig", `
printf '%s\n' "$*" >> "$STUB_LOG"
rcode="${STUB_UDP_RCODE:-NOERROR}"
[[ " $* " == *" +tcp "* ]] && rcode="${STUB_TCP_RCODE:-NOERROR}"
[[ "$rcode" == "TIMEOUT" ]] && exit 9
printf ';; ->>HEADER<<- opcode: QUERY, status: %s, id: 1\n' "$rcode"
if [[ "$rcode" == "NOERROR" ]]; then
  printf 'example.com. 60 IN A %s\n' "${STUB_ANSWER:-203.0.113.10}"
fi`)
	return in
}

func runHealthcheck(t *testing.T, in *install, args ...string) (string, int) {
	t.Helper()
	argv := append([]string{filepath.Join(in.root, "deploy", "healthcheck.sh")}, args...)
	cmd := exec.Command("bash", argv...)
	cmd.Dir = in.root
	cmd.Env = append([]string{"PATH=" + in.bin, "STUB_LOG=" + filepath.Join(in.root, "compose.log")}, in.env...)
	b, err := cmd.CombinedOutput()
	if err == nil {
		return string(b), 0
	}
	if e, ok := err.(*exec.ExitError); ok {
		return string(b), e.ExitCode()
	}
	t.Fatalf("run health check: %v\n%s", err, b)
	return "", -1
}

func TestHealthcheckRequiresBothDNSProtocolsAndBlocklistEvidence(t *testing.T) {
	cases := []struct {
		name       string
		env        []string
		missingDig bool
		code       int
		want       string
	}{
		{name: "complete", want: "RESULT: ready — UDP/TCP DNS answering and blocklist loaded"},
		{name: "dig missing", missingDig: true, code: 1, want: "DNS readiness was not checked"},
		{name: "private health fields unavailable", env: []string{`STUB_HEALTH_DETAIL={"status":"ok"}`}, code: 1, want: "could not read the blocklist state"},
		{name: "cold feeds", env: []string{`STUB_HEALTH_DETAIL={"status":"ok","protecting":false,"blocklistSize":0}`}, code: 1, want: "blocklist is empty"},
		{name: "UDP failure", env: []string{"STUB_UDP_RCODE=SERVFAIL"}, code: 2, want: "udp DNS returned SERVFAIL"},
		{name: "TCP port not published", env: []string{"STUB_TCP_RCODE=TIMEOUT"}, code: 2, want: "no tcp DNS response"},
		{name: "client ACL refusal", env: []string{"STUB_UDP_RCODE=REFUSED", "STUB_TCP_RCODE=REFUSED"}, code: 2, want: "not permitted to use the resolver"},
		{name: "blocked positive probe", env: []string{"STUB_UDP_RCODE=NXDOMAIN", "STUB_TCP_RCODE=NXDOMAIN"}, code: 1, want: "is the probe domain blocked?"},
		{name: "sinkhole positive probe", env: []string{"STUB_ANSWER=0.0.0.0"}, code: 1, want: "sinkhole address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := newHealthcheck(t)
			in.setenv(tc.env...)
			if tc.missingDig {
				must(t, os.Remove(filepath.Join(in.bin, "dig")))
			}
			out, code := runHealthcheck(t, in)
			if code != tc.code {
				t.Fatalf("exit=%d want=%d\n%s", code, tc.code, out)
			}
			contains(t, out, tc.want)
			if code != 0 {
				notContains(t, out, "RESULT: ready")
			}
			if !tc.missingDig {
				calls := in.composeLog()
				contains(t, calls, "+notcp")
				contains(t, calls, "+tcp")
			}
		})
	}
}

func TestHealthcheckUsesTheChosenContainerForPrivateHealth(t *testing.T) {
	in := newHealthcheck(t)
	in.setenv("DNSDADDY_CONTAINER=custom-resolver", "STUB_EXPECT_CONTAINER=custom-resolver")
	out, code := runHealthcheck(t, in)
	if code != 0 {
		t.Fatalf("custom container's private health was not checked: exit=%d\n%s", code, out)
	}
	contains(t, out, "blocklist loaded (100 domains)")
}

func TestHealthcheckQuietOnlySuppressesVerifiedReadiness(t *testing.T) {
	in := newHealthcheck(t)
	out, code := runHealthcheck(t, in, "--quiet")
	if code != 0 || out != "" {
		t.Fatalf("healthy quiet output: code=%d out=%q", code, out)
	}
	must(t, os.Remove(filepath.Join(in.bin, "dig")))
	out, code = runHealthcheck(t, in, "--quiet")
	if code != 1 || !strings.Contains(out, "DNS readiness was not checked") {
		t.Fatalf("quiet mode hid an unverified DNS service: code=%d out=%q", code, out)
	}
}
