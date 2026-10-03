package deploy

import (
	"os/exec"
	"runtime"
	"testing"
)

// Host tooling is not a resolver runtime dependency. On Linux, exercise the
// actual helper's deterministic offline tests in the normal repository suite.
func TestHostNetworkHandoffChecks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the host installer targets Linux")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatal("Python 3 is required to validate the Linux host installer")
	}
	output, err := exec.Command("python3", "-m", "unittest", "-v", "test_docker_network.py").CombinedOutput()
	if err != nil {
		t.Fatalf("host network tests: %v\n%s", err, output)
	}
	for _, file := range []string{"../install.sh", "install-docker.sh"} {
		output, err := exec.Command("bash", "-n", file).CombinedOutput()
		if err != nil {
			t.Fatalf("shell syntax %s: %v\n%s", file, err, output)
		}
	}
}

func TestComposePassesHostHintWithoutPinningOperatorSettings(t *testing.T) {
	env := loadCompose(t, "docker-compose.yml")["dnsdaddy"].Environment
	value, present := env["DNSDADDY_DEPLOYMENT_DNS"]
	if !present || value != nil {
		t.Fatal("the host hint must be an optional pass-through, not a guessed Compose default")
	}
}
