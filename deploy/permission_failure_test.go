package deploy

import (
	"os"
	"strings"
	"testing"
)

func TestPermissionFailureStopsInstallAndUpgradeBeforeComposeChanges(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		for _, noOp := range []bool{false, true} {
			in := newInstall(t)
			in.writeEnv("DNSDADDY_ADMIN_PASSWORD=fixture-only\n")
			body := "exit 1"
			if noOp {
				body = "exit 0"
			}
			in.stub("chmod", body)
			args := []string{"--yes"}
			if upgrade {
				args = append(args, "--upgrade")
			}
			out, code := in.run(args...)
			if code == 0 {
				t.Fatalf("upgrade=%v noop=%v accepted unprotected file:\n%s", upgrade, noOp, out)
			}
			if strings.Contains(out, "fixture-only") {
				t.Fatal("failure output leaked the secret")
			}
			log, err := os.ReadFile(in.root + "/compose.log")
			must(t, err)
			for _, forbidden := range []string{"compose up", "compose down", "compose restart", "compose build"} {
				if strings.Contains(string(log), forbidden) {
					t.Fatalf("permission failure reached %s", forbidden)
				}
			}
		}
	}
}
