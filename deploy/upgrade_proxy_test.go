package deploy

import (
	"strings"
	"testing"
)

func managedProxyEnv(proxy string) string {
	return "# managed by install-docker.sh\nDNSDADDY_BASE_URL=https://dns.example.test\n" +
		"# managed by install-docker.sh\nDNSDADDY_SECURE_COOKIES=always\n" +
		"# managed by install-docker.sh\nDNSDADDY_TRUSTED_PROXY_CIDRS=" + proxy + "\n"
}

func TestUpgradeRepairsManagedHTTPSProxyGateway(t *testing.T) {
	in := newInstall(t)
	in.writeEnv(managedProxyEnv("172.17.0.0/16") + "TZ=Europe/London\n")
	in.setenv("STUB_PROXY_GATEWAYS=172.23.0.1\nfd12:3456::1\n172.23.0.1")
	out, code := in.run("--upgrade", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	contains(t, in.readEnv(), "DNSDADDY_TRUSTED_PROXY_CIDRS=172.23.0.1/32,fd12:3456::1/128")
	contains(t, in.readEnv(), "DNSDADDY_SECURE_COOKIES=always")
	contains(t, in.readEnv(), "TZ=Europe/London")
	contains(t, out, "Trusted proxy set to the container gateway")
	if strings.Count(in.composeLog(), "compose up -d") != 2 {
		t.Fatalf("expected build and settings recreation:\n%s", in.composeLog())
	}
	before := in.readEnv()
	out, code = in.run("--upgrade", "--yes")
	if code != 0 || before != in.readEnv() {
		t.Fatalf("repeat changed managed settings: exit %d\n%s", code, out)
	}
}

func TestUpgradePreservesCustomProxyTopology(t *testing.T) {
	for _, extra := range []string{
		"DNSDADDY_TRUSTED_PROXY_CIDRS=192.0.2.8/32\n",     // the last assignment is operator-owned
		"DNSDADDY_BASE_URL=https://custom.example.test\n", // no evidence this is installer-owned HTTPS
	} {
		in := newInstall(t)
		original := managedProxyEnv("172.17.0.0/16") + extra
		in.writeEnv(original)
		out, code := in.run("--upgrade", "--yes")
		if code != 0 || in.readEnv() != original {
			t.Fatalf("changed custom topology: exit %d\n%s", code, out)
		}
	}
}

func TestUpgradeProxyDryRunDoesNotWrite(t *testing.T) {
	in := newInstall(t)
	original := managedProxyEnv("172.17.0.0/16")
	in.writeEnv(original)
	out, code := in.run("--upgrade", "--yes", "--dry-run")
	if code != 0 || in.readEnv() != original {
		t.Fatalf("dry run mutated .env: exit %d\n%s", code, out)
	}
	contains(t, out, "Would reconcile installer-managed HTTPS proxy trust")
	if strings.Contains(in.composeLog(), "compose up") {
		t.Fatal("dry run started a container")
	}
}

func TestUpgradeMissingGatewayIsNotReportedAsRepaired(t *testing.T) {
	for _, gateway := range []string{"", "not-an-address", "0.0.0.0", "::"} {
		in := newInstall(t)
		original := managedProxyEnv("172.17.0.0/16")
		in.writeEnv(original)
		in.setenv("STUB_PROXY_GATEWAYS=" + gateway)
		out, code := in.run("--upgrade", "--yes")
		if code == 0 {
			t.Fatalf("unknown gateway finished successfully:\n%s", out)
		}
		if in.readEnv() != original {
			t.Fatal("unknown gateway must not replace trust settings")
		}
	}
}

func TestUpgradeDoesNotInferProxyForTunnelInstall(t *testing.T) {
	in := newInstall(t)
	original := "TZ=UTC\n"
	in.writeEnv(original)
	out, code := in.run("--upgrade", "--yes")
	if code != 0 || in.readEnv() != original {
		t.Fatalf("inferred a proxy: exit %d\n%s", code, out)
	}
}

func TestUpgradePreservesExplicitEnvironmentProxyOverride(t *testing.T) {
	in := newInstall(t)
	original := managedProxyEnv("172.17.0.0/16")
	in.writeEnv(original)
	in.setenv("DNSDADDY_TRUSTED_PROXY_CIDRS=192.0.2.25/32")
	out, code := in.run("--upgrade", "--yes")
	if code != 0 || in.readEnv() != original {
		t.Fatalf("changed overridden proxy: exit %d\n%s", code, out)
	}
	contains(t, out, "environment override")
}
