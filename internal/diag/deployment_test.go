package diag

import "testing"

// The property that matters most, and the one a naive exposure check gets
// backwards: a dashboard on loopback is the correct, intended state for both
// public deployment modes. Reporting it as a failure would teach operators to
// "fix" the single thing keeping the management API off the internet.
func TestALoopbackDashboardIsNeverAFailure(t *testing.T) {
	for _, in := range []DeploymentInput{
		{Listen: "127.0.0.1:8080"},
		{Listen: "127.0.0.1:8080", BaseURL: "https://admin.example.com", SecureCookies: "always",
			TrustedProxyCIDRs: []string{"172.17.0.0/16"}},
		{Listen: "[::1]:8080"},
	} {
		for _, c := range Deployment(in) {
			if c.Status == StatusFail {
				t.Errorf("listen=%q baseURL=%q reported FAIL: %s", in.Listen, in.BaseURL, c.Summary)
			}
		}
	}
}

func TestTunnelAndProxiedModesAreToldApart(t *testing.T) {
	tunnel := Classify(DeploymentInput{Listen: "127.0.0.1:8080"})
	if tunnel != ModeTunnel {
		t.Errorf("loopback with no base URL = %q, want %q", tunnel, ModeTunnel)
	}
	proxied := Classify(DeploymentInput{Listen: "127.0.0.1:8080", BaseURL: "https://admin.example.com"})
	if proxied != ModeProxied {
		t.Errorf("loopback behind TLS = %q, want %q", proxied, ModeProxied)
	}
	// The distinction is the point: the tunnel summary must not claim a public
	// URL exists, and the proxied one must name it.
	tc := Deployment(DeploymentInput{Listen: "127.0.0.1:8080"})[0]
	if got := tc.Summary; !contains(got, "SSH tunnel") {
		t.Errorf("tunnel summary does not mention the tunnel: %q", got)
	}
	pc := Deployment(DeploymentInput{Listen: "127.0.0.1:8080", BaseURL: "https://admin.example.com", SecureCookies: "always"})[0]
	if got := pc.Summary; !contains(got, "https://admin.example.com") {
		t.Errorf("proxied summary does not name the public URL: %q", got)
	}
}

func TestAPubliclyBoundDashboardIsAFailure(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8080", ":8080", "203.0.113.9:8080", "[::]:8080"} {
		checks := Deployment(DeploymentInput{Listen: listen})
		if checks[0].Status != StatusFail {
			t.Errorf("listen=%q reported %v, want FAIL: %s", listen, checks[0].Status, checks[0].Summary)
		}
	}
}

// A LAN bind is a deliberate trade-off, not a defect. It passes, and says what
// the trade-off is rather than leaving the operator to infer it.
func TestALANBindPassesButStatesTheTradeOff(t *testing.T) {
	c := Deployment(DeploymentInput{Listen: "192.168.1.75:8080"})[0]
	if c.Status != StatusPass {
		t.Fatalf("LAN bind reported %v: %s", c.Status, c.Summary)
	}
	if c.Action == "" {
		t.Error("a LAN bind should say what it trades away")
	}
}

// Behind TLS, a cookie without Secure is a real weakening — but not a reason
// to call the deployment broken.
func TestProxiedWithoutSecureCookiesWarns(t *testing.T) {
	c := Deployment(DeploymentInput{
		Listen: "127.0.0.1:8080", BaseURL: "https://admin.example.com", SecureCookies: "auto",
	})[0]
	if c.Status != StatusWarn {
		t.Fatalf("status = %v, want WARN: %s", c.Status, c.Summary)
	}
	if !contains(c.Action, "always") {
		t.Errorf("the action should name the setting to change: %q", c.Action)
	}
}

// Trusting everything is worse than trusting nothing: it believes whatever a
// client asserts.
func TestTrustingEveryPeerIsAFailure(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		checks := Deployment(DeploymentInput{
			Listen: "127.0.0.1:8080", BaseURL: "https://x.example.com", SecureCookies: "always",
			TrustedProxyCIDRs: []string{cidr},
		})
		found := false
		for _, c := range checks {
			if c.Name == "Proxy trust" {
				found = true
				if c.Status != StatusFail {
					t.Errorf("trusted_proxy_cidrs=%q reported %v, want FAIL", cidr, c.Status)
				}
			}
		}
		if !found {
			t.Errorf("no proxy-trust check emitted for %q", cidr)
		}
	}
}

// Proxy trust is only asked about when there is a proxy. Without one, trusting
// no forwarding header is correct and must not be nagged about.
func TestProxyTrustIsNotReportedWithoutAProxy(t *testing.T) {
	for _, c := range Deployment(DeploymentInput{Listen: "127.0.0.1:8080"}) {
		if c.Name == "Proxy trust" {
			t.Errorf("tunnel mode should not report proxy trust: %s", c.Summary)
		}
	}
}

// Measurement beats inference: a request that actually arrived in plaintext
// from the internet outranks a configuration that says it cannot happen.
func TestObservedPlaintextRequestsOverrideACleanConfiguration(t *testing.T) {
	c := Deployment(DeploymentInput{Listen: "127.0.0.1:8080", PublicPlaintextRequests: 3})[0]
	if c.Status != StatusFail {
		t.Fatalf("status = %v, want FAIL: %s", c.Status, c.Summary)
	}
	if !contains(c.Summary, "3 management request") {
		t.Errorf("the count should be in the summary: %q", c.Summary)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// ---------------------------------------------------------------------------
// Container awareness.
//
// From a real Debian 13 VPS running the Docker deployment: Compose published
// the dashboard as 127.0.0.1:8080:8080, Caddy proxied :443 to it, and external
// probing proved host port 8080 was not reachable from the internet. `docker
// compose exec dnsdaddy dnsdaddy doctor` nevertheless reported
//
//	[FAIL] Bound to :8080, which publishes the management API beyond this machine.
//
// which was false. These pin both halves of the correction: the container case
// stops being a definite failure, and nothing else starts being a pass.
// ---------------------------------------------------------------------------

func TestNativeWildcardAndPublicBindsStayFailures(t *testing.T) {
	// The strict half. A host process really does publish these, and none of
	// the container work below is allowed to soften them.
	for _, listen := range []string{":8080", "0.0.0.0:8080", "203.0.113.10:8080", "[::]:8080"} {
		got := Deployment(DeploymentInput{Listen: listen, Runtime: RuntimeHost})[0]
		if got.Status != StatusFail {
			t.Errorf("native listen=%q reported %s, want FAIL: %s", listen, got.Status, got.Summary)
		}
	}
	// The zero value of Runtime must behave as the host: an input that forgot
	// to set it must not be the thing that relaxes the finding.
	if got := Deployment(DeploymentInput{Listen: ":8080"})[0]; got.Status != StatusFail {
		t.Errorf("listen=\":8080\" with an unset Runtime reported %s, want FAIL", got.Status)
	}
}

func TestNativeLoopbackStaysAPass(t *testing.T) {
	got := Deployment(DeploymentInput{Listen: "127.0.0.1:8080", Runtime: RuntimeHost})[0]
	if got.Status != StatusPass {
		t.Errorf("native loopback reported %s, want PASS: %s", got.Status, got.Summary)
	}
}

func TestContainerWildcardIsUnknownNotFailure(t *testing.T) {
	got := Deployment(DeploymentInput{Listen: ":8080", Runtime: RuntimeContainer})[0]
	if got.Status == StatusFail {
		t.Fatalf("container-internal :8080 reported FAIL: %s", got.Summary)
	}
	if got.Status != StatusWarn {
		t.Fatalf("container-internal :8080 reported %s, want WARN", got.Status)
	}
	// It has to say why it cannot tell, or the warning is just noise the
	// operator will learn to skip.
	for _, want := range []string{"inside the container", "cannot be proven"} {
		if !contains(got.Summary, want) {
			t.Errorf("summary does not explain the limit (%q missing): %q", want, got.Summary)
		}
	}
	// And it must not send the reader towards the fix that breaks Docker.
	if !contains(got.Action, "Do not") || !contains(got.Action, "127.0.0.1 inside the") {
		t.Errorf("action does not warn against binding loopback inside the container: %q", got.Action)
	}
}

func TestContainerWithAPublicAddressIsStillAFailure(t *testing.T) {
	// Being in a container excuses a wildcard, not a specific public address:
	// no host mapping makes 203.0.113.10 private, and typing it is a request
	// to publish.
	got := Deployment(DeploymentInput{Listen: "203.0.113.10:8080", Runtime: RuntimeContainer})[0]
	if got.Status != StatusFail {
		t.Errorf("container bound to a public address reported %s, want FAIL: %s", got.Status, got.Summary)
	}
}

// The deployment that was being misreported, end to end: the container as the
// installer configures it for HTTPS mode. It must not come out as NOT READY.
func TestContainerBehindTLSIsNotReportedAsFailing(t *testing.T) {
	checks := Deployment(DeploymentInput{
		Listen:            ":8080",
		BaseURL:           "https://198.51.100.7",
		SecureCookies:     "always",
		TrustedProxyCIDRs: []string{"172.18.0.0/16"},
		Runtime:           RuntimeContainer,
	})
	if w := Worst(checks); w == StatusFail {
		for _, c := range checks {
			if c.Status == StatusFail {
				t.Errorf("FAIL from %q: %s", c.Name, c.Summary)
			}
		}
		t.Fatal("a correctly deployed HTTPS container is reported as failing")
	}
}

// The proxy-trust check keyed on ModeProxied, which is loopback-only. Once a
// container's wildcard bind stopped classifying as ModeProxied the check would
// have silently disappeared for the deployment that most needs it — and a
// check that vanishes reads exactly like one that passed.
func TestProxyTrustStillRunsForAContainerBehindTLS(t *testing.T) {
	find := func(checks []Check, name string) (Check, bool) {
		for _, c := range checks {
			if c.Name == name {
				return c, true
			}
		}
		return Check{}, false
	}

	// No trusted proxy configured: the warning must still be raised.
	checks := Deployment(DeploymentInput{
		Listen: ":8080", BaseURL: "https://198.51.100.7", SecureCookies: "always",
		Runtime: RuntimeContainer,
	})
	c, ok := find(checks, "Proxy trust")
	if !ok {
		t.Fatal("no proxy-trust check for a container behind TLS")
	}
	if c.Status != StatusWarn {
		t.Errorf("missing trusted_proxy_cidrs reported %s, want WARN", c.Status)
	}

	// Trusting everything must still be a failure, container or not.
	checks = Deployment(DeploymentInput{
		Listen: ":8080", BaseURL: "https://198.51.100.7", SecureCookies: "always",
		TrustedProxyCIDRs: []string{"0.0.0.0/0"}, Runtime: RuntimeContainer,
	})
	c, ok = find(checks, "Proxy trust")
	if !ok {
		t.Fatal("no proxy-trust check when every peer is trusted")
	}
	if c.Status != StatusFail {
		t.Errorf("trusting 0.0.0.0/0 reported %s, want FAIL", c.Status)
	}
}

func TestContainerBehindTLSStillChecksSecureCookies(t *testing.T) {
	got := Deployment(DeploymentInput{
		Listen: ":8080", BaseURL: "https://198.51.100.7", SecureCookies: "auto",
		TrustedProxyCIDRs: []string{"172.18.0.0/16"}, Runtime: RuntimeContainer,
	})[0]
	if got.Status != StatusWarn {
		t.Fatalf("cookies not marked Secure behind TLS reported %s, want WARN", got.Status)
	}
	if !contains(got.Summary, "Secure") {
		t.Errorf("summary does not mention the cookie flag: %q", got.Summary)
	}
}

// Observation outranks inference, and being in a container does not change
// that. A plaintext management request that actually arrived from a public
// address is proof the host mapping is wide open, which is the one thing the
// container case is otherwise unable to establish.
func TestObservedPublicPlaintextIsAFailureEvenInAContainer(t *testing.T) {
	for _, rt := range []Runtime{RuntimeHost, RuntimeContainer} {
		got := Deployment(DeploymentInput{
			Listen:                  ":8080",
			Runtime:                 rt,
			PublicPlaintextRequests: 3,
		})[0]
		if got.Status != StatusFail {
			t.Errorf("runtime=%s with observed public plaintext reported %s, want FAIL: %s",
				rt, got.Status, got.Summary)
		}
	}
	// Including the case that would otherwise be a clean pass.
	got := Deployment(DeploymentInput{
		Listen: "127.0.0.1:8080", Runtime: RuntimeContainer, PublicPlaintextRequests: 1,
	})[0]
	if got.Status != StatusFail {
		t.Errorf("loopback with observed public plaintext reported %s, want FAIL", got.Status)
	}
}

// WARN must not become a non-zero exit. doctor returns an error only on FAIL,
// and a container that is correctly deployed would otherwise start failing CI
// and health checks for a state that is merely unproven.
func TestContainerWarningDoesNotBecomeAFailingWorst(t *testing.T) {
	checks := Deployment(DeploymentInput{Listen: ":8080", Runtime: RuntimeContainer})
	if got := Worst(checks); got != StatusWarn {
		t.Errorf("worst status for a container-internal bind = %s, want WARN", got)
	}
}
