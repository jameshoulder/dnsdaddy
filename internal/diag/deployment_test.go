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
