package diag

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// REFUSED is the answer at the centre of the reported failure. Reporting it as
// "DNS query failed" would be true and useless: the resolver is running,
// reachable and working correctly, and has declined to serve this address.
func TestResolverReachabilityExplainsRefused(t *testing.T) {
	c := ResolverReachability(ResolverProbe{
		Address:    "192.168.1.75:53",
		Proto:      "udp",
		Rcode:      "REFUSED",
		SourceAddr: "192.168.10.14",
		Elapsed:    2 * time.Millisecond,
	}, []string{"192.168.1.0/24"})

	if c.Status != StatusFail {
		t.Fatalf("status = %s, want fail", c.Status)
	}
	if !strings.Contains(c.Summary, "not permitted to resolve") {
		t.Errorf("summary does not explain the refusal: %q", c.Summary)
	}
	if !strings.Contains(c.Action, "not a network fault") {
		t.Errorf("action does not steer the operator away from chasing the network: %q", c.Action)
	}
	joined := strings.Join(c.Evidence, "\n")
	for _, want := range []string{"192.168.10.14", "192.168.1.0/24"} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence is missing %q:\n%s", want, joined)
		}
	}
}

func TestResolverReachabilityPassesOnNoError(t *testing.T) {
	c := ResolverReachability(ResolverProbe{
		Address: "127.0.0.1:53", Proto: "tcp", Rcode: "NOERROR", Elapsed: time.Millisecond,
	}, nil)
	if c.Status != StatusPass {
		t.Fatalf("status = %s, want pass", c.Status)
	}
}

// Nothing answering is a different problem from something answering REFUSED,
// and conflating them sends the operator to the wrong place.
func TestResolverReachabilityDistinguishesSilence(t *testing.T) {
	c := ResolverReachability(ResolverProbe{
		Address: "192.168.1.75:53", Proto: "udp", Err: errors.New("i/o timeout"),
	}, []string{"192.168.1.0/24"})

	if c.Status != StatusFail {
		t.Fatalf("status = %s, want fail", c.Status)
	}
	if strings.Contains(c.Summary, "REFUSED") {
		t.Errorf("silence was reported as a refusal: %q", c.Summary)
	}
	if !strings.Contains(c.Action, "firewall") {
		t.Errorf("action does not point at reachability: %q", c.Action)
	}
}

// SERVFAIL means reachable-but-cannot-resolve, which belongs to the upstream,
// not to the client ACL.
func TestResolverReachabilitySendsServfailUpstream(t *testing.T) {
	c := ResolverReachability(ResolverProbe{Address: "127.0.0.1:53", Proto: "udp", Rcode: "SERVFAIL"}, nil)
	if c.Status != StatusFail {
		t.Fatalf("status = %s, want fail", c.Status)
	}
	if !strings.Contains(c.Action, "UPSTREAM") {
		t.Errorf("action does not point at the upstream section: %q", c.Action)
	}
}

func TestPortConflictDistinguishesEmptyFromOccupied(t *testing.T) {
	empty := PortConflict("udp", "0.0.0.0:53", true, nil)
	if !strings.Contains(empty.Summary, "Nothing is listening") {
		t.Errorf("a free port was not reported as nothing listening: %q", empty.Summary)
	}

	occupied := PortConflict("udp", "0.0.0.0:53", false, []string{"systemd-resolved (pid 812)"})
	if !strings.Contains(occupied.Summary, "another process") {
		t.Errorf("an occupied port was not reported as a conflict: %q", occupied.Summary)
	}
	if !strings.Contains(occupied.Action, "DNSStubListener") {
		t.Errorf("systemd-resolved was not given its specific remedy: %q", occupied.Action)
	}
	// Disabling resolved outright leaves the machine with no resolver, which
	// is a worse outage than the one being fixed.
	if !strings.Contains(occupied.Action, "another resolver first") {
		t.Errorf("action does not warn against disabling systemd-resolved wholesale: %q", occupied.Action)
	}
}

func TestPortConflictRecognisesOtherResolvers(t *testing.T) {
	c := PortConflict("tcp", "0.0.0.0:53", false, []string{"pihole-FTL (pid 91)"})
	if !strings.Contains(c.Action, "alongside") {
		t.Errorf("Pi-hole was not offered coexistence: %q", c.Action)
	}
}

func TestUpstreamsFailOnlyWhenEveryForwarderIsDown(t *testing.T) {
	partial := Upstreams([]UpstreamProbe{
		{Spec: "tls://9.9.9.9:853", Rcode: "NOERROR", Elapsed: 20 * time.Millisecond},
		{Spec: "tls://1.1.1.1:853", Err: errors.New("i/o timeout")},
	})
	if Worst(partial) != StatusWarn {
		t.Errorf("one dead forwarder of two = %s, want warn — the resolver still works", Worst(partial))
	}

	all := Upstreams([]UpstreamProbe{
		{Spec: "tls://9.9.9.9:853", Err: errors.New("i/o timeout")},
		{Spec: "tls://1.1.1.1:853", Err: errors.New("i/o timeout")},
	})
	if Worst(all) != StatusFail {
		t.Errorf("every forwarder dead = %s, want fail", Worst(all))
	}

	none := Upstreams(nil)
	if Worst(none) != StatusFail {
		t.Errorf("no forwarders configured = %s, want fail", Worst(none))
	}
}

// An empty index is a resolver that works and protects nobody. That is not a
// green state, whatever the health endpoint says.
func TestThreatIndexFailsWhenEmpty(t *testing.T) {
	c := ThreatIndex(0, time.Time{}, time.Now(), 48*time.Hour)
	if c.Status != StatusFail {
		t.Fatalf("status = %s, want fail for an empty index", c.Status)
	}
	if !strings.Contains(c.Summary, "blocking nothing") {
		t.Errorf("summary = %q", c.Summary)
	}
}

// Stale intelligence still enforces last-known-good. Saying otherwise would
// send an operator hunting for an outage that is not happening.
func TestThreatIndexWarnsButDoesNotFailWhenStale(t *testing.T) {
	now := time.Now()
	c := ThreatIndex(400000, now.Add(-96*time.Hour), now, 48*time.Hour)
	if c.Status != StatusWarn {
		t.Fatalf("status = %s, want warn for stale intelligence", c.Status)
	}
	if !strings.Contains(c.Action, "has not stopped") {
		t.Errorf("action does not say protection continues: %q", c.Action)
	}
}

func TestThreatIndexPassesWhenFresh(t *testing.T) {
	now := time.Now()
	c := ThreatIndex(400000, now.Add(-time.Hour), now, 48*time.Hour)
	if c.Status != StatusPass {
		t.Fatalf("status = %s, want pass", c.Status)
	}
}

// A sub-millisecond exchange is the good case. Rounding it to "0s" reads as a
// failure to anybody scanning the output.
func TestFormatElapsedKeepsSubMillisecondPrecision(t *testing.T) {
	if got := formatElapsed(180 * time.Microsecond); got == "0s" {
		t.Errorf("formatElapsed(180µs) = %q, which reads as nothing happening", got)
	}
	if got := formatElapsed(18 * time.Millisecond); got != "18ms" {
		t.Errorf("formatElapsed(18ms) = %q, want 18ms", got)
	}
}

// The suggested `ss` command must name the port that is actually in conflict.
// A resolver on 5353 told to inspect :53 sends the operator to the wrong
// socket and makes the diagnostic look wrong.
func TestPortConflictSuggestsTheRightPort(t *testing.T) {
	c := PortConflict("udp", "0.0.0.0:5353", false, nil)
	if !strings.Contains(c.Action, ":5353") {
		t.Errorf("action does not name the conflicting port: %q", c.Action)
	}
	if strings.Contains(c.Action, ":53 ") || strings.Contains(c.Action, ":53`") {
		t.Errorf("action still hardcodes port 53: %q", c.Action)
	}
}

// UDP and TCP conflicts on the same address are two findings, and a consumer
// reading the JSON must be able to tell them apart.
func TestPortConflictNamesTheProtocol(t *testing.T) {
	udp := PortConflict("udp", "0.0.0.0:53", true, nil)
	tcp := PortConflict("tcp", "0.0.0.0:53", true, nil)
	if udp.Name == tcp.Name {
		t.Errorf("both protocols produced the same check name %q", udp.Name)
	}
}

// An upstream that answers is not necessarily an upstream that works. One
// returning REFUSED or SERVFAIL to everything is reachable and useless, and a
// connection-only probe could not tell the difference.
func TestUpstreamsTreatANonSuccessRcodeAsUnusable(t *testing.T) {
	for _, rcode := range []string{"REFUSED", "SERVFAIL"} {
		t.Run(rcode, func(t *testing.T) {
			checks := Upstreams([]UpstreamProbe{{Spec: "udp://10.0.0.1:53", Rcode: rcode}})
			if Worst(checks) == StatusPass {
				t.Fatalf("an upstream answering %s was reported as healthy", rcode)
			}
			if !strings.Contains(checks[0].Summary, rcode) {
				t.Errorf("summary does not name the rcode: %q", checks[0].Summary)
			}
			if !strings.Contains(checks[0].Action, "not a firewall") {
				t.Errorf("action does not distinguish this from a reachability problem: %q", checks[0].Action)
			}
		})
	}

	// And the tally must count it: every upstream answering REFUSED means no
	// name resolves, which is a failure, not a pair of warnings.
	all := Upstreams([]UpstreamProbe{
		{Spec: "udp://10.0.0.1:53", Rcode: "REFUSED"},
		{Spec: "udp://10.0.0.2:53", Rcode: "SERVFAIL"},
	})
	if Worst(all) != StatusFail {
		t.Errorf("Worst = %s, want fail when no upstream can resolve anything", Worst(all))
	}
}

// This check exists to catch one thing: a management port reachable from the
// internet in plaintext. It must be silent otherwise, because a LAN dashboard
// over plain HTTP is a supported deployment and a diagnostic that cries wolf
// gets ignored on the day it is right.
func TestManagementExposureIsSilentWithoutEvidence(t *testing.T) {
	c := ManagementExposure(0, "")
	if c.Status != StatusPass {
		t.Fatalf("status = %s, want pass when nothing public has been observed", c.Status)
	}
	if c.Action != "" {
		t.Errorf("a passing check carries an action the renderer will not print: %q", c.Action)
	}
}

func TestManagementExposureReportsObservedPublicPlaintextAccess(t *testing.T) {
	c := ManagementExposure(3, "203.0.113.9")

	if c.Status != StatusFail {
		t.Fatalf("status = %s, want fail", c.Status)
	}
	if !strings.Contains(c.Summary, "unencrypted") {
		t.Errorf("summary does not say what is at stake: %q", c.Summary)
	}
	if !strings.Contains(strings.Join(c.Evidence, " "), "203.0.113.9") {
		t.Errorf("evidence does not name the source the operator has to recognise: %v", c.Evidence)
	}
	// Docker's port publishing bypasses ufw, so "add a firewall rule" is not a
	// fix here and the action must not let the operator believe it is.
	if !strings.Contains(c.Action, "bypasses ufw") {
		t.Errorf("action does not warn that a host firewall rule will not close this: %q", c.Action)
	}
	// Anything that crossed the internet in the clear should be assumed seen.
	if !strings.Contains(c.Action, "password") {
		t.Errorf("action does not tell the operator to rotate the credential: %q", c.Action)
	}
}
