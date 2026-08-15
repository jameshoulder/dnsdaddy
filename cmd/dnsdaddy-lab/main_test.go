package main

import (
	"math/rand"
	"net"
	"strings"
	"testing"
)

// checkTarget is a safety control, not a convenience. It exists to stop
// synthetic attack traffic being written into a real security database, where
// it would be indistinguishable from genuine detections. That makes it worth
// testing properly rather than trusting to inspection.
func TestCheckTargetRefusesProductionPorts(t *testing.T) {
	for _, target := range []string{
		"127.0.0.1:53",   // plain DNS on loopback — the dangerous default we removed
		"127.0.0.1:853",  // DNS-over-TLS
		"192.168.1.1:53", // a router or a real resolver on the LAN
		"10.0.0.5:853",
		"[::1]:53", // the IPv6 form must be caught too
	} {
		t.Run(target, func(t *testing.T) {
			err := checkTarget(target, false)
			if err == nil {
				t.Fatalf("checkTarget(%q) allowed a standard DNS port", target)
			}
			// The error has to tell the operator how to proceed deliberately,
			// or they will reach for a worse workaround.
			if !strings.Contains(err.Error(), "-allow-production-target") {
				t.Errorf("refusal does not mention the opt-in flag: %v", err)
			}
			if !strings.Contains(err.Error(), defaultLabResolver) {
				t.Errorf("refusal does not point at the lab resolver: %v", err)
			}
		})
	}
}

// The opt-in has to actually work, or somebody with a legitimate throwaway
// instance will patch the binary or the guard instead.
func TestCheckTargetHonoursExplicitOptIn(t *testing.T) {
	for _, target := range []string{"127.0.0.1:53", "127.0.0.1:853", "[::1]:53"} {
		if err := checkTarget(target, true); err != nil {
			t.Errorf("checkTarget(%q, allow=true) refused: %v", target, err)
		}
	}
}

func TestCheckTargetAllowsLabPorts(t *testing.T) {
	for _, target := range []string{
		defaultLabResolver, // the shipped default must never be refused
		"127.0.0.1:5353",   // `make run`
		"127.0.0.1:15353",  // the CI smoke test
		"172.30.0.20:5353", // the compose lab, non-loopback by design
	} {
		if err := checkTarget(target, false); err != nil {
			t.Errorf("checkTarget(%q) refused a lab target: %v", target, err)
		}
	}
}

// The shipped default is the whole point of the change: a bare invocation must
// not be able to reach a production resolver.
func TestDefaultTargetIsNotAProductionPort(t *testing.T) {
	if err := checkTarget(defaultLabResolver, false); err != nil {
		t.Fatalf("the default target is refused by its own guard: %v", err)
	}
	_, port, _ := splitForTest(defaultLabResolver)
	if productionDNSPorts[port] {
		t.Errorf("defaultLabResolver %q uses standard DNS port %s", defaultLabResolver, port)
	}
}

func TestCheckTargetRejectsMalformedAddresses(t *testing.T) {
	for _, target := range []string{"", "not-an-address", "127.0.0.1", "::1"} {
		if err := checkTarget(target, false); err == nil {
			t.Errorf("checkTarget(%q) accepted a malformed address", target)
		}
	}
}

// Every scenario must stay inside the reserved namespaces. A scenario that
// started emitting a real domain would send synthetic attack traffic at
// somebody else's infrastructure, which is the one thing the lab promises it
// will never do.
func TestEveryScenarioUsesReservedDomainsOnly(t *testing.T) {
	for name, sc := range scenarios {
		t.Run(name, func(t *testing.T) {
			for _, q := range sc.Build(newRandForTest(1)) {
				if !isReservedName(q.name) {
					t.Errorf("scenario %s emits %q, which is not under a reserved TLD "+
						"(.example / .test per RFC 2606 and RFC 6761)", name, q.name)
				}
			}
		})
	}
}

// The responder's zone must be reserved for the same reason.
func TestLabZonesAreReserved(t *testing.T) {
	for zone := range labZones {
		if !isReservedName(zone) {
			t.Errorf("lab zone %q is not under a reserved TLD", zone)
		}
	}
}

// Determinism is what makes a demonstration reproducible and the CI assertion
// non-flaky, so it is asserted rather than assumed.
func TestScenariosAreDeterministic(t *testing.T) {
	for name, sc := range scenarios {
		a := sc.Build(newRandForTest(7))
		b := sc.Build(newRandForTest(7))
		if len(a) != len(b) {
			t.Fatalf("%s: same seed produced %d then %d queries", name, len(a), len(b))
		}
		for i := range a {
			if a[i].name != b[i].name || a[i].qtype != b[i].qtype || a[i].at != b[i].at {
				t.Fatalf("%s: same seed diverged at query %d", name, i)
				return
			}
		}
	}
}

func isReservedName(name string) bool {
	return strings.HasSuffix(name, ".example") || strings.HasSuffix(name, ".test")
}

// newRandForTest and splitForTest keep the tests from duplicating the
// production helpers' internals.
func newRandForTest(seed int64) *rand.Rand { return rand.New(rand.NewSource(seed)) }

func splitForTest(addr string) (host, port string, err error) { return net.SplitHostPort(addr) }
