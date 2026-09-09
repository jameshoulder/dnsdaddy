package config

import (
	"strings"
	"testing"
	"time"
)

// TestTheShippedConfigLeavesTheModeToTheInstallation.
//
// Not a mode, deliberately. Load unmarshals YAML over Default(), so any mode
// chosen here would be indistinguishable afterwards from one the operator
// wrote — and the right answer differs between a new install and an upgrade.
// The config layer therefore expresses "unset" and lets ResolveLocalDNSSEC
// settle it against the installation record.
func TestTheShippedConfigLeavesTheModeToTheInstallation(t *testing.T) {
	cfg := Default()
	if cfg.DNS.LocalDNSSECConfigured() {
		t.Fatalf("the shipped config pins a mode (%q); an upgrade could not then tell it from the operator's own choice",
			cfg.DNS.LocalDNSSECValidation)
	}
	// Unresolved reads as off. A caller that forgets to resolve gets a
	// validator that does nothing rather than one that starts querying.
	if cfg.DNS.ObserveDNSSEC() {
		t.Fatal("an unresolved configuration already reports as observing")
	}
}

// TestAFreshInstallRunsLearn is the product default.
//
// Learn is safe to switch on for someone who has just installed DNS Daddy:
// it runs out of band, records what it concludes and can never alter a client
// response. What it is not safe to do is arrive unannounced on a machine that
// has been running for a year, which is the case below it.
func TestAFreshInstallRunsLearn(t *testing.T) {
	cfg := Default()
	mode, fromInstall := cfg.ResolveLocalDNSSEC(LocalDNSSECObserve)

	if mode != LocalDNSSECObserve {
		t.Fatalf("a fresh installation resolved to %q, want %q", mode, LocalDNSSECObserve)
	}
	if !fromInstall {
		t.Fatal("the mode was not reported as coming from the installation record")
	}
	if !cfg.DNS.ObserveDNSSEC() {
		t.Fatal("the resolved configuration does not start Learn mode")
	}
}

// TestAnUpgradeThatNeverAskedForItStaysOff is the other half, and the reason
// this mechanism exists rather than a changed Go default.
//
// Learn is off the answer path, but it is not free: it sends its own DNSSEC
// queries upstream, spends CPU and fills a queue. Turning that on because
// someone pulled a new image is a change to their traffic that they did not
// ask for and would have no reason to look for.
func TestAnUpgradeThatNeverAskedForItStaysOff(t *testing.T) {
	cfg := Default()
	mode, fromInstall := cfg.ResolveLocalDNSSEC(LocalDNSSECOff)

	if mode != LocalDNSSECOff {
		t.Fatalf("an existing installation resolved to %q, want %q", mode, LocalDNSSECOff)
	}
	if !fromInstall {
		t.Fatal("the mode was not reported as coming from the installation record")
	}
	if cfg.DNS.ObserveDNSSEC() {
		t.Fatal("an upgrade started sending DNSSEC queries nobody asked for")
	}
}

// An unreadable or absent installation record is not evidence that this is a
// new install, so it must not be treated as one.
func TestAnUnreadableInstallationRecordFallsBackToOff(t *testing.T) {
	for _, record := range []string{"", "learn", "enforce", "yes", "  observe"} {
		cfg := Default()
		if mode, _ := cfg.ResolveLocalDNSSEC(record); mode != LocalDNSSECOff {
			t.Errorf("installation record %q resolved to %q, want %q", record, mode, LocalDNSSECOff)
		}
	}
}

// What the operator wrote always wins, in both directions, and is never
// reported as an installation decision.
func TestAnExplicitModeIsNeverOverriddenByTheInstallation(t *testing.T) {
	for _, tc := range []struct{ configured, record string }{
		{LocalDNSSECOff, LocalDNSSECObserve},
		{LocalDNSSECObserve, LocalDNSSECOff},
	} {
		cfg := Default()
		cfg.DNS.LocalDNSSECValidation = tc.configured
		mode, fromInstall := cfg.ResolveLocalDNSSEC(tc.record)
		if mode != tc.configured {
			t.Errorf("configured %q with record %q resolved to %q", tc.configured, tc.record, mode)
		}
		if fromInstall {
			t.Errorf("configured %q was reported as an installation decision", tc.configured)
		}
	}
}

// Resolving twice must not drift: the second call sees a configured value and
// leaves it alone. Startup does this once, but nothing about the API says it
// may only be called once, and a resolve that flipped a mode on the second
// call would be a very unpleasant surprise.
func TestResolvingIsIdempotent(t *testing.T) {
	cfg := Default()
	first, _ := cfg.ResolveLocalDNSSEC(LocalDNSSECObserve)
	second, fromInstall := cfg.ResolveLocalDNSSEC(LocalDNSSECOff)
	if second != first {
		t.Fatalf("a second resolve changed the mode from %q to %q", first, second)
	}
	if fromInstall {
		t.Fatal("a resolved mode was reported as a fresh installation decision")
	}
}

// TestAZeroValueModeIsOffRatherThanAnError keeps the DNS type safe to use on
// its own: an empty mode is valid configuration, not a rejection, and it does
// not construct a validator.
func TestAZeroValueModeIsOffRatherThanAnError(t *testing.T) {
	cfg := Default()
	cfg.DNS.LocalDNSSECValidation = ""
	if err := cfg.validateLocalDNSSEC(); err != nil {
		t.Fatalf("an empty mode was rejected: %v", err)
	}
	if cfg.DNS.ObserveDNSSEC() {
		t.Fatal("an empty mode switched observation on")
	}
}

// TestEnforceIsRefusedRatherThanDowngraded is the rule this whole function
// exists for.
//
// "enforce" is a word an operator can reasonably expect to work, and it does
// not. The dangerous failure is not rejecting it — it is accepting it and
// running in observe, which leaves someone believing their resolver refuses
// forged answers while it forwards them unchanged. Refusing to start is the
// only honest outcome, and the message has to say so rather than just naming
// a valid set.
func TestEnforceIsRefusedRatherThanDowngraded(t *testing.T) {
	cfg := Default()
	cfg.DNS.LocalDNSSECValidation = LocalDNSSECEnforce

	err := cfg.validateLocalDNSSEC()
	if err == nil {
		t.Fatal("enforce was accepted; a mode that is not implemented must fail startup")
	}
	msg := err.Error()
	for _, want := range []string{"not implemented", LocalDNSSECObserve, LocalDNSSECOff} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q, so it does not explain what happened: %s", want, msg)
		}
	}
	// And the mode must not have been quietly rewritten on the way out.
	if cfg.DNS.ObserveDNSSEC() {
		t.Fatal("a refused mode still reports as observing")
	}
}

func TestAnUnknownModeIsRejected(t *testing.T) {
	cfg := Default()
	for _, mode := range []string{"on", "true", "yes", "validate", "OBSERVE", " observe"} {
		cfg.DNS.LocalDNSSECValidation = mode
		if err := cfg.validateLocalDNSSEC(); err == nil {
			t.Errorf("mode %q was accepted", mode)
		}
	}
}

func TestObserveIsAccepted(t *testing.T) {
	cfg := Default()
	cfg.DNS.LocalDNSSECValidation = LocalDNSSECObserve
	if err := cfg.validateLocalDNSSEC(); err != nil {
		t.Fatalf("observe was rejected: %v", err)
	}
	if !cfg.DNS.ObserveDNSSEC() {
		t.Fatal("observe mode does not report as observing")
	}
}

// TestNegativeBudgetsAreRejectedEvenWhenOff catches the trap of validating a
// setting only on the path that reads it.
//
// A negative worker count in a file with the mode off is a mistake waiting for
// whoever switches the mode on, quite possibly months later and while
// debugging something else.
func TestNegativeBudgetsAreRejectedEvenWhenOff(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*Config)
	}{
		{"workers", func(c *Config) { c.DNS.LocalDNSSECWorkers = -1 }},
		{"queue", func(c *Config) { c.DNS.LocalDNSSECQueue = -1 }},
		{"timeout", func(c *Config) { c.DNS.LocalDNSSECTimeout = Duration(-time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.DNS.LocalDNSSECValidation = LocalDNSSECOff
			tc.apply(&cfg)
			if err := cfg.validateLocalDNSSEC(); err == nil {
				t.Fatalf("a negative %s was accepted while the mode was off", tc.name)
			}
		})
	}
}

// TestTelemetryAndLocalValidationAreIndependent guards the field ADR 0002 §9
// says must not be repurposed.
//
// dnssec_telemetry records what the *upstream* concluded. Local validation is
// a different measurement. Neither switch may imply the other, in either
// direction, or the two facts stop being separable in the data.
func TestTelemetryAndLocalValidationAreIndependent(t *testing.T) {
	cfg := Default()
	cfg.DNS.DNSSECTelemetry = false
	cfg.DNS.LocalDNSSECValidation = LocalDNSSECObserve
	if err := cfg.validateLocalDNSSEC(); err != nil {
		t.Fatalf("observe without upstream telemetry was rejected: %v", err)
	}
	if !cfg.DNS.ObserveDNSSEC() {
		t.Fatal("switching telemetry off switched observation off too")
	}

	cfg = Default()
	cfg.DNS.DNSSECTelemetry = true
	cfg.DNS.LocalDNSSECValidation = LocalDNSSECOff
	if cfg.DNS.ObserveDNSSEC() {
		t.Fatal("upstream telemetry switched local observation on")
	}
}
