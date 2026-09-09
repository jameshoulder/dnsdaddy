package config

import (
	"strings"
	"testing"
	"time"
)

// TestLocalDNSSECDefaultsToOff pins the default.
//
// A feature that sends extra upstream queries and runs an experimental
// validator must be something an operator switched on. Inheriting it from a
// release upgrade would change an instance's upstream traffic without anyone
// asking for it.
func TestLocalDNSSECDefaultsToOff(t *testing.T) {
	cfg := Default()
	if got := cfg.DNS.LocalDNSSECMode(); got != LocalDNSSECOff {
		t.Fatalf("default local_dnssec_validation = %q, want %q", got, LocalDNSSECOff)
	}
	if cfg.DNS.ObserveDNSSEC() {
		t.Fatal("the default configuration observes DNSSEC")
	}
}

// TestAnAbsentModeIsOffRatherThanAnError is the upgrade path.
//
// Every configuration file written before this feature existed omits the key.
// Those instances must keep working exactly as they did, which means the empty
// string is off rather than invalid.
func TestAnAbsentModeIsOffRatherThanAnError(t *testing.T) {
	cfg := Default()
	cfg.DNS.LocalDNSSECValidation = ""
	if err := cfg.validateLocalDNSSEC(); err != nil {
		t.Fatalf("an omitted key was rejected: %v", err)
	}
	if cfg.DNS.ObserveDNSSEC() {
		t.Fatal("an omitted key switched observation on")
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
