package config

import (
	"net/netip"
	"strings"
	"testing"
)

// loadYAMLInto decodes a fragment over an already-defaulted Config, which is
// exactly what Load does. Testing against a fresh struct instead would hide
// the question these tests exist to answer: what an omitted key does.
func loadYAMLInto(t *testing.T, cfg *Config, y string) error {
	t.Helper()
	return unmarshalYAML([]byte(y), cfg)
}

// TestRateLimitIsOnByDefault. The threat model has carried "no per-client rate
// limiting" as a residual risk since the first release; shipping the control
// switched off would leave that sentence true for everyone who does not read
// the configuration reference.
func TestRateLimitIsOnByDefault(t *testing.T) {
	d := Default()
	if !d.DNS.RateLimit.Enabled {
		t.Fatal("the rate limiter ships disabled")
	}
	if d.DNS.RateLimit.Rate <= 0 || d.DNS.RateLimit.Burst < d.DNS.RateLimit.Rate {
		t.Errorf("default rate=%v burst=%v: burst should leave headroom above the sustained rate",
			d.DNS.RateLimit.Rate, d.DNS.RateLimit.Burst)
	}
	if d.DNS.RateLimit.MaxClients <= 0 {
		t.Error("the tracking table has no bound by default")
	}
}

// TestDisablingTheLimiterIsPossible: on by default must not mean impossible to
// turn off. An operator who has measured their own traffic and disagrees with
// the default has to be able to act on that.
func TestDisablingTheLimiterIsPossible(t *testing.T) {
	cfg := Default()
	if err := loadYAMLInto(t, &cfg, "dns:\n  rate_limit:\n    enabled: false\n"); err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.RateLimit.Enabled {
		t.Error("enabled: false did not turn the limiter off")
	}
}

// TestOmittingTheKeyKeepsTheDefault is the other half: YAML unmarshals over
// the defaults, so an absent key must not read as false.
func TestOmittingTheKeyKeepsTheDefault(t *testing.T) {
	cfg := Default()
	if err := loadYAMLInto(t, &cfg, "dns:\n  rate_limit:\n    rate: 42\n"); err != nil {
		t.Fatal(err)
	}
	if !cfg.DNS.RateLimit.Enabled {
		t.Error("omitting enabled turned the limiter off")
	}
	if cfg.DNS.RateLimit.Rate != 42 {
		t.Errorf("rate = %v, want the configured 42", cfg.DNS.RateLimit.Rate)
	}
	if cfg.DNS.RateLimit.Burst != Default().DNS.RateLimit.Burst {
		t.Error("setting rate alone discarded the default burst")
	}
}

// TestAMalformedOverrideIsAStartupError, not a skipped line. The only reason
// to write an override is that some range needs different treatment; ignoring
// a typo gives the operator exactly the treatment they were trying to avoid
// and says nothing.
func TestAMalformedOverrideIsAStartupError(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{"not a cidr", "cidr: \"10.0.0.1\"\n        rate: 10", "is not a CIDR"},
		{"host bits set", "cidr: \"10.1.2.3/24\"\n        rate: 10", "host bits set"},
		{"negative rate", "cidr: \"10.0.0.0/8\"\n        rate: -1", "must not be negative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			y := "dns:\n  rate_limit:\n    overrides:\n      - " + tc.yaml + "\n"
			if err := loadYAMLInto(t, &cfg, y); err != nil {
				t.Fatal(err)
			}
			err := cfg.validateRateLimit()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not explain the problem (%q)", err, tc.want)
			}
		})
	}
}

// TestAnInvalidLimitIsRefusedAtStartup. internal/ratelimit falls back to its
// defaults rather than refusing traffic, which is right at the point of use
// and wrong here: silently correcting a typo leaves an operator believing a
// limit is in force that is not.
func TestAnInvalidLimitIsRefusedAtStartup(t *testing.T) {
	for _, tc := range []struct{ name, yaml string }{
		{"negative rate", "rate: -5"},
		{"negative burst", "burst: -5"},
		{"zero burst", "burst: 0"},
		{"ipv4 prefix too long", "ipv4_prefix_length: 33"},
		{"ipv6 prefix too long", "ipv6_prefix_length: 129"},
		{"negative max clients", "max_clients: -1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			if err := loadYAMLInto(t, &cfg, "dns:\n  rate_limit:\n    "+tc.yaml+"\n"); err != nil {
				t.Fatal(err)
			}
			if err := cfg.validateRateLimit(); err == nil {
				t.Errorf("%s was accepted", tc.name)
			}
		})
	}
}

// TestADisabledLimiterIsNotValidated. Somebody who has switched the feature
// off should not be held to the shape of numbers nothing will read.
func TestADisabledLimiterIsNotValidated(t *testing.T) {
	cfg := Default()
	cfg.DNS.RateLimit.Enabled = false
	cfg.DNS.RateLimit.Rate = -99
	cfg.DNS.RateLimit.Overrides = []RateLimitOverride{{CIDR: "nonsense"}}
	if err := cfg.validateRateLimit(); err != nil {
		t.Errorf("a disabled limiter was validated: %v", err)
	}
}

// TestOverridesReachTheLimiterMasked. A CIDR an operator wrote is translated
// into the limiter's own form exactly once, here; if the translation dropped
// entries or left host bits on, an override would silently not match.
func TestOverridesReachTheLimiter(t *testing.T) {
	cfg := Default()
	cfg.DNS.RateLimit.Overrides = []RateLimitOverride{
		{CIDR: " 127.0.0.0/8 ", Rate: 0},
		{CIDR: "10.1.0.0/16", Rate: 50, Burst: 100},
	}
	rc := cfg.DNS.RateLimitConfig()
	if len(rc.Overrides) != 2 {
		t.Fatalf("translated %d overrides, want 2", len(rc.Overrides))
	}
	if rc.Overrides[0].Prefix != netip.MustParsePrefix("127.0.0.0/8") {
		t.Errorf("surrounding whitespace broke an override: %v", rc.Overrides[0].Prefix)
	}
	if rc.Rate != cfg.DNS.RateLimit.Rate || rc.MaxClients != cfg.DNS.RateLimit.MaxClients {
		t.Error("the global limits did not survive translation")
	}
}

// TestAZeroGlobalRateIsRefusedWithTheRemedy. Zero already means "do not limit
// this range" inside an override. Letting it mean the same thing globally
// would disable the control while enabled: true still sat above it; letting it
// mean zero queries per second would take a network down on one character.
// Neither guess is safe, so the operator is asked which they meant.
func TestAZeroGlobalRateIsRefusedWithTheRemedy(t *testing.T) {
	cfg := Default()
	if err := loadYAMLInto(t, &cfg, "dns:\n  rate_limit:\n    rate: 0\n"); err != nil {
		t.Fatal(err)
	}
	err := cfg.validateRateLimit()
	if err == nil {
		t.Fatal("rate: 0 was accepted")
	}
	if !strings.Contains(err.Error(), "enabled: false") {
		t.Errorf("the error does not name the way to turn the limiter off: %v", err)
	}
}

// TestAZeroRateOverrideIsStillAnExemption — rejecting a global zero must not
// have taken away the documented way to exempt a monitoring host.
func TestAZeroRateOverrideIsStillAnExemption(t *testing.T) {
	cfg := Default()
	cfg.DNS.RateLimit.Overrides = []RateLimitOverride{{CIDR: "127.0.0.0/8", Rate: 0}}
	if err := cfg.validateRateLimit(); err != nil {
		t.Errorf("a zero-rate override was rejected: %v", err)
	}
	if rc := cfg.DNS.RateLimitConfig(); len(rc.Overrides) != 1 || rc.Overrides[0].Rate != 0 {
		t.Error("the exemption did not survive translation to the limiter")
	}
}
