package diag

import (
	"fmt"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/ratelimit"
)

// RateLimitInput is the configured per-client rate limit, as the daemon would
// build it.
type RateLimitInput struct {
	// Enabled is dns.rate_limit.enabled.
	Enabled bool
	// Config is what the limiter would run on, after defaults are applied.
	// Taking the limiter's own view rather than the raw YAML matters: a value
	// the limiter falls back on is a value that is not in force, and reporting
	// the file instead of the effect is how a doctor comes to disagree with
	// the thing it is describing.
	Config ratelimit.Config
}

// RateLimit reports whether one client can exhaust this resolver.
//
// A warning rather than a failure when the limiter is off: running without one
// is a legitimate choice on a network whose clients are all trusted and
// measured, and this command has no way to know that it is not. But it is the
// residual risk the threat model has carried the longest, so it is not silent
// either.
func RateLimit(in RateLimitInput) Check {
	c := Check{Section: sectionClientAccess, Name: "Per-client rate limit"}

	if !in.Enabled {
		c.Status = StatusWarn
		c.Summary = "No per-client query rate limit. One authorised client can saturate this resolver."
		c.Evidence = []string{"dns.rate_limit.enabled is false"}
		c.Action = "Set dns.rate_limit.enabled: true unless you have measured your clients' " +
			"query rates and decided otherwise. The shipped default sits far above what a " +
			"legitimate host does."
		return c
	}

	cfg := in.Config
	c.Status = StatusPass
	c.Summary = fmt.Sprintf(
		"Each client may sustain %g queries/second with a burst of %g; beyond that it is REFUSED.",
		cfg.Rate, cfg.Burst)

	ev := []string{
		fmt.Sprintf("one client means one IPv4 /%d and one IPv6 /%d",
			cfg.IPv4PrefixLength, cfg.IPv6PrefixLength),
		fmt.Sprintf("at most %d clients are tracked at once", cfg.MaxClients),
	}

	// An IPv6 prefix shorter than a host is reported as the fact it is. On a
	// typical LAN every host shares one /64, which makes the IPv6 limit
	// per-LAN rather than per-host — a surprise worth having in front of an
	// operator before it is a surprise during an incident.
	if cfg.IPv6PrefixLength < 128 {
		ev = append(ev, fmt.Sprintf(
			"IPv6 clients are grouped by /%d, so hosts sharing a /%d share one allowance",
			cfg.IPv6PrefixLength, cfg.IPv6PrefixLength))
	}

	var exempt []string
	for _, o := range cfg.Overrides {
		if o.Rate <= 0 {
			exempt = append(exempt, o.Prefix.String())
			continue
		}
		ev = append(ev, fmt.Sprintf("%s: %g/second, burst %g", o.Prefix, o.Rate, o.Burst))
	}
	if len(exempt) > 0 {
		// Exemptions are named rather than counted. A range with no limit is a
		// hole in the control, and an operator reviewing this should be able
		// to recognise the ranges they meant to exempt without opening the
		// configuration file.
		ev = append(ev, "not limited at all: "+strings.Join(exempt, ", "))
	}
	if len(cfg.Overrides) == 0 {
		ev = append(ev, "no per-range overrides are configured")
	}

	c.Evidence = ev
	return c
}
