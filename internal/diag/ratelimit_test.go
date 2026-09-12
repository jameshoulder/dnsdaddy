package diag

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/ratelimit"
)

func rlCheck(t *testing.T, in RateLimitInput) Check {
	t.Helper()
	return RateLimit(in)
}

func evidence(c Check) string { return strings.Join(c.Evidence, " | ") }

// TestADisabledLimiterWarnsAndSaysWhatToDo. Silence about a control that is
// off is how an operator comes to believe they have one.
func TestADisabledLimiterWarnsAndSaysWhatToDo(t *testing.T) {
	c := rlCheck(t, RateLimitInput{Enabled: false})
	if c.Status != StatusWarn {
		t.Errorf("status = %v, want WARN", c.Status)
	}
	if !strings.Contains(c.Summary, "saturate") {
		t.Errorf("summary does not say what the risk is: %q", c.Summary)
	}
	if !strings.Contains(c.Action, "dns.rate_limit.enabled") {
		t.Errorf("action does not name the setting: %q", c.Action)
	}
}

// TestAnEnabledLimiterReportsTheLimitsInForce, in numbers an operator can
// compare against what they wrote.
func TestAnEnabledLimiterReportsTheLimitsInForce(t *testing.T) {
	c := rlCheck(t, RateLimitInput{
		Enabled: true,
		Config:  ratelimit.New(ratelimit.Config{Rate: 250, Burst: 400, MaxClients: 1024}).Config(),
	})
	if c.Status != StatusPass {
		t.Errorf("status = %v, want PASS", c.Status)
	}
	for _, want := range []string{"250", "400"} {
		if !strings.Contains(c.Summary, want) {
			t.Errorf("summary %q does not mention %s", c.Summary, want)
		}
	}
	if !strings.Contains(evidence(c), "1024") {
		t.Errorf("evidence does not report the table bound: %q", evidence(c))
	}
}

// TestTheReportedLimitsAreTheOnesThatWouldBeEnforced. The doctor takes the
// limiter's own view rather than the YAML, so a value the file left out is
// reported as the default that is actually in force rather than as a zero.
func TestTheReportedLimitsAreTheOnesThatWouldBeEnforced(t *testing.T) {
	// Everything omitted but the rate.
	c := rlCheck(t, RateLimitInput{
		Enabled: true,
		Config:  ratelimit.New(ratelimit.Config{Rate: 42}).Config(),
	})
	if strings.Contains(c.Summary, "burst of 0") {
		t.Errorf("an omitted burst was reported as 0 rather than as the default in force: %q", c.Summary)
	}
	if !strings.Contains(evidence(c), "/32") || !strings.Contains(evidence(c), "/64") {
		t.Errorf("omitted prefix lengths were not reported as the defaults in force: %q", evidence(c))
	}
}

// TestTheIPv6GroupingIsStated. On a typical LAN every host shares one /64, so
// the IPv6 limit is per-LAN rather than per-host. That should be in front of
// an operator before it is a surprise during an incident.
func TestTheIPv6GroupingIsStated(t *testing.T) {
	c := rlCheck(t, RateLimitInput{
		Enabled: true,
		Config:  ratelimit.New(ratelimit.Config{Rate: 100, Burst: 100, IPv6PrefixLength: 64}).Config(),
	})
	if !strings.Contains(evidence(c), "share one allowance") {
		t.Errorf("the /64 grouping is not explained: %q", evidence(c))
	}

	perHost := rlCheck(t, RateLimitInput{
		Enabled: true,
		Config:  ratelimit.New(ratelimit.Config{Rate: 100, Burst: 100, IPv6PrefixLength: 128}).Config(),
	})
	if strings.Contains(evidence(perHost), "share one allowance") {
		t.Error("per-host IPv6 limiting still warned about sharing")
	}
}

// TestAnExemptRangeIsNamed. An unlimited range is a hole in the control, and
// an operator reviewing this should recognise the ones they meant to make
// without opening the configuration file.
func TestAnExemptRangeIsNamed(t *testing.T) {
	c := rlCheck(t, RateLimitInput{
		Enabled: true,
		Config: ratelimit.New(ratelimit.Config{
			Rate: 100, Burst: 100,
			Overrides: []ratelimit.Override{
				{Prefix: netip.MustParsePrefix("127.0.0.0/8"), Rate: 0},
				{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Rate: 20, Burst: 40},
			},
		}).Config(),
	})
	ev := evidence(c)
	if !strings.Contains(ev, "not limited at all: 127.0.0.0/8") {
		t.Errorf("the exempt range was not named: %q", ev)
	}
	if !strings.Contains(ev, "10.1.0.0/16") || !strings.Contains(ev, "20") {
		t.Errorf("the tightened range was not reported: %q", ev)
	}
}

// TestNoOverridesSaysSo, rather than leaving an operator to infer it from an
// absence.
func TestNoOverridesSaysSo(t *testing.T) {
	c := rlCheck(t, RateLimitInput{
		Enabled: true,
		Config:  ratelimit.New(ratelimit.Config{Rate: 100, Burst: 100}).Config(),
	})
	if !strings.Contains(evidence(c), "no per-range overrides") {
		t.Errorf("evidence is silent about overrides: %q", evidence(c))
	}
}
