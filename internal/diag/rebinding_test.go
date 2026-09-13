package diag

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/rebind"
)

func onFilter() RebindingInput {
	return RebindingInput{
		Enabled:     true,
		Ranges:      rebind.DefaultRanges(),
		EmptyAction: rebind.EmptyNoData,
		Exemptions:  map[string][]string{},
	}
}

func findCheck(checks []Check, name string) (Check, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

func joined(c Check) string { return strings.Join(c.Evidence, " | ") }

// TestADisabledFilterWarnsAndNamesTheEscapeHatch. An operator told only "turn
// it on" will turn it on, break their intranet, and turn it off again. The
// action has to mention exemptions.
func TestADisabledFilterWarnsAndNamesTheEscapeHatch(t *testing.T) {
	checks := Rebinding(RebindingInput{Enabled: false})
	if len(checks) != 1 || checks[0].Status != StatusWarn {
		t.Fatalf("got %d checks, first status %v; want one WARN", len(checks), checks[0].Status)
	}
	if !strings.Contains(checks[0].Action, "exempt") {
		t.Errorf("the action does not mention exemptions: %q", checks[0].Action)
	}
}

// TestAnEnabledFilterWithNoRangesFails. This is the misconfiguration that
// reads as protection: on, and filtering nothing.
func TestAnEnabledFilterWithNoRangesFails(t *testing.T) {
	in := onFilter()
	in.Ranges = nil
	checks := Rebinding(in)
	if checks[0].Status != StatusFail {
		t.Errorf("status = %v, want FAIL", checks[0].Status)
	}
	if !strings.Contains(checks[0].Summary, "filters nothing") {
		t.Errorf("summary does not say what is wrong: %q", checks[0].Summary)
	}
}

// TestAWorkingFilterPasses and reports what it withholds.
func TestAWorkingFilterPasses(t *testing.T) {
	checks := Rebinding(onFilter())
	c, ok := findCheck(checks, "DNS rebinding filter")
	if !ok || c.Status != StatusPass {
		t.Fatalf("want a passing filter check, got %+v", checks)
	}
	if !strings.Contains(joined(c), "10.0.0.0/8") {
		t.Errorf("evidence does not list the filtered ranges: %q", joined(c))
	}
	if !strings.Contains(c.Summary, "nodata") {
		t.Errorf("summary does not say what an emptied answer becomes: %q", c.Summary)
	}
}

// TestADefaultRouteExemptionFails, and says so loudly when it is on the
// default policy, because that one covers every client the operator has not
// explicitly placed.
func TestADefaultRouteExemptionFails(t *testing.T) {
	in := onFilter()
	in.DefaultPolicyID = "p_standard"
	in.Exemptions["p_standard"] = []string{"0.0.0.0/0"}

	c, ok := findCheck(Rebinding(in), "Rebinding exemption covers every address")
	if !ok {
		t.Fatal("a 0.0.0.0/0 exemption produced no check")
	}
	if c.Status != StatusFail {
		t.Errorf("status = %v, want FAIL", c.Status)
	}
	if !strings.Contains(joined(c), "every unmatched client") {
		t.Errorf("the default policy was not called out: %q", joined(c))
	}
}

// TestABroadExemptionWarnsWithoutFailing. An operator with a flat 10/8 is not
// doing anything wrong, but they should be able to see that they have handed
// back most of what the filter withholds.
func TestABroadExemptionWarnsWithoutFailing(t *testing.T) {
	in := onFilter()
	in.Exemptions["p_office"] = []string{"10.0.0.0/8"}

	checks := Rebinding(in)
	c, ok := findCheck(checks, "Broad rebinding exemption")
	if !ok {
		t.Fatal("a /8 exemption produced no warning")
	}
	if c.Status != StatusWarn {
		t.Errorf("status = %v, want WARN", c.Status)
	}
	if main, _ := findCheck(checks, "DNS rebinding filter"); main.Status != StatusPass {
		t.Error("a broad exemption downgraded the filter check itself")
	}
}

// TestANarrowExemptionIsNotWarnedAbout. The warning has to be rare enough to
// mean something.
func TestANarrowExemptionIsNotWarnedAbout(t *testing.T) {
	in := onFilter()
	in.Exemptions["p_office"] = []string{"192.168.10.0/24", "10.1.2.0/24"}

	if _, ok := findCheck(Rebinding(in), "Broad rebinding exemption"); ok {
		t.Error("two /24 exemptions were reported as broad")
	}
	c, _ := findCheck(Rebinding(in), "DNS rebinding filter")
	if !strings.Contains(joined(c), "1 polic") {
		t.Errorf("the exemption count is wrong: %q", joined(c))
	}
}

// TestIPv6ExemptionsAreJudgedOnTheirOwnScale. A /32 of IPv4 is a single host
// and a /32 of IPv6 is larger than the entire IPv4 internet; one threshold for
// both would either warn about every host exemption or never warn about IPv6.
func TestIPv6ExemptionsAreJudgedOnTheirOwnScale(t *testing.T) {
	host := onFilter()
	host.Exemptions["p"] = []string{"192.168.1.5/32"}
	if _, ok := findCheck(Rebinding(host), "Broad rebinding exemption"); ok {
		t.Error("a single IPv4 host was reported as a broad exemption")
	}

	huge := onFilter()
	huge.Exemptions["p"] = []string{"fd00::/16"}
	if _, ok := findCheck(Rebinding(huge), "Broad rebinding exemption"); !ok {
		t.Error("an fd00::/16 exemption was not reported as broad")
	}
}

// TestUnreadableExemptionsFail. A policy filtering a range its operator
// believes is exempt presents to them as an intranet that stopped working for
// no reason, so it must not be silent.
func TestUnreadableExemptionsFail(t *testing.T) {
	in := onFilter()
	in.Dropped = 2

	c, ok := findCheck(Rebinding(in), "Unreadable rebinding exemption")
	if !ok || c.Status != StatusFail {
		t.Fatalf("dropped exemptions produced %+v", c)
	}
	if !strings.Contains(c.Summary, "2") {
		t.Errorf("the count is missing: %q", c.Summary)
	}
}

// TestADisabledFilterDoesNotReportExemptions. Nothing is being filtered, so
// warning about what is exempt from the filtering would be noise.
func TestADisabledFilterDoesNotReportExemptions(t *testing.T) {
	in := RebindingInput{Enabled: false, Exemptions: map[string][]string{"p": {"0.0.0.0/0"}}, Dropped: 3}
	if got := len(Rebinding(in)); got != 1 {
		t.Errorf("a disabled filter produced %d checks, want 1", got)
	}
}

// TestPrefixesAreReportedInMaskedForm, so evidence an operator compares
// against their config file matches it.
func TestPrefixesAreReportedInMaskedForm(t *testing.T) {
	in := onFilter()
	in.Ranges = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	c, _ := findCheck(Rebinding(in), "DNS rebinding filter")
	if !strings.Contains(joined(c), "10.0.0.0/8") {
		t.Errorf("evidence = %q", joined(c))
	}
}
