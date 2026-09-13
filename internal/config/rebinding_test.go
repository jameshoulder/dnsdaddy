package config

import (
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/rebind"
)

// TestTheFilterStateIsUndecidedUntilResolved. The whole point of the tri-state
// is that Default() must not answer a question only the database can.
func TestTheFilterStateIsUndecidedUntilResolved(t *testing.T) {
	d := Default()
	if d.DNS.RebindingConfigured() {
		t.Error("Default() decided the rebinding state; only the installation record may")
	}
	if d.DNS.FilterRebinding() {
		t.Error("an undecided filter reported itself as on")
	}
	if len(d.DNS.Rebinding.FilterRanges) == 0 {
		t.Error("Default() ships no filter ranges")
	}
}

// TestAFreshInstallFiltersAndAnUpgradeDoesNot. This is the upgrade contract,
// and it is the difference between a release that protects new deployments and
// one that silently breaks existing intranets.
func TestAFreshInstallFiltersAndAnUpgradeDoesNot(t *testing.T) {
	fresh := Default()
	on, fromInstall := fresh.ResolveRebinding(RebindingOn)
	if !on || !fromInstall {
		t.Errorf("fresh install: enabled=%v fromInstall=%v, want true/true", on, fromInstall)
	}

	upgrade := Default()
	on, fromInstall = upgrade.ResolveRebinding(RebindingOff)
	if on || !fromInstall {
		t.Errorf("upgrade: enabled=%v fromInstall=%v, want false/true", on, fromInstall)
	}

	// An unrecognised record reads as off, which is what every release before
	// this one did.
	unknown := Default()
	if on, _ := unknown.ResolveRebinding("banana"); on {
		t.Error("an unrecognised installation record turned the filter on")
	}
}

// TestTheOperatorOutranksTheInstallationRecord, in both directions.
func TestTheOperatorOutranksTheInstallationRecord(t *testing.T) {
	yes := true
	on := Default()
	on.DNS.Rebinding.Enabled = &yes
	if got, fromInstall := on.ResolveRebinding(RebindingOff); !got || fromInstall {
		t.Errorf("enabled: true lost to an off record (got=%v fromInstall=%v)", got, fromInstall)
	}

	no := false
	off := Default()
	off.DNS.Rebinding.Enabled = &no
	if got, fromInstall := off.ResolveRebinding(RebindingOn); got || fromInstall {
		t.Errorf("enabled: false lost to an on record (got=%v fromInstall=%v)", got, fromInstall)
	}
}

// TestOmittingEnabledLeavesItUndecidedThroughYAML. If unmarshalling wrote a
// zero value over the nil, the tri-state would collapse and every upgrade
// would silently take the "off" branch for the wrong reason.
func TestOmittingEnabledLeavesItUndecidedThroughYAML(t *testing.T) {
	cfg := Default()
	if err := unmarshalYAML([]byte("dns:\n  rebinding:\n    empty_action: nxdomain\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.RebindingConfigured() {
		t.Error("setting an unrelated key decided the enabled state")
	}
	if cfg.DNS.Rebinding.EmptyAction != "nxdomain" {
		t.Errorf("empty_action = %q", cfg.DNS.Rebinding.EmptyAction)
	}

	explicit := Default()
	if err := unmarshalYAML([]byte("dns:\n  rebinding:\n    enabled: false\n"), &explicit); err != nil {
		t.Fatal(err)
	}
	if !explicit.DNS.RebindingConfigured() || explicit.DNS.FilterRebinding() {
		t.Error("enabled: false was not recorded as a decision")
	}
}

// TestAnEmptyRangeListIsRefused. "Enabled, filtering nothing" is the
// misconfiguration that looks exactly like protection.
func TestAnEmptyRangeListIsRefused(t *testing.T) {
	cfg := Default()
	if err := unmarshalYAML([]byte("dns:\n  rebinding:\n    filter_ranges: []\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	err := cfg.validateRebinding()
	if err == nil {
		t.Fatal("an empty filter_ranges was accepted")
	}
	if !strings.Contains(err.Error(), "enabled: false") {
		t.Errorf("the error does not name the remedy: %v", err)
	}
}

// TestAMalformedRangeIsAStartupError, including host bits, which would
// otherwise silently filter a different range than the one written.
func TestAMalformedRangeIsAStartupError(t *testing.T) {
	for _, tc := range []struct{ name, cidr, want string }{
		{"not a cidr", "10.0.0.1", "is not a CIDR"},
		{"host bits set", "10.1.2.3/8", "host bits set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.DNS.Rebinding.FilterRanges = []string{tc.cidr}
			err := cfg.validateRebinding()
			if err == nil {
				t.Fatalf("%q was accepted", tc.cidr)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not explain the problem", err)
			}
		})
	}
}

// TestAnUnknownEmptyActionIsRefusedEvenWhenTheFilterIsOff. A typo should fail
// at startup, not the first time somebody turns the feature on.
func TestAnUnknownEmptyActionIsRefusedEvenWhenTheFilterIsOff(t *testing.T) {
	no := false
	cfg := Default()
	cfg.DNS.Rebinding.Enabled = &no
	cfg.DNS.Rebinding.EmptyAction = "drop"
	if err := cfg.validateRebinding(); err == nil {
		t.Error("an unknown empty_action was accepted because the filter was off")
	}
}

// TestTheShippedRangesBuildAWorkingFilter. The defaults must survive the round
// trip from configuration strings into the filter's own form.
func TestTheShippedRangesBuildAWorkingFilter(t *testing.T) {
	cfg := Default()
	f, err := rebind.New(cfg.DNS.RebindingFilterConfig())
	if err != nil {
		t.Fatalf("the shipped defaults do not build a filter: %v", err)
	}
	if len(f.Ranges()) != len(rebind.DefaultRangeStrings) {
		t.Errorf("filter has %d ranges, want %d", len(f.Ranges()), len(rebind.DefaultRangeStrings))
	}
	if f.EmptyAction() != rebind.EmptyNoData {
		t.Errorf("default empty action = %q, want nodata", f.EmptyAction())
	}
}

// TestAnOmittedRangeListStillBuildsTheDefaults, so a config that mentions only
// empty_action does not end up with no filter at all.
func TestAnOmittedRangeListStillBuildsTheDefaults(t *testing.T) {
	var d DNS
	d.Rebinding.EmptyAction = "refused"
	cfg := d.RebindingFilterConfig()
	if len(cfg.Ranges) != len(rebind.DefaultRangeStrings) {
		t.Errorf("an omitted list produced %d ranges, want the defaults", len(cfg.Ranges))
	}
	if cfg.EmptyAction != rebind.EmptyRefused {
		t.Errorf("empty action = %q", cfg.EmptyAction)
	}
}
