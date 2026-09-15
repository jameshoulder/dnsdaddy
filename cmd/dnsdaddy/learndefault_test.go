package main

import (
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/resources"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// TestOnlyTheSmallestMachineStartsWithLearnOff.
//
// The mapping from machine size to what a brand-new installation records. The
// change is scoped to the one machine that cannot afford Learn; everything
// larger keeps the behaviour every release before machine sizing had.
func TestOnlyTheSmallestMachineStartsWithLearnOff(t *testing.T) {
	for _, tc := range []struct {
		size resources.Profile
		want string
	}{
		{resources.ProfileTiny, "off"},
		{resources.ProfileSmall, "observe"},
		{resources.ProfileFull, "observe"},
	} {
		if got := freshInstallLearn(tc.size); got != tc.want {
			t.Errorf("a fresh install on a %s records %q, want %q", tc.size.Label(), got, tc.want)
		}
	}

	// An unrecognised size gets the historic behaviour rather than the
	// restriction. Nothing should reach here with one, but guessing "too small
	// to validate" about a machine nothing could classify would be the program
	// acting on something it does not know.
	if got := freshInstallLearn(""); got != "observe" {
		t.Errorf("an unknown size records %q, want observe", got)
	}
}

// TestAnOperatorsOwnSettingBeatsTheMachineSize.
//
// Whoever wrote dns.local_dnssec_validation in their configuration has
// decided, and no amount of reasoning about how much memory the box has
// overrides that. The record only ever fills in the blank nobody filled.
func TestAnOperatorsOwnSettingBeatsTheMachineSize(t *testing.T) {
	for _, written := range []string{config.LocalDNSSECObserve, config.LocalDNSSECOff} {
		t.Run("configured="+written, func(t *testing.T) {
			cfg := config.Default()
			cfg.DNS.LocalDNSSECValidation = written

			// The record says the opposite of the configuration.
			record := config.LocalDNSSECOff
			if written == config.LocalDNSSECOff {
				record = config.LocalDNSSECObserve
			}

			mode, fromInstall := cfg.ResolveLocalDNSSEC(record)
			if fromInstall {
				t.Error("an explicit setting was reported as coming from the installation record")
			}
			if mode != written {
				t.Errorf("mode = %q, want the configured %q", mode, written)
			}
		})
	}
}

// TestAFresh1GBInstallResolvesToLearnOffEndToEnd.
//
// The whole path the daemon takes: the machine size chooses what a first run
// records, the record is written by seed, and the configuration resolves
// against it. Each half is tested on its own; this is the join, because a
// mapping that is right and a record that is right can still be wired to each
// other backwards.
func TestAFresh1GBInstallResolvesToLearnOffEndToEnd(t *testing.T) {
	st, err := store.OpenWithOptions(t.TempDir()+"/tiny.db", store.Options{
		FreshInstallLearn: freshInstallLearn(resources.ProfileTiny),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	recorded, err := st.GetSetting(t.Context(), store.SettingLocalDNSSECDefault)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default() // nothing configured, which is the case that matters
	mode, fromInstall := cfg.ResolveLocalDNSSEC(recorded)
	if !fromInstall {
		t.Fatal("the installation record was not consulted")
	}
	if mode != config.LocalDNSSECOff {
		t.Errorf("a fresh 1 GB install resolves to %q, want off", mode)
	}
	if cfg.DNS.ObserveDNSSEC() {
		t.Error("a fresh 1 GB install would observe DNSSEC")
	}

	// And the same path on a 2 GB machine still observes, so this is a size
	// rule rather than the feature being switched off everywhere.
	big, err := store.OpenWithOptions(t.TempDir()+"/small.db", store.Options{
		FreshInstallLearn: freshInstallLearn(resources.ProfileSmall),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer big.Close()

	recorded, err = big.GetSetting(t.Context(), store.SettingLocalDNSSECDefault)
	if err != nil {
		t.Fatal(err)
	}
	cfg = config.Default()
	if mode, _ := cfg.ResolveLocalDNSSEC(recorded); mode != config.LocalDNSSECObserve {
		t.Errorf("a fresh 2 GB install resolves to %q, want observe", mode)
	}
}

// TestTurningLearnOffChangesNothingAClientSees.
//
// Learn is observe-only: it looks at answers the resolver has already decided
// and records what it concludes. So switching it off can change what is
// written down and what the box costs, and must change nothing on the wire.
//
// The property is already pinned in internal/dnsserver, where an observer is
// made to accept, refuse, hang and panic and the bytes are compared. This
// asserts the half that belongs here: the default this change alters feeds one
// setting, and that setting has no path to a response.
func TestTurningLearnOffChangesNothingAClientSees(t *testing.T) {
	observe := config.Default()
	observe.DNS.LocalDNSSECValidation = config.LocalDNSSECObserve
	off := config.Default()
	off.DNS.LocalDNSSECValidation = config.LocalDNSSECOff

	// Everything that decides what a client receives is identical.
	for _, tc := range []struct {
		name         string
		with, wthout any
	}{
		{"block mode", observe.DNS.RefuseANY, off.DNS.RefuseANY},
		{"upstreams", len(observe.DNS.Upstreams), len(off.DNS.Upstreams)},
		{"upstream mode", observe.DNS.UpstreamMode, off.DNS.UpstreamMode},
		{"rebinding filter", observe.DNS.FilterRebinding(), off.DNS.FilterRebinding()},
		{"rate limit", observe.DNS.RateLimit.Enabled, off.DNS.RateLimit.Enabled},
		{"client access", len(observe.DNS.AllowedClientCIDRs), len(off.DNS.AllowedClientCIDRs)},
		{"answer cache", observe.Cache.Enabled, off.Cache.Enabled},
		{"cache size", observe.Cache.MaxEntries, off.Cache.MaxEntries},
	} {
		if tc.with != tc.wthout {
			t.Errorf("%s differs between Learn on and Learn off: %v vs %v",
				tc.name, tc.with, tc.wthout)
		}
	}

	// And the one thing that does differ is the one thing that should.
	if observe.DNS.ObserveDNSSEC() == off.DNS.ObserveDNSSEC() {
		t.Error("the setting under test has no effect, so this test proves nothing")
	}
}
