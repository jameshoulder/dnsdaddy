package config

import (
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/firstseen"
)

// TestTheIndexIsOnForEveryone, fresh install and upgrade alike.
//
// Unlike the rebinding filter, this engine cannot change an answer, an RCODE
// or a block decision, so there is no behaviour for an upgrade to inherit and
// no fresh-versus-upgrade question to answer. Turning it on during an upgrade
// changes nothing an operator would notice except that a hunt starts working.
func TestTheIndexIsOnForEveryone(t *testing.T) {
	d := Default()
	if !d.DNS.IndexFirstSeen() {
		t.Error("the first-seen index ships disabled")
	}
	if d.DNS.FirstSeen.MaxRows != firstseen.DefaultMaxRows {
		t.Errorf("max_rows = %d, want the reasoned default", d.DNS.FirstSeen.MaxRows)
	}
	if d.DNS.FirstSeen.MaxNewPerMinute != firstseen.DefaultMaxNewPerMinute {
		t.Errorf("max_new_per_minute = %d", d.DNS.FirstSeen.MaxNewPerMinute)
	}
	if err := d.validateFirstSeen(); err != nil {
		t.Errorf("the shipped defaults do not validate: %v", err)
	}
}

// TestDisablingTheIndexIsPossible, and omitting the key keeps it on.
func TestDisablingTheIndexIsPossible(t *testing.T) {
	off := Default()
	if err := unmarshalYAML([]byte("dns:\n  first_seen:\n    enabled: false\n"), &off); err != nil {
		t.Fatal(err)
	}
	if off.DNS.IndexFirstSeen() {
		t.Error("enabled: false did not turn the index off")
	}

	partial := Default()
	if err := unmarshalYAML([]byte("dns:\n  first_seen:\n    max_rows: 25\n"), &partial); err != nil {
		t.Fatal(err)
	}
	if !partial.DNS.IndexFirstSeen() {
		t.Error("setting an unrelated key turned the index off")
	}
	if partial.DNS.FirstSeen.MaxRows != 25 {
		t.Errorf("max_rows = %d, want 25", partial.DNS.FirstSeen.MaxRows)
	}
	if partial.DNS.FirstSeen.MaxNewPerMinute != firstseen.DefaultMaxNewPerMinute {
		t.Error("setting max_rows alone discarded the default budget")
	}
}

// TestZeroBoundsAreRefusedWithTheRemedy.
//
// Both zeroes would produce an index that reports itself as on and records
// nothing — max_rows of 0 evicts everything it writes, and a budget of 0
// admits no new domain ever. That is the same "on, and doing nothing" state
// the rebinding filter refuses, and it gets the same answer.
func TestZeroBoundsAreRefusedWithTheRemedy(t *testing.T) {
	for _, tc := range []struct{ name, yaml, want string }{
		{"zero max_rows", "max_rows: 0", "enabled: false"},
		{"negative max_rows", "max_rows: -5", "at least 1"},
		{"zero budget", "max_new_per_minute: 0", "enabled: false"},
		{"negative budget", "max_new_per_minute: -1", "at least 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			if err := unmarshalYAML([]byte("dns:\n  first_seen:\n    "+tc.yaml+"\n"), &cfg); err != nil {
				t.Fatal(err)
			}
			err := cfg.validateFirstSeen()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the remedy (%q)", err, tc.want)
			}
		})
	}
}

// TestADisabledIndexIsNotValidated. Somebody who switched the feature off
// should not be held to the shape of numbers nothing will read.
func TestADisabledIndexIsNotValidated(t *testing.T) {
	cfg := Default()
	cfg.DNS.FirstSeen.Enabled = false
	cfg.DNS.FirstSeen.MaxRows = -99
	cfg.DNS.FirstSeen.MaxNewPerMinute = 0
	if err := cfg.validateFirstSeen(); err != nil {
		t.Errorf("a disabled index was validated: %v", err)
	}
}

// TestTheBoundsReachTheIndex, so what an operator wrote is what runs.
func TestTheBoundsReachTheIndex(t *testing.T) {
	cfg := Default()
	cfg.DNS.FirstSeen.MaxRows = 1234
	cfg.DNS.FirstSeen.MaxNewPerMinute = 7

	got := cfg.DNS.FirstSeenConfig()
	if got.MaxRows != 1234 || got.MaxNewPerMinute != 7 {
		t.Errorf("translated to %+v", got)
	}
}
