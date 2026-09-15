package store

import (
	"context"
	"path/filepath"
	"testing"
)

// learnDefault reads what a database recorded for local DNSSEC validation.
func learnDefault(t *testing.T, st *Store) string {
	t.Helper()
	v, err := st.GetSetting(context.Background(), SettingLocalDNSSECDefault)
	if err != nil {
		t.Fatalf("reading %s: %v", SettingLocalDNSSECDefault, err)
	}
	return v
}

// openAt opens a database at a fixed path so it can be closed and reopened,
// which is how an upgrade is simulated.
func openAt(t *testing.T, path string, o Options) *Store {
	t.Helper()
	st, err := OpenWithOptions(path, o)
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	return st
}

// TestFresh1GBStartsWithLearnOff.
//
// Learn resolves and checks the signatures on each name a second time. It is
// the most expensive default in this tree, and its cost is deliberately
// outside the memory budget published for a 1 GB machine — so a fresh install
// there was creating the situation that doctor then warned about.
func TestFresh1GBStartsWithLearnOff(t *testing.T) {
	st := openAt(t, filepath.Join(t.TempDir(), "tiny.db"), Options{FreshInstallLearn: "off"})
	defer st.Close()

	if got := learnDefault(t, st); got != "off" {
		t.Errorf("a fresh 1 GB install recorded local DNSSEC validation as %q, want off", got)
	}
}

// TestFresh2GBAndAboveStillStartWithLearnOn.
//
// The change is scoped to the machine that cannot afford it. A 2 GB install —
// which is what every release before machine sizing was built for — keeps
// exactly the behaviour it had, and so does anything larger.
func TestFresh2GBAndAboveStillStartWithLearnOn(t *testing.T) {
	for _, hint := range []string{"observe", ""} {
		t.Run("hint="+hint, func(t *testing.T) {
			st := openAt(t, filepath.Join(t.TempDir(), "small.db"), Options{FreshInstallLearn: hint})
			defer st.Close()

			if got := learnDefault(t, st); got != "observe" {
				t.Errorf("a fresh install recorded %q, want observe — this is the "+
					"behaviour every release before machine sizing had", got)
			}
		})
	}
}

// TestPlainOpenIsUnchanged, so the 29 callers that do not care — every test,
// every tool that is not the daemon — keep the behaviour they had.
func TestPlainOpenIsUnchanged(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "plain.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if got := learnDefault(t, st); got != "observe" {
		t.Errorf("Open recorded %q, want observe", got)
	}
}

// TestAnUpgradeKeepsWhateverItRecorded.
//
// The load-bearing half. An installation that has been running Learn for a
// year must go on running it, and one that has been running without it must
// not acquire it — whatever the machine now looks like. The record is written
// once and never revisited.
func TestAnUpgradeKeepsWhateverItRecorded(t *testing.T) {
	for _, first := range []string{"observe", "off"} {
		t.Run("recorded="+first, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "upgrade.db")

			st := openAt(t, path, Options{FreshInstallLearn: first})
			if got := learnDefault(t, st); got != first {
				t.Fatalf("the first run recorded %q, want %q", got, first)
			}
			st.Close()

			// Reopened as the opposite size, the way a restart after a VPS
			// resize would.
			other := "off"
			if first == "off" {
				other = "observe"
			}
			st = openAt(t, path, Options{FreshInstallLearn: other})
			defer st.Close()

			if got := learnDefault(t, st); got != first {
				t.Errorf("an existing installation's setting changed from %q to %q "+
					"when it restarted on a different-sized machine", first, got)
			}
		})
	}
}

// TestASizeChangeNeverFlipsLearn, across every order of sizes an operator
// might move through.
func TestASizeChangeNeverFlipsLearn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "moving.db")

	st := openAt(t, path, Options{FreshInstallLearn: "off"}) // installed on 1 GB
	st.Close()

	// Moved up, then down, then up again.
	for _, hint := range []string{"observe", "off", "observe"} {
		st = openAt(t, path, Options{FreshInstallLearn: hint})
		got := learnDefault(t, st)
		st.Close()
		if got != "off" {
			t.Fatalf("reopening with hint %q changed the recorded setting to %q, "+
				"want the original off", hint, got)
		}
	}
}

// TestTheOtherFirstRunDecisionsAreUntouched.
//
// Rebinding and the machine-size record are decided by the same seed, on their
// own presence keys. A change to one first-run rule must not disturb another:
// a fresh 1 GB install still filters rebinding and still sizes itself.
func TestTheOtherFirstRunDecisionsAreUntouched(t *testing.T) {
	st := openAt(t, filepath.Join(t.TempDir(), "others.db"), Options{FreshInstallLearn: "off"})
	defer st.Close()
	ctx := context.Background()

	if got, err := st.GetSetting(ctx, SettingRebindingDefault); err != nil || got != "on" {
		t.Errorf("rebinding default = %q (err %v), want on for a fresh install", got, err)
	}
	if got, err := st.GetSetting(ctx, SettingMachineSizeDefault); err != nil || got != MachineSizeAuto {
		t.Errorf("machine size default = %q (err %v), want auto for a fresh install", got, err)
	}
}
