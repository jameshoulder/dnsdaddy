package resources

import (
	"strings"
	"testing"
	"testing/fstest"
)

func machineOf(memoryMB, cpus int) Detected {
	f := fstest.MapFS{"proc/meminfo": &fstest.MapFile{
		Data: []byte("MemTotal: " + itoa(memoryMB*1024) + " kB\n")}}
	return Detect(Options{Root: f, NumCPU: func() int { return cpus }})
}

// TestAFreshInstallSizesItselfFromTheMachine — the case the whole feature
// exists for, and the only one where limits change without anybody asking.
func TestAFreshInstallSizesItselfFromTheMachine(t *testing.T) {
	d := Decide(ProfileAuto, "auto", machineOf(1024, 1))
	if d.Running != ProfileTiny {
		t.Errorf("running = %q, want tiny on a 1 GB machine", d.Running)
	}
	if d.Reason != ReasonAutomatic {
		t.Errorf("reason = %q, want automatic", d.Reason)
	}
	if !d.Applied {
		t.Error("a fresh install did not apply a size")
	}
	if d.Summary() != DefaultSentence {
		t.Errorf("summary = %q, want the default sentence", d.Summary())
	}
}

// TestAnUpgradeIsLeftExactlyAsItWas.
//
// The load-bearing half. An installation that has been keeping a week of query
// history and filtering with a particular set of limits is doing so because
// that is what it was installed as. A new release applying its own limits
// would change that operator's evidence trail, and their resolver's memory
// use, without anybody deciding anything.
func TestAnUpgradeIsLeftExactlyAsItWas(t *testing.T) {
	for _, installDefault := range []string{"keep", ""} {
		t.Run("record="+installDefault, func(t *testing.T) {
			d := Decide(ProfileAuto, installDefault, machineOf(1024, 1))
			if d.Applied {
				t.Error("an upgrade had a size applied to it")
			}
			if d.Running != "" {
				t.Errorf("running = %q, want none in force", d.Running)
			}
			if d.Reason != ReasonUpgradeKept {
				t.Errorf("reason = %q, want upgrade-kept", d.Reason)
			}
			// The machine is still read, so doctor can say what it would have
			// chosen. Not reading it would leave the operator with a warning
			// and no way to act on it.
			if d.Detected != ProfileTiny {
				t.Errorf("detected = %q, want tiny — the machine was not read", d.Detected)
			}
		})
	}
}

// TestAnOperatorsChoiceWinsOverBothTheMachineAndTheRecord.
func TestAnOperatorsChoiceWinsOverBothTheMachineAndTheRecord(t *testing.T) {
	for _, installDefault := range []string{"auto", "keep", ""} {
		d := Decide(ProfileFull, installDefault, machineOf(1024, 1))
		if d.Running != ProfileFull {
			t.Errorf("record %q: running = %q, want full", installDefault, d.Running)
		}
		if d.Reason != ReasonOperator {
			t.Errorf("record %q: reason = %q, want operator", installDefault, d.Reason)
		}
		if !d.Applied {
			t.Errorf("record %q: an explicit choice was not applied", installDefault)
		}
	}
}

// TestChoosingTooLargeASizeWarnsAndStillObeys.
//
// Obeying matters as much as warning. The operator may be adding memory in an
// hour, or the reading may be wrong inside an unfamiliar runtime, and refusing
// to start over a guess about hardware turns a cosmetic problem into an
// outage. So it runs what it was told and says what it thinks.
func TestChoosingTooLargeASizeWarnsAndStillObeys(t *testing.T) {
	d := Decide(ProfileFull, "auto", machineOf(1024, 1))
	if !d.Mismatch() {
		t.Error("choosing the 4 GB size on a 1 GB machine did not warn")
	}
	if d.Running != ProfileFull {
		t.Errorf("running = %q: the warning overrode the operator", d.Running)
	}

	// Choosing smaller than the machine is not a mismatch. Somebody running
	// DNS Daddy alongside other things on a big box is doing it deliberately,
	// and warning about it would train them to ignore the section.
	if Decide(ProfileTiny, "auto", machineOf(8192, 4)).Mismatch() {
		t.Error("choosing a smaller size than the machine was reported as a mismatch")
	}
	// Matching exactly is not a mismatch either.
	if Decide(ProfileTiny, "auto", machineOf(1024, 1)).Mismatch() {
		t.Error("choosing the size the machine would have chosen was reported as a mismatch")
	}
	// Automatic can never mismatch: it chose the size from the machine.
	if Decide(ProfileAuto, "auto", machineOf(1024, 1)).Mismatch() {
		t.Error("an automatic size reported a mismatch with itself")
	}
}

// TestAnUnreadableMachineNeverContradictsTheOperator.
//
// When nothing could be read, the smallest size is assumed so that the limits
// are safe — but that assumption is not evidence, and using it to tell an
// operator their 4 GB machine is too small would be the program asserting
// something it does not know.
func TestAnUnreadableMachineNeverContradictsTheOperator(t *testing.T) {
	blind := Detect(Options{Root: fstest.MapFS{}, NumCPU: func() int { return 4 }})
	d := Decide(ProfileFull, "auto", blind)
	if !d.Applied || d.Running != ProfileFull {
		t.Fatalf("running = %q, applied = %v", d.Running, d.Applied)
	}
	if d.Mismatch() {
		t.Error("an unreadable machine was used as evidence against the operator's choice")
	}
}

// TestEverySummaryIsASentenceAPersonCanRead. These strings are the feature's
// entire interface for most operators.
func TestEverySummaryIsASentenceAPersonCanRead(t *testing.T) {
	for _, d := range []Decision{
		Decide(ProfileAuto, "auto", machineOf(1024, 1)),
		Decide(ProfileSmall, "auto", machineOf(2048, 2)),
		Decide(ProfileAuto, "keep", machineOf(1024, 1)),
	} {
		s := d.Summary()
		if s == "" || !strings.HasSuffix(strings.TrimSpace(s), ".") {
			t.Errorf("summary %q is not a sentence", s)
		}
		for _, jargon := range []string{"pin", "cgroup", "psi", "tier", "retract",
			"usable_mb", "memtotal", "memory.max", "expand_modes", "profile"} {
			if strings.Contains(strings.ToLower(s), jargon) {
				t.Errorf("summary %q contains %q, which an operator will not know", s, jargon)
			}
		}
	}
}

// TestAnUpgradeGetsTheDocumentedDefaultsRatherThanTheSmallestCeilings.
//
// The bug this exists for: an unsized installation has no size to take
// ceilings from, and asking for the ceilings of an empty size falls through to
// the smallest set. That would have shrunk every detector table on precisely
// the installations the upgrade rule promises to leave alone.
func TestAnUpgradeGetsTheDocumentedDefaultsRatherThanTheSmallestCeilings(t *testing.T) {
	upgrade := Decide(ProfileAuto, "keep", machineOf(1024, 1))
	if upgrade.Applied {
		t.Fatal("the test is not exercising the upgrade path")
	}

	const documented = 16384
	if got := upgrade.Caps().DetectorTracked(documented); got != documented {
		t.Errorf("an upgrade scaled a detector from %d to %d; it must be left alone",
			documented, got)
	}
	// And it is genuinely different from the smallest size, so this is not
	// passing because the two happen to agree.
	if CapsFor(ProfileTiny).DetectorTracked(documented) == documented {
		t.Fatal("the smallest size does not scale detectors, so this test proves nothing")
	}

	// A sized installation still gets its size's ceilings.
	sized := Decide(ProfileAuto, "auto", machineOf(1024, 1))
	if sized.Caps().DetectorTracked(documented) != CapsFor(ProfileTiny).DetectorTracked(documented) {
		t.Error("a sized installation did not get its size's detector ceiling")
	}
}

// TestAnUpgradeStillBoundsTheListingDateTable.
//
// The other caps are left alone on an upgrade because they describe behaviour
// that installation already has. The listing-date table has no prior
// behaviour — it is new — so "leave it alone" would mean leaving it unbounded,
// and it grows with the operator's feeds rather than with anything this
// program controls.
func TestAnUpgradeStillBoundsTheListingDateTable(t *testing.T) {
	upgrade := Decide(ProfileAuto, "keep", machineOf(1024, 1))
	if upgrade.Applied {
		t.Fatal("the test is not exercising the upgrade path")
	}
	if got := upgrade.Caps().LifecycleMaxRows; got <= 0 {
		t.Errorf("an upgrade has no ceiling on listing dates (%d); that table would "+
			"grow without limit", got)
	}
	// And a sized installation gets its own size's figure rather than this
	// fallback, so the fallback is not quietly becoming the only value.
	sized := Decide(ProfileAuto, "auto", machineOf(1024, 1))
	if sized.Caps().LifecycleMaxRows != CapsFor(ProfileTiny).LifecycleMaxRows {
		t.Errorf("a sized installation got %d, want the 1 GB figure %d",
			sized.Caps().LifecycleMaxRows, CapsFor(ProfileTiny).LifecycleMaxRows)
	}
}
