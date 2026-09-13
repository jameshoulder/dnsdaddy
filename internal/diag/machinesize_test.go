package diag

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jameshoulder/dnsdaddy/internal/resources"
)

func machineWith(memoryMB, cpus int) resources.Detected {
	kb := memoryMB * 1024
	return resources.Detect(resources.Options{
		Root:   fstest.MapFS{"proc/meminfo": &fstest.MapFile{Data: []byte(itoaMemInfo(kb))}},
		NumCPU: func() int { return cpus },
	})
}

func itoaMemInfo(kb int) string {
	var b strings.Builder
	b.WriteString("MemTotal: ")
	digits := ""
	for n := kb; n > 0; n /= 10 {
		digits = string(rune('0'+n%10)) + digits
	}
	if digits == "" {
		digits = "0"
	}
	b.WriteString(digits)
	b.WriteString(" kB\n")
	return b.String()
}

func onlyCheck(t *testing.T, checks []Check, name string) Check {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q in %+v", name, checks)
	return Check{}
}

// bannedWords are the terms an operator reading doctor will not know.
//
// This is not a style preference. Every one of these has a plain equivalent
// that says the same thing, and a diagnostic that answers "why is my resolver
// slow?" with a Linux kernel feature name has not answered it. The list is
// asserted rather than reviewed because wording drifts back one commit at a
// time, and nobody notices until somebody who has never read this repository
// tries to use the output.
var bannedWords = []string{
	"pin", "pinned", "pinning", "unpin", "unpinned", "repin",
	"cgroup", "cgroups", "psi", "tier", "tiers", "retract", "retracted",
	"expand_modes", "usable_mb", "memtotal", "memory.max",
	"profile", "profiles", "sqlite", "pragma", "wal", "gogc", "heap",
}

// permitted are the exact strings that may contain a banned word.
//
// One entry, and it is there because the brief that set these rules allows it:
// a doctor remedy may name the configuration key as a fallback, after saying
// in words what to change. "Set the size to Automatic" is the instruction;
// "resources.profile: auto" is for the operator who is editing a file rather
// than clicking anything.
var permitted = []string{"resources.profile"}

// operatorText gathers everything a person would read out of a check.
func operatorText(checks []Check) string {
	var b strings.Builder
	for _, c := range checks {
		b.WriteString(" " + c.Name + " " + c.Summary + " " + c.Action)
		for _, e := range c.Evidence {
			b.WriteString(" " + e)
		}
	}
	return b.String()
}

// TestNothingInTheResourceSectionUsesWordsAnOperatorDoesNotKnow, across every
// state the section can be in.
func TestNothingInTheResourceSectionUsesWordsAnOperatorDoesNotKnow(t *testing.T) {
	states := map[string]MachineSizeInput{
		"automatic on a small box": {
			Sizing: resources.Decide(resources.ProfileAuto, "auto", machineWith(1024, 1)),
			Limits: []string{"answers cached: 10,000"},
		},
		"operator chose too large": {
			Sizing: resources.Decide(resources.ProfileFull, "auto", machineWith(1024, 1)),
		},
		"upgrade with nothing saved": {
			Sizing: resources.Decide(resources.ProfileAuto, "keep", machineWith(1024, 1)),
		},
		"machine could not be read": {
			Sizing: resources.Decide(resources.ProfileAuto, "auto",
				resources.Detect(resources.Options{Root: fstest.MapFS{}, NumCPU: func() int { return 1 }})),
		},
		"both heavy features on a small box": {
			Sizing:           resources.Decide(resources.ProfileAuto, "auto", machineWith(1024, 1)),
			DecisionRecords:  true,
			LocalDNSSECLearn: true,
		},
		"a large database log": {
			Sizing:   resources.Decide(resources.ProfileAuto, "auto", machineWith(4096, 2)),
			WALBytes: 512 << 20,
		},
	}

	for name, in := range states {
		t.Run(name, func(t *testing.T) {
			checks := MachineSize(in)
			if len(checks) == 0 {
				t.Fatal("no checks produced")
			}
			text := strings.ToLower(operatorText(checks))
			for _, ok := range permitted {
				text = strings.ReplaceAll(text, ok, "")
			}
			for _, word := range bannedWords {
				// Whole words only, so that "spinning" is not "pin" and
				// "walk" is not "wal". The forms that would otherwise slip
				// through — "unpin", "cgroups" — are listed explicitly rather
				// than caught by substring, because substring matching here
				// produces false failures on ordinary English and a test that
				// cries wolf gets deleted.
				for _, field := range strings.FieldsFunc(text, func(r rune) bool {
					return !('a' <= r && r <= 'z') && !('0' <= r && r <= '9') && r != '_' && r != '.'
				}) {
					if field == word {
						t.Errorf("the %s state says %q, which an operator will not know.\n%s",
							name, word, text)
					}
				}
			}
		})
	}
}

// TestAnAutomaticSizePassesAndShowsTheDefaultSentence.
func TestAnAutomaticSizePassesAndShowsTheDefaultSentence(t *testing.T) {
	checks := MachineSize(MachineSizeInput{
		Sizing: resources.Decide(resources.ProfileAuto, "auto", machineWith(1024, 1)),
	})
	c := onlyCheck(t, checks, "Machine size")
	if c.Status != StatusPass {
		t.Errorf("status = %v, want PASS", c.Status)
	}
	if !strings.Contains(c.Summary, "1 GB machine") {
		t.Errorf("summary does not name the size in words: %q", c.Summary)
	}
	if !strings.Contains(c.Summary, resources.DefaultSentence) {
		t.Errorf("summary does not carry the standard sentence: %q", c.Summary)
	}
}

// TestChoosingTooLargeASizeWarnsWithSomethingToDo.
func TestChoosingTooLargeASizeWarnsWithSomethingToDo(t *testing.T) {
	c := onlyCheck(t, MachineSize(MachineSizeInput{
		Sizing: resources.Decide(resources.ProfileFull, "auto", machineWith(1024, 1)),
	}), "Machine size")

	if c.Status != StatusWarn {
		t.Fatalf("status = %v, want WARN", c.Status)
	}
	for _, want := range []string{"1 GB machine", "4 GB+ machine", "run out of memory"} {
		if !strings.Contains(c.Summary, want) {
			t.Errorf("summary does not mention %q: %q", want, c.Summary)
		}
	}
	for _, want := range []string{"Automatic", "larger VPS"} {
		if !strings.Contains(c.Action, want) {
			t.Errorf("the remedy does not mention %q: %q", want, c.Action)
		}
	}
}

// TestAnUpgradeSaysNothingWasChanged.
//
// The most important sentence in this section. An operator upgrading must not
// come away thinking limits were applied to their running resolver, and must
// be told the one edit that adopts them.
func TestAnUpgradeSaysNothingWasChanged(t *testing.T) {
	c := onlyCheck(t, MachineSize(MachineSizeInput{
		Sizing: resources.Decide(resources.ProfileAuto, "keep", machineWith(1024, 1)),
	}), "Machine size")

	if c.Status != StatusWarn {
		t.Errorf("status = %v, want WARN", c.Status)
	}
	for _, want := range []string{"No size saved yet", "1 GB machine", "Nothing was changed"} {
		if !strings.Contains(c.Summary, want) {
			t.Errorf("summary does not say %q: %q", want, c.Summary)
		}
	}
	if !strings.Contains(c.Action, "Automatic") || !strings.Contains(c.Action, "restart") {
		t.Errorf("the remedy does not say what to do: %q", c.Action)
	}
}

// TestAnUnreadableMachineWarnsAndNeverFails.
//
// Not being able to read how much memory a box has is a gap in what this
// program can see, not a fault in the operator's deployment. Reporting it as a
// failure would make `dnsdaddy doctor` exit non-zero — and so fail a
// deployment script — on a container runtime that lays its files out
// differently.
func TestAnUnreadableMachineWarnsAndNeverFails(t *testing.T) {
	blind := resources.Detect(resources.Options{
		Root: fstest.MapFS{}, NumCPU: func() int { return 4 }})
	checks := MachineSize(MachineSizeInput{
		Sizing: resources.Decide(resources.ProfileAuto, "auto", blind),
	})
	for _, c := range checks {
		if c.Status == StatusFail {
			t.Errorf("an unreadable machine produced a FAIL: %q", c.Summary)
		}
	}
	c := onlyCheck(t, checks, "Machine size")
	if c.Status != StatusWarn {
		t.Errorf("status = %v, want WARN", c.Status)
	}
}

// TestTheLimitsBlockIsPrintedWhenThereAreLimits, since that block is the
// answer to "what does this size actually do?".
func TestTheLimitsBlockIsPrintedWhenThereAreLimits(t *testing.T) {
	in := MachineSizeInput{
		Sizing: resources.Decide(resources.ProfileAuto, "auto", machineWith(1024, 1)),
		Limits: []string{"answers cached: 10,000", "query history kept: 3 days"},
		KeptByOperator: []string{
			"domains remembered as seen before: 5,000, as you set it",
		},
	}
	c := onlyCheck(t, MachineSize(in), "Limits in force")
	joined := strings.Join(c.Evidence, " | ")
	for _, want := range []string{"10,000", "3 days", "as you set it"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the limits block does not mention %q: %s", want, joined)
		}
	}
}

// TestHeavyFeaturesOnASmallMachineAreNamed, and only there: on a larger
// machine these are a reasonable thing to run, and warning would train an
// operator to ignore the section.
//
// A fresh install switches local DNSSEC Learn on before it knows how large the
// machine is — that is a first-run decision this feature deliberately does not
// touch — so on a 1 GB box it is entirely normal to find it on and unasked
// for. Saying so is the point.
func TestHeavyFeaturesOnASmallMachineAreNamed(t *testing.T) {
	small := MachineSizeInput{
		Sizing:           resources.Decide(resources.ProfileAuto, "auto", machineWith(1024, 1)),
		DecisionRecords:  true,
		LocalDNSSECLearn: true,
	}
	c := onlyCheck(t, MachineSize(small), "Heavy features on a small machine")
	if c.Status != StatusWarn {
		t.Errorf("status = %v, want WARN", c.Status)
	}
	if !strings.Contains(c.Action, "2 GB VPS") {
		t.Errorf("the remedy does not offer the alternative: %q", c.Action)
	}

	big := small
	big.Sizing = resources.Decide(resources.ProfileAuto, "auto", machineWith(8192, 4))
	for _, c := range MachineSize(big) {
		if c.Name == "Heavy features on a small machine" {
			t.Error("a 4 GB machine was warned about features it can afford")
		}
	}

	// One alone is still reported on a small machine, because the published
	// budget for that size does not include either of them — but the remedy is
	// softer, since one may well be fine.
	one := small
	one.DecisionRecords = false
	c = onlyCheck(t, MachineSize(one), "Heavy features on a small machine")
	if !strings.Contains(c.Summary, "Local DNSSEC Learn is on") {
		t.Errorf("one feature is not named in the singular: %q", c.Summary)
	}
	if strings.Contains(c.Action, "Turn them off or") {
		t.Errorf("one feature got the two-feature remedy: %q", c.Action)
	}

	// And nothing on means nothing said.
	none := small
	none.DecisionRecords, none.LocalDNSSECLearn = false, false
	for _, c := range MachineSize(none) {
		if c.Name == "Heavy features on a small machine" {
			t.Error("a small machine with neither feature on was warned anyway")
		}
	}
}

// TestALargeDatabaseLogIsReportedInWords.
func TestALargeDatabaseLogIsReportedInWords(t *testing.T) {
	quiet := MachineSizeInput{
		Sizing:   resources.Decide(resources.ProfileAuto, "auto", machineWith(4096, 2)),
		WALBytes: 8 << 20,
	}
	for _, c := range MachineSize(quiet) {
		if c.Name == "Database log file is large" {
			t.Error("an 8 MB log was reported as large")
		}
	}

	loud := quiet
	loud.WALBytes = 2 << 30
	c := onlyCheck(t, MachineSize(loud), "Database log file is large")
	if !strings.Contains(c.Summary, "2.0 GB") {
		t.Errorf("the size is not readable: %q", c.Summary)
	}
}

// TestEverySectionIsTheResourceSection, so the output has one findable place
// for this rather than lines scattered under SYSTEM.
func TestEverySectionIsTheResourceSection(t *testing.T) {
	checks := MachineSize(MachineSizeInput{
		Sizing:           resources.Decide(resources.ProfileAuto, "auto", machineWith(1024, 1)),
		Limits:           []string{"answers cached: 10,000"},
		DecisionRecords:  true,
		LocalDNSSECLearn: true,
		WALBytes:         1 << 30,
	})
	if len(checks) < 4 {
		t.Fatalf("expected every kind of check, got %d", len(checks))
	}
	for _, c := range checks {
		if c.Section != SectionResource {
			t.Errorf("%q is in section %q, want %q", c.Name, c.Section, SectionResource)
		}
	}
}

// TestNoDecisionProducesNoChecks.
//
// A caller that never worked out a size has told this function nothing, and
// the difference between "nothing was decided" and "an upgrade was
// deliberately left alone" matters: only one of them is a finding. Reporting
// the first as the second produced the sentence "This looks like a ." with the
// size missing, which is worse than silence.
func TestNoDecisionProducesNoChecks(t *testing.T) {
	if checks := MachineSize(MachineSizeInput{}); len(checks) != 0 {
		t.Errorf("a zero decision produced %d checks: %+v", len(checks), checks)
	}
	// A genuine upgrade still reports, so this is not silencing the case that
	// matters.
	upgrade := MachineSize(MachineSizeInput{
		Sizing: resources.Decide(resources.ProfileAuto, "keep", machineWith(1024, 1)),
	})
	if len(upgrade) == 0 {
		t.Error("a real upgrade produced no checks")
	}
}

// TestAMachineThatHasNeverRunIsNotToldItUpgraded.
//
// Both situations leave the record empty, and they are opposites. An
// installation with no database has never started and will size itself the
// moment it does; one with a database and no record has been running for a
// year and is deliberately being left alone. Telling the first "nothing was
// changed, set it to Automatic and restart" is advice about a resolver that
// does not exist, and it arrives at exactly the moment somebody is checking a
// new box before starting it.
func TestAMachineThatHasNeverRunIsNotToldItUpgraded(t *testing.T) {
	fresh := MachineSize(MachineSizeInput{
		NoDatabase: true,
		Sizing:     resources.Decide(resources.ProfileAuto, "", machineWith(1024, 1)),
	})
	c := onlyCheck(t, fresh, "Machine size")
	if c.Status != StatusPass {
		t.Errorf("status = %v, want PASS on a machine that has not started yet", c.Status)
	}
	if strings.Contains(c.Summary, "No size saved yet") {
		t.Errorf("a machine that has never run was told it upgraded: %q", c.Summary)
	}
	if !strings.Contains(c.Summary, "1 GB machine") {
		t.Errorf("the summary does not say what it will choose: %q", c.Summary)
	}
	if c.Action != "" {
		t.Errorf("a machine with nothing to fix was given something to do: %q", c.Action)
	}

	// A real upgrade — a database that exists with no record in it — still
	// gets the warning, so this is a distinction rather than a silencing.
	upgrade := onlyCheck(t, MachineSize(MachineSizeInput{
		Sizing: resources.Decide(resources.ProfileAuto, "", machineWith(1024, 1)),
	}), "Machine size")
	if upgrade.Status != StatusWarn || !strings.Contains(upgrade.Summary, "No size saved yet") {
		t.Errorf("a real upgrade no longer warns: %v %q", upgrade.Status, upgrade.Summary)
	}
}
