package config

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/resources"
)

// TestTheSmallestSizeLowersCeilingsAndTouchesNothingElse.
//
// This is the property the whole feature rests on: sizing is about how much
// state the resolver holds, never about what it does. If applying a size could
// switch something on or off, then changing machine would change the security
// posture of a network, and an operator would have to re-read the
// documentation every time they resized a VPS.
func TestTheSmallestSizeLowersCeilingsAndTouchesNothingElse(t *testing.T) {
	before := Default()
	// Put the feature switches somewhere unmistakable first, so that a change
	// to any of them shows up rather than matching the default by luck.
	on := true
	before.DNS.Rebinding.Enabled = &on
	before.DNS.RateLimit.Enabled = true
	before.DNS.FirstSeen.Enabled = true
	before.Log.DecisionRecords = true
	before.Log.QueryLog = true
	before.Detection.Enabled = true
	before.DNS.LocalDNSSECValidation = LocalDNSSECObserve
	before.Cache.Enabled = true

	after := before
	after.ApplySize(resources.ProfileTiny)

	// Ceilings moved.
	if after.Cache.MaxEntries >= before.Cache.MaxEntries {
		t.Errorf("the answer cache was not lowered: %d", after.Cache.MaxEntries)
	}
	if after.DNS.FirstSeen.MaxRows >= before.DNS.FirstSeen.MaxRows {
		t.Errorf("the first-seen ceiling was not lowered: %d", after.DNS.FirstSeen.MaxRows)
	}
	if after.Log.RetentionDays >= before.Log.RetentionDays {
		t.Errorf("query history was not shortened: %d days", after.Log.RetentionDays)
	}

	// Nothing was switched.
	for _, tc := range []struct {
		name      string
		got, want bool
	}{
		{"the rebinding filter", *after.DNS.Rebinding.Enabled, true},
		{"the rate limiter", after.DNS.RateLimit.Enabled, true},
		{"the first-seen index", after.DNS.FirstSeen.Enabled, true},
		{"decision history", after.Log.DecisionRecords, true},
		{"query logging", after.Log.QueryLog, true},
		{"behavioural detection", after.Detection.Enabled, true},
		{"the answer cache", after.Cache.Enabled, true},
	} {
		if tc.got != tc.want {
			t.Errorf("%s was changed by applying a machine size", tc.name)
		}
	}
	if after.DNS.LocalDNSSECValidation != LocalDNSSECObserve {
		t.Errorf("local DNSSEC validation was changed to %q by applying a machine size",
			after.DNS.LocalDNSSECValidation)
	}
	// And the things a size has no business touching at all.
	if after.DNS.RateLimit.Rate != before.DNS.RateLimit.Rate ||
		after.DNS.RateLimit.Burst != before.DNS.RateLimit.Burst {
		t.Error("the rate limit itself was changed; only the size of its table is a ceiling")
	}
	if len(after.DNS.AllowedClientCIDRs) != len(before.DNS.AllowedClientCIDRs) {
		t.Error("who may use the resolver was changed by applying a machine size")
	}
	if after.Log.AuditRetentionDays != before.Log.AuditRetentionDays {
		t.Error("the audit log's retention was shortened; it grows per operator edit, " +
			"not per query, so machine size is not a reason to keep less of it")
	}
}

// TestALargerMachineRaisesCeilingsAndStillSwitchesNothingOn.
//
// The direction that is easy to get wrong. Finding more memory is a reason to
// remember more; it is not consent to start recording what a network resolves,
// nor to start validating DNSSEC locally. Both of those are decisions about
// what the software does and about what is written down, and neither should
// arrive with a bigger VPS.
func TestALargerMachineRaisesCeilingsAndStillSwitchesNothingOn(t *testing.T) {
	small := Default()
	small.ApplySize(resources.ProfileTiny)
	// The state a 1 GB install is in: history off, local validation off.
	small.Log.DecisionRecords = false
	small.DNS.LocalDNSSECValidation = LocalDNSSECOff

	grown := small
	grown.ApplySize(resources.ProfileFull)

	if grown.DNS.FirstSeen.MaxRows <= small.DNS.FirstSeen.MaxRows {
		t.Errorf("moving to a 4 GB machine did not raise the first-seen ceiling: %d",
			grown.DNS.FirstSeen.MaxRows)
	}
	if grown.Cache.MaxEntries <= small.Cache.MaxEntries {
		t.Error("moving to a 4 GB machine did not raise the answer cache")
	}
	if grown.Log.RetentionDays <= small.Log.RetentionDays {
		t.Error("moving to a 4 GB machine did not lengthen query history")
	}

	if grown.Log.DecisionRecords {
		t.Error("decision history was switched on by moving to a larger machine")
	}
	if grown.DNS.LocalDNSSECValidation != LocalDNSSECOff {
		t.Errorf("local DNSSEC validation was switched to %q by moving to a larger machine",
			grown.DNS.LocalDNSSECValidation)
	}
}

// TestApplyingASizeIsIdempotent, so a restart that re-detects the same machine
// reports no changes rather than a list of things it did not do.
func TestApplyingASizeIsIdempotent(t *testing.T) {
	c := Default()
	first := c.ApplySize(resources.ProfileSmall)
	second := c.ApplySize(resources.ProfileSmall)
	if len(second) != 0 {
		t.Errorf("applying the same size twice reported %d changes the second time: %v",
			len(second), second)
	}
	_ = first
}

// TestTheChangeListIsReadableByAPerson. The list goes into the startup log and
// under a doctor check, so it is the explanation most operators get.
func TestTheChangeListIsReadableByAPerson(t *testing.T) {
	c := Default()
	changes := c.ApplySize(resources.ProfileTiny)
	if len(changes) == 0 {
		t.Fatal("applying the smallest size to the defaults reported no changes")
	}
	joined := strings.ToLower(strings.Join(changes, " | "))
	for _, jargon := range []string{"maxrows", "max_rows", "maxentries", "cache_size",
		"cgroup", "retract", "_mb", "pragma"} {
		if strings.Contains(joined, jargon) {
			t.Errorf("the change list contains %q, which is a setting name rather than "+
				"an explanation: %v", jargon, changes)
		}
	}
	if !strings.Contains(joined, "query history kept") {
		t.Errorf("the change list does not mention query history in words: %v", changes)
	}
}

// TestAMisspelledSizeIsRefusedRatherThanIgnored.
//
// Silently falling back to automatic would make a typo and a deliberate choice
// indistinguishable afterwards, and only one of those is something the
// operator wants to hear about.
func TestAMisspelledSizeIsRefusedRatherThanIgnored(t *testing.T) {
	for _, bad := range []string{"smal", "medium", "large", "1gb", "TINY!"} {
		if err := validateResources(Resources{Profile: bad}); err == nil {
			t.Errorf("%q was accepted as a machine size", bad)
		}
	}
	for _, good := range []string{"", "auto", "AUTO", " tiny ", "small", "full"} {
		if err := validateResources(Resources{Profile: good}); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
}

// TestTheSizeErrorTellsAnOperatorWhatToWrite rather than naming a Go type.
func TestTheSizeErrorTellsAnOperatorWhatToWrite(t *testing.T) {
	err := validateResources(Resources{Profile: "medium"})
	if err == nil {
		t.Fatal("no error")
	}
	msg := err.Error()
	for _, want := range []string{"auto", "1 GB", "2 GB", "4 GB"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q: %s", want, msg)
		}
	}
}

// TestAnImpossibleMemorySettingIsRefused. These are the shapes that would
// otherwise produce a running resolver sized for nothing.
func TestAnImpossibleMemorySettingIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    Resources
	}{
		{"negative memory", Resources{MemoryMB: -1}},
		{"negative reserve", Resources{ReservedMB: -1}},
		{"less memory than a resolver needs", Resources{MemoryMB: 64}},
		{"the reserve eats all of it", Resources{MemoryMB: 512, ReservedMB: 512}},
		{"the reserve eats more than all of it", Resources{MemoryMB: 512, ReservedMB: 1024}},
	} {
		if err := validateResources(tc.r); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
	// And the ordinary shapes are fine.
	for _, r := range []Resources{{}, {MemoryMB: 512}, {MemoryMB: 2048, ReservedMB: 512}, {ReservedMB: 128}} {
		if err := validateResources(r); err != nil {
			t.Errorf("%+v was refused: %v", r, err)
		}
	}
}

// TestTheDefaultIsAutomatic. The whole point is that an operator who never
// opens the file gets a machine-appropriate install.
func TestTheDefaultIsAutomatic(t *testing.T) {
	if got := Default().Resources.SizeProfile(); got != resources.ProfileAuto {
		t.Errorf("the default size is %q, want automatic", got)
	}
}

// TestACeilingTheOperatorSetSurvivesAResize.
//
// Somebody who lowered how many domains are remembered — because their disk is
// nearly full, or because they do not want that much history — must not find
// it raised again by moving to a bigger VPS. A setting is a decision; the size
// only fills in the ones nobody made.
func TestACeilingTheOperatorSetSurvivesAResize(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/dnsdaddy.yaml"
	if err := os.WriteFile(path, []byte(`
dns:
  first_seen:
    max_rows: 5000
log:
  retention_days: 30
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DNS.FirstSeen.MaxRows != 5000 || cfg.Log.RetentionDays != 30 {
		t.Fatalf("the file was not read: %d rows, %d days",
			cfg.DNS.FirstSeen.MaxRows, cfg.Log.RetentionDays)
	}

	changes := cfg.ApplySize(resources.ProfileFull)
	if cfg.DNS.FirstSeen.MaxRows != 5000 {
		t.Errorf("a 4 GB machine raised a ceiling the operator had set to 5000: %d",
			cfg.DNS.FirstSeen.MaxRows)
	}
	if cfg.Log.RetentionDays != 30 {
		t.Errorf("a 4 GB machine changed query history from the configured 30 days to %d",
			cfg.Log.RetentionDays)
	}
	// And the same going the other way: a smaller machine does not discard it
	// either. The operator asked for 5,000; the size has no better idea.
	cfg.ApplySize(resources.ProfileTiny)
	if cfg.DNS.FirstSeen.MaxRows != 5000 {
		t.Errorf("a 1 GB machine overwrote the configured ceiling: %d", cfg.DNS.FirstSeen.MaxRows)
	}

	// The ceilings nobody set still moved, so this is preservation rather than
	// the size doing nothing at all.
	if len(changes) == 0 {
		t.Error("applying a size to a partly-configured file changed nothing")
	}
	if cfg.Cache.MaxEntries != resources.CapsFor(resources.ProfileTiny).AnswerCacheEntries {
		t.Errorf("the answer cache, which nobody configured, was not sized: %d",
			cfg.Cache.MaxEntries)
	}

	// And it is explained rather than left as a puzzle.
	kept := strings.Join(cfg.KeptByOperator(), " | ")
	if !strings.Contains(kept, "5,000") || !strings.Contains(kept, "30 days") {
		t.Errorf("the kept settings are not reported to the operator: %q", kept)
	}
}

// TestWritingTheDefaultValueIsNotTreatedAsASetting.
//
// The honest limit of how "did the operator set this?" is decided: a file that
// writes the default value is indistinguishable from one that omits it. This
// pins that the consequence is harmless — the size applies, which is what they
// would have got anyway — rather than leaving it undocumented.
func TestWritingTheDefaultValueIsNotTreatedAsASetting(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/dnsdaddy.yaml"
	def := Default()
	if err := os.WriteFile(path, []byte(fmt.Sprintf("log:\n  retention_days: %d\n",
		def.Log.RetentionDays)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ApplySize(resources.ProfileTiny)
	want := resources.CapsFor(resources.ProfileTiny).QueryLogRetentionDays
	if cfg.Log.RetentionDays != want {
		t.Errorf("retention = %d, want %d: writing the default value is not a setting",
			cfg.Log.RetentionDays, want)
	}
}

// TestNoSizeTurnsOnABlockingCategory.
//
// Which categories block is a decision about what a network can reach, and it
// belongs to the operator. A 4 GB machine having room for the ads list is not
// a reason to start blocking ads on it: the first anyone would know is a
// colleague reporting that a site stopped working after a VPS upgrade.
//
// Asserted at every size, in both directions, because the tempting version of
// this feature is exactly "we have memory, let's use it".
func TestNoSizeTurnsOnABlockingCategory(t *testing.T) {
	defaultOn := func() []string {
		var out []string
		for _, c := range catalog.Categories {
			if c.DefaultOn {
				out = append(out, c.ID)
			}
		}
		return out
	}

	want := []string{"malware", "phishing", "c2", "cryptomining"}
	before := defaultOn()
	if !slices.Equal(before, want) {
		t.Fatalf("the core set has changed to %v; if that is deliberate, update this test "+
			"and say so in the changelog, because it changes what a new install blocks", before)
	}

	for _, p := range []resources.Profile{
		resources.ProfileTiny, resources.ProfileSmall, resources.ProfileFull,
	} {
		cfg := Default()
		cfg.ApplySize(p)
		if got := defaultOn(); !slices.Equal(got, want) {
			t.Errorf("%s changed which categories block by default: %v", p.Label(), got)
		}
	}

	// The same for the feeds that ship enabled: core categories only, at every
	// size. An extra feed is extra memory and extra blocking, and neither
	// arrives with a bigger box.
	enabled := func() []string {
		var out []string
		for _, f := range catalog.DefaultFeeds {
			if f.Enabled {
				out = append(out, f.Category)
			}
		}
		return out
	}
	core := map[string]bool{"malware": true, "phishing": true, "c2": true, "cryptomining": true}
	for _, p := range []resources.Profile{
		resources.ProfileTiny, resources.ProfileSmall, resources.ProfileFull,
	} {
		cfg := Default()
		cfg.ApplySize(p)
		for _, category := range enabled() {
			if !core[category] {
				t.Errorf("%s ships the %q feed category enabled", p.Label(), category)
			}
		}
	}
}
