package diag

import (
	"strings"
	"testing"
)

func healthyDates() ListingDatesInput {
	return ListingDatesInput{
		Available: true, Live: 250_000, History: 12_000, Feeds: 6,
		MaxRows: 400_000, RetentionDays: 90,
	}
}

// TestAWorkingRecordPassesAndSaysWhatItGuarantees.
func TestAWorkingRecordPassesAndSaysWhatItGuarantees(t *testing.T) {
	c := ListingDates(healthyDates())[0]
	if c.Status != StatusPass {
		t.Fatalf("status = %v, want PASS: %s", c.Status, c.Summary)
	}
	if !strings.Contains(c.Summary, "250,000") {
		t.Errorf("the count is not readable: %q", c.Summary)
	}
	joined := strings.Join(c.Evidence, " | ")
	if !strings.Contains(joined, "original first-seen date") {
		t.Errorf("the evidence does not state the property that matters: %q", joined)
	}
	if !strings.Contains(joined, "does not change when the feeds do") {
		t.Errorf("the evidence does not state the snapshot guarantee: %q", joined)
	}
}

// TestAnEmptyRecordOnAFreshInstallIsNotAFault.
//
// Nothing has refreshed yet, so there is nothing to record. Reporting that as
// a fault would teach an operator to ignore this section within a day, and the
// action says plainly that there is nothing to do.
func TestAnEmptyRecordOnAFreshInstallIsNotAFault(t *testing.T) {
	in := healthyDates()
	in.Live, in.History, in.Feeds = 0, 0, 0
	c := ListingDates(in)[0]

	if c.Status == StatusFail {
		t.Errorf("an empty table on a fresh install was a FAIL: %q", c.Summary)
	}
	if c.Status != StatusWarn {
		t.Errorf("status = %v, want WARN", c.Status)
	}
	if !strings.Contains(c.Action, "Nothing to do") {
		t.Errorf("the action does not say it is nothing to fix: %q", c.Action)
	}
	if !strings.Contains(strings.Join(c.Evidence, " "), "normal on a new installation") {
		t.Errorf("the evidence does not explain why it is empty: %v", c.Evidence)
	}
}

// TestOnlyAnUnreadableTableIsAFailure.
//
// Everything else here costs an explanation, never any protection: blocking is
// built from the feeds, and a missing date cannot let a domain through. So a
// failure — which makes doctor exit non-zero and can stop a deployment script
// — is reserved for the one thing that is genuinely broken.
func TestOnlyAnUnreadableTableIsAFailure(t *testing.T) {
	in := healthyDates()
	in.Available = false
	if c := ListingDates(in)[0]; c.Status != StatusFail {
		t.Errorf("an unreadable table = %v, want FAIL", c.Status)
	}

	for name, mutate := range map[string]func(*ListingDatesInput){
		"empty":            func(i *ListingDatesInput) { i.Live, i.History, i.Feeds = 0, 0, 0 },
		"nearly full":      func(i *ListingDatesInput) { i.Live = 390_000 },
		"failing to write": func(i *ListingDatesInput) { i.RecordingFailures = 3 },
		"no ceiling":       func(i *ListingDatesInput) { i.MaxRows = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			in := healthyDates()
			mutate(&in)
			if c := ListingDates(in)[0]; c.Status == StatusFail {
				t.Errorf("%s was reported as a failure: %q", name, c.Summary)
			}
		})
	}
}

// TestANearlyFullRecordWarnsBeforeDatesStartGoingMissing, and says which way
// it discards.
func TestANearlyFullRecordWarnsBeforeDatesStartGoingMissing(t *testing.T) {
	in := healthyDates()
	in.Live, in.History = 320_000, 10_000 // 82.5% of 400,000
	c := ListingDates(in)[0]

	if c.Status != StatusWarn {
		t.Fatalf("status = %v, want WARN at 82%% full", c.Status)
	}
	joined := strings.Join(c.Evidence, " | ")
	if !strings.Contains(joined, "never discarded") {
		t.Errorf("the evidence does not say current listings are protected: %q", joined)
	}

	// Comfortably below the threshold is silent, so the warning means
	// something when it appears.
	in.Live, in.History = 100_000, 1_000
	if c := ListingDates(in)[0]; c.Status != StatusPass {
		t.Errorf("a quarter-full table warned: %q", c.Summary)
	}
}

// TestAFailureToRecordSaysBlockingIsUnaffected.
//
// The thing an operator most needs to know when they see this: the dates went
// stale, the filtering did not. Without that sentence the natural reading of
// "could not record" is that something stopped being blocked.
func TestAFailureToRecordSaysBlockingIsUnaffected(t *testing.T) {
	in := healthyDates()
	in.RecordingFailures = 2
	c := ListingDates(in)[0]

	if c.Status != StatusWarn {
		t.Fatalf("status = %v, want WARN", c.Status)
	}
	if !strings.Contains(strings.Join(c.Evidence, " "), "blocking is unaffected") {
		t.Errorf("the evidence does not say blocking is unaffected: %v", c.Evidence)
	}
}

// TestTheListingDatesCheckAvoidsWordsAnOperatorDoesNotKnow. The same rule the
// machine-size section is held to, applied to this one.
func TestTheListingDatesCheckAvoidsWordsAnOperatorDoesNotKnow(t *testing.T) {
	inputs := []ListingDatesInput{healthyDates(), {}, {Available: true}}
	nearly := healthyDates()
	nearly.Live = 395_000
	failing := healthyDates()
	failing.RecordingFailures = 1
	inputs = append(inputs, nearly, failing)

	for _, in := range inputs {
		for _, c := range ListingDates(in) {
			text := strings.ToLower(c.Name + " " + c.Summary + " " + c.Action + " " +
				strings.Join(c.Evidence, " "))
			for _, word := range []string{"cgroup", "psi", "tier", "retract", "sqlite",
				"upsert", "reconcile", "indicator", "live=0", "off-live", "prune"} {
				if strings.Contains(text, word) {
					t.Errorf("the check says %q, which an operator will not know: %s", word, text)
				}
			}
		}
	}
}
