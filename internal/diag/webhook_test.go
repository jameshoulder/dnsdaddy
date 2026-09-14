package diag

import (
	"strings"
	"testing"
	"time"
)

func working() NotificationsInput {
	return NotificationsInput{
		Configured: true,
		Address:    "https://hooks.slack.com/[redacted]",
		Sent:       12,
		Dropped:    map[string]uint64{},
		LastSendAt: time.Now().UTC().Add(-time.Hour),
	}
}

// TestNoAddressIsAPassAndSaysTheExactSentence.
//
// Sending findings off the machine is a choice, not a missing step. A check
// that warned about the default would be telling an operator their correct
// configuration is wrong, and on a 1 GB box leaving it off is also the right
// answer. One line, no nag.
func TestNoAddressIsAPassAndSaysTheExactSentence(t *testing.T) {
	checks := Notifications(NotificationsInput{})
	if len(checks) != 1 {
		t.Fatalf("%d checks for the default state, want 1", len(checks))
	}
	c := checks[0]
	if c.Status != StatusPass {
		t.Errorf("status = %v, want PASS: leaving this off is normal", c.Status)
	}
	const want = "Findings stay on this machine. Add a notification address if you " +
		"want them sent to Slack, Teams, or another tool."
	if c.Summary != want {
		t.Errorf("summary =\n  %q\nwant\n  %q", c.Summary, want)
	}
	if c.Action != "" {
		t.Errorf("a correct default was given something to do: %q", c.Action)
	}
}

// TestAWorkingAddressPasses, and says where without saying the secret.
func TestAWorkingAddressPasses(t *testing.T) {
	c := Notifications(working())[0]
	if c.Status != StatusPass {
		t.Fatalf("status = %v, want PASS", c.Status)
	}
	if !strings.Contains(c.Summary, "hooks.slack.com") {
		t.Errorf("the summary does not say where findings go: %q", c.Summary)
	}
}

// TestNothingSentYetIsStillAPass. On a quiet network there are no findings, so
// an endpoint that has never been used is working exactly as it should.
func TestNothingSentYetIsStillAPass(t *testing.T) {
	in := working()
	in.Sent, in.LastSendAt = 0, time.Time{}
	c := Notifications(in)[0]
	if c.Status != StatusPass {
		t.Errorf("status = %v, want PASS when nothing has been sent yet", c.Status)
	}
	if !strings.Contains(strings.Join(c.Evidence, " "), "normal on a quiet network") {
		t.Errorf("the evidence does not explain the empty count: %v", c.Evidence)
	}
}

// TestOnlyAnUnusableAddressIsAFailure.
//
// Doctor exits non-zero on a failure and can stop a deployment script, so a
// failure is reserved for the case where the operator asked for something that
// will never happen. Drops are a warning: the findings are still recorded.
func TestOnlyAnUnusableAddressIsAFailure(t *testing.T) {
	bad := NotificationsInput{
		Configured: true,
		URLError:   "must start with https://",
		Dropped:    map[string]uint64{},
	}
	c := Notifications(bad)[0]
	if c.Status != StatusFail {
		t.Errorf("an unusable address = %v, want FAIL", c.Status)
	}
	if !strings.Contains(c.Action, "https://") {
		t.Errorf("the remedy does not say what to write: %q", c.Action)
	}

	for name, in := range map[string]NotificationsInput{
		"not configured": {},
		"working":        working(),
		"dropping": func() NotificationsInput {
			i := working()
			i.Dropped = map[string]uint64{"full": 5}
			return i
		}(),
		"last send failed": func() NotificationsInput {
			i := working()
			i.LastError = "the notification address answered 503"
			return i
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if c := Notifications(in)[0]; c.Status == StatusFail {
				t.Errorf("%s was a FAIL: %q", name, c.Summary)
			}
		})
	}
}

// TestDropsWarnAndSayNothingWasLost.
//
// The thing an operator most needs to know when they see this: the
// notification did not arrive, the finding is still recorded. Without that
// sentence the natural reading is that detection lost something.
func TestDropsWarnAndSayNothingWasLost(t *testing.T) {
	in := working()
	in.Dropped = map[string]uint64{"full": 3, "timeout": 1}
	c := Notifications(in)[0]

	if c.Status != StatusWarn {
		t.Fatalf("status = %v, want WARN", c.Status)
	}
	joined := strings.Join(c.Evidence, " | ")
	if !strings.Contains(joined, "still in the database") {
		t.Errorf("the evidence does not say the findings are kept: %q", joined)
	}
	if !strings.Contains(joined, "4 not delivered") {
		t.Errorf("the evidence does not total the drops: %q", joined)
	}
	if !strings.Contains(c.Action, "Nothing has been lost") {
		t.Errorf("the remedy does not reassure: %q", c.Action)
	}
}

// TestTheCheckNeverPrintsAnUnredactedAddress.
//
// The input carries an already-redacted address by contract, and this pins
// that the check does not reconstruct one or print anything else secret.
func TestTheCheckNeverPrintsAnUnredactedAddress(t *testing.T) {
	in := working()
	in.Address = "https://hooks.slack.com/[redacted]"
	in.LastError = "the notification address answered 503"

	for _, c := range Notifications(in) {
		text := c.Summary + " " + c.Action + " " + strings.Join(c.Evidence, " ")
		for _, secret := range []string{"T00000000", "B00000000", "XXXXXXXX", "services/"} {
			if strings.Contains(text, secret) {
				t.Errorf("the check printed %q: %s", secret, text)
			}
		}
	}
}

// TestTheNotificationsCheckAvoidsWordsAnOperatorDoesNotKnow.
func TestTheNotificationsCheckAvoidsWordsAnOperatorDoesNotKnow(t *testing.T) {
	inputs := []NotificationsInput{{}, working()}
	dropping := working()
	dropping.Dropped = map[string]uint64{"full": 2}
	bad := NotificationsInput{Configured: true, URLError: "must start with https://",
		Dropped: map[string]uint64{}}
	inputs = append(inputs, dropping, bad)

	for _, in := range inputs {
		for _, c := range Notifications(in) {
			text := strings.ToLower(c.Name + " " + c.Summary + " " + c.Action + " " +
				strings.Join(c.Evidence, " "))
			for _, word := range []string{"pin", "cgroup", "psi", "tier", "retract",
				"usable_mb", "ssrf", "sink", "goroutine", "webhook"} {
				for _, field := range strings.FieldsFunc(text, func(r rune) bool {
					return !('a' <= r && r <= 'z') && !('0' <= r && r <= '9') && r != '_'
				}) {
					if field == word {
						t.Errorf("the check says %q, which an operator will not know: %s", word, text)
					}
				}
			}
		}
	}
}
