package diag

import (
	"strings"
	"testing"
	"time"
)

func accountable() AccountabilityInput {
	return AccountabilityInput{
		DecisionsEnabled: true, SchemaPresent: true,
		DecisionRows: 12, DecisionRetentionDays: 30,
		AuditRows: 4, AuditRetentionDays: 90,
		LastAuditAt: time.Now().UTC().Add(-2 * time.Hour),
	}
}

func namedCheck(checks []Check, name string) *Check {
	for i := range checks {
		if checks[i].Name == name {
			return &checks[i]
		}
	}
	return nil
}

// TestAHealthyInstallationReportsBothRecordsAsPassing, so that a WARN anywhere
// here means something rather than being the permanent state of the check.
func TestAHealthyInstallationReportsBothRecordsAsPassing(t *testing.T) {
	checks := Accountability(accountable())
	for _, name := range []string{"Decision records", "Audit log"} {
		c := namedCheck(checks, name)
		if c == nil {
			t.Fatalf("%q is missing from %+v", name, checks)
		}
		if c.Status != StatusPass {
			t.Errorf("%q = %v, want PASS: %s", name, c.Status, c.Summary)
		}
	}
	if len(checks) != 2 {
		t.Errorf("a healthy installation produced %d checks, want 2: %+v", len(checks), checks)
	}
}

// TestDecisionRecordsOffWarnsAndSaysWhyItCannotBeFixedLater.
//
// The trap this warning exists for is that the cost of leaving it off is
// invisible until somebody asks about a block from last month — at which point
// the feeds have moved and no amount of work reconstructs the answer. So the
// action says that, rather than "consider enabling".
func TestDecisionRecordsOffWarnsAndSaysWhyItCannotBeFixedLater(t *testing.T) {
	in := accountable()
	in.DecisionsEnabled = false
	c := namedCheck(Accountability(in), "Decision records")
	if c.Status != StatusWarn {
		t.Fatalf("status = %v, want WARN", c.Status)
	}
	if !strings.Contains(strings.ToLower(c.Action), "cannot be reconstructed") {
		t.Errorf("the action does not say the answer is unrecoverable later: %q", c.Action)
	}
}

// TestEnabledWithNoTablesIsAFailureNotAWarning. Configured on and not writing
// is the one state where the operator's setting and reality disagree, and an
// operator who believes blocks are being explained when they are not is worse
// off than one who knows they are not.
func TestEnabledWithNoTablesIsAFailureNotAWarning(t *testing.T) {
	in := accountable()
	in.SchemaPresent = false
	checks := Accountability(in)
	if c := namedCheck(checks, "Decision records"); c.Status != StatusFail {
		t.Errorf("decision records = %v, want FAIL", c.Status)
	}
	// The audit log is always on, so a missing table is a fault there too.
	if c := namedCheck(checks, "Audit log"); c.Status != StatusFail {
		t.Errorf("audit log = %v, want FAIL", c.Status)
	}
}

// TestAnEmptyAuditLogOnAFreshInstallIsNotAProblem, and says which kind of
// empty it is. Zero rows because nobody has changed anything is the correct
// state; reporting it as a fault teaches an operator to ignore the check.
func TestAnEmptyAuditLogOnAFreshInstallIsNotAProblem(t *testing.T) {
	in := accountable()
	in.AuditRows = 0
	in.LastAuditAt = time.Time{}
	c := namedCheck(Accountability(in), "Audit log")
	if c.Status != StatusPass {
		t.Fatalf("status = %v, want PASS on a fresh install", c.Status)
	}
	joined := strings.Join(c.Evidence, " ")
	if !strings.Contains(joined, "nothing has been changed") {
		t.Errorf("the evidence does not explain why the log is empty: %q", joined)
	}
}

// TestShortAuditRetentionWarnsSeparately. It is a legitimate choice, so it
// does not downgrade the audit check itself — but an audit log shorter than
// the time it takes to notice an incident answers nothing when it is needed.
func TestShortAuditRetentionWarnsSeparately(t *testing.T) {
	in := accountable()
	in.AuditRetentionDays = 7
	checks := Accountability(in)
	if c := namedCheck(checks, "Audit log"); c.Status != StatusPass {
		t.Errorf("the audit check itself = %v, want PASS — retention is a separate judgement", c.Status)
	}
	c := namedCheck(checks, "Audit retention is short")
	if c == nil || c.Status != StatusWarn {
		t.Fatalf("no WARN for short retention: %+v", checks)
	}

	// And at the boundary and above, it is silent.
	in.AuditRetentionDays = shortAuditRetention
	if namedCheck(Accountability(in), "Audit retention is short") != nil {
		t.Errorf("%d days warned, but that is the threshold itself", shortAuditRetention)
	}
	// Zero means "keep everything", which is the opposite of too short.
	in.AuditRetentionDays = 0
	if namedCheck(Accountability(in), "Audit retention is short") != nil {
		t.Error("keeping everything was reported as keeping too little")
	}
}

// TestDropsAreReportedBecauseTheHolesAreOtherwiseInvisible.
//
// Both writers drop rather than delaying what they describe, so a drop is
// designed behaviour rather than a malfunction — but an explanation nobody can
// produce is indistinguishable from nothing having happened, and this counter
// is the only thing that tells an operator the difference.
func TestDropsAreReportedBecauseTheHolesAreOtherwiseInvisible(t *testing.T) {
	in := accountable()
	if namedCheck(Accountability(in), "Records dropped under load") != nil {
		t.Fatal("a drop was reported with no drops")
	}

	for _, tc := range []struct {
		name           string
		decision, audi uint64
	}{
		{"decisions only", 3, 0},
		{"audit only", 0, 1},
		{"both", 2, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := accountable()
			in.DecisionsDropped, in.AuditDropped = tc.decision, tc.audi
			c := namedCheck(Accountability(in), "Records dropped under load")
			if c == nil || c.Status != StatusWarn {
				t.Fatalf("no WARN for %d/%d drops", tc.decision, tc.audi)
			}
			joined := strings.Join(c.Evidence, " ")
			if !strings.Contains(joined, "took effect") {
				t.Errorf("the evidence does not say the decisions themselves still happened: %q", joined)
			}
		})
	}
}
