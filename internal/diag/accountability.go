package diag

import (
	"fmt"
	"time"
)

// AccountabilityInput describes whether this installation can say why it did
// what it did.
type AccountabilityInput struct {
	// DecisionsEnabled is log.decision_records.
	DecisionsEnabled bool
	// DecisionRows and DecisionRetentionDays describe the record.
	DecisionRows          int64
	DecisionRetentionDays int

	// AuditRows, AuditRetentionDays and LastAuditAt describe the audit log.
	// LastAuditAt is the zero time when nothing has been written.
	AuditRows          int64
	AuditRetentionDays int
	LastAuditAt        time.Time

	// DecisionsDropped and AuditDropped are runtime counters, visible only to
	// the running daemon. Zero from dnsdaddy doctor, which reads the database
	// rather than the process.
	DecisionsDropped uint64
	AuditDropped     uint64

	// SchemaPresent reports whether the tables exist.
	SchemaPresent bool
}

// shortAuditRetention is the window below which an audit log stops being
// useful for the thing it is for.
//
// Thirty days, because the question an audit log answers is "what changed
// before this started?" about an incident somebody noticed late — and a month
// is roughly how late "late" tends to be. Shorter is a choice an operator may
// have made deliberately, so it warns rather than fails.
const shortAuditRetention = 30

// Accountability reports whether the record of decisions and changes is
// intact.
//
// Empty tables are not a failure. A fresh install has never blocked anything
// and nobody has edited a policy yet, so zero rows is the correct state and
// reporting it as a problem would teach an operator to ignore this check.
func Accountability(in AccountabilityInput) []Check {
	var out []Check

	dec := Check{Section: SectionSystem, Name: "Decision records"}
	switch {
	case !in.DecisionsEnabled:
		dec.Status = StatusWarn
		dec.Summary = "Blocked queries are not explained. The query log keeps a one-line reason " +
			"with no sources behind it, and nothing records what was true at the time."
		dec.Evidence = []string{"log.decision_records is false"}
		dec.Action = "Set log.decision_records: true if you need to answer \"why was this " +
			"blocked?\" weeks later. Feeds change, so the answer cannot be reconstructed " +
			"afterwards."
	case !in.SchemaPresent:
		dec.Status = StatusFail
		dec.Summary = "Decision records are enabled but the tables are missing, so nothing is being written."
		dec.Evidence = []string{"log.decision_records is true and the decisions table is absent"}
		dec.Action = "This is a schema fault rather than a setting. Check the startup log and please report it."
	default:
		dec.Status = StatusPass
		dec.Summary = fmt.Sprintf("%d decision(s) recorded, kept for %d days.",
			in.DecisionRows, in.DecisionRetentionDays)
		dec.Evidence = []string{
			"each record stores what was true when the decision was made, so a feed " +
				"refreshing later cannot rewrite it",
		}
	}
	out = append(out, dec)

	aud := Check{Section: SectionSystem, Name: "Audit log"}
	switch {
	case !in.SchemaPresent:
		aud.Status = StatusFail
		aud.Summary = "The audit log table is missing, so configuration changes are not being recorded."
		aud.Action = "This is a schema fault rather than a setting. Check the startup log and please report it."
	default:
		aud.Status = StatusPass
		aud.Summary = fmt.Sprintf("%d change(s) recorded, kept for %d days.",
			in.AuditRows, in.AuditRetentionDays)
		ev := []string{"policy, network, token, provider-credential and mode changes are recorded"}
		if in.LastAuditAt.IsZero() {
			ev = append(ev, "nothing has been changed on this installation yet, which is why the log is empty")
		} else {
			ev = append(ev, "most recent change: "+in.LastAuditAt.UTC().Format(time.RFC3339))
		}
		ev = append(ev, "secrets are redacted before they are written, never on the way out")
		aud.Evidence = ev
	}
	out = append(out, aud)

	if in.AuditRetentionDays > 0 && in.AuditRetentionDays < shortAuditRetention {
		out = append(out, Check{
			Section: SectionSystem,
			Name:    "Audit retention is short",
			Status:  StatusWarn,
			Summary: fmt.Sprintf("Configuration changes are kept for %d days.", in.AuditRetentionDays),
			Evidence: []string{
				"an audit log answers \"what changed before this started?\", and incidents are " +
					"usually noticed later than that",
			},
			Action: "Raise log.audit_retention_days unless you have a reason to keep less. The " +
				"table grows per configuration change, not per query, so it stays small.",
		})
	}

	// Drops are reported together: both writers drop rather than delaying the
	// thing they describe, and both leave the same kind of hole.
	if in.DecisionsDropped > 0 || in.AuditDropped > 0 {
		out = append(out, Check{
			Section: SectionSystem,
			Name:    "Records dropped under load",
			Status:  StatusWarn,
			Summary: fmt.Sprintf("%d decision record(s) and %d audit entr(ies) were not written.",
				in.DecisionsDropped, in.AuditDropped),
			Evidence: []string{
				"both writers drop rather than delaying what they describe — a DNS answer, or " +
					"a change that has already committed",
				"the decisions and changes themselves took effect; only the record of them is incomplete",
			},
			Action: "Expected under a burst. Sustained, it means the database cannot keep up and " +
				"\"why was this blocked?\" will have gaps.",
		})
	}

	return out
}
