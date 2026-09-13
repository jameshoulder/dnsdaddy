package diag

import (
	"fmt"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/resources"
)

// SectionResource is where the machine size is reported.
//
// Its own section rather than a line under SYSTEM, because for most operators
// this is the only place they will ever read about sizing and it needs to be
// findable in a page of output.
const SectionResource = "RESOURCE"

// MachineSizeInput describes what to report.
//
// Everything an operator reads comes from here, so the fields are the words
// and numbers rather than the settings behind them: nothing downstream has to
// know what a setting is called in order to explain what it does.
type MachineSizeInput struct {
	// Sizing is what was decided and why.
	Sizing resources.Decision

	// Limits are the ceilings in force, already in words. One line each.
	Limits []string
	// KeptByOperator are ceilings a size left alone because they were set in
	// the configuration file.
	KeptByOperator []string

	// DecisionRecords and LocalDNSSECLearn are the two expensive features. A
	// size never switches either on, so having both running on a small machine
	// is a combination worth naming.
	DecisionRecords  bool
	LocalDNSSECLearn bool

	// ExtraCategoriesOn reports that blocking categories beyond the core set
	// are enabled.
	ExtraCategoriesOn bool

	// WALBytes is the size of the database's write-ahead log.
	WALBytes int64

	// NoDatabase reports that there is no database to read a record from,
	// which on this machine means DNS Daddy has not started yet.
	//
	// It has to be distinguished from an installation that has a database with
	// no size recorded in it. Both leave the record empty, but they are
	// opposite situations: one has never run and will size itself the moment
	// it does; the other has been running for a year and is deliberately being
	// left alone. Telling the first "nothing was changed, set it to Automatic
	// and restart" is advice about a resolver that does not exist yet.
	NoDatabase bool
}

// largeWALBytes is when the write-ahead log is worth mentioning.
//
// It is bounded after each checkpoint, so anything much above that bound means
// either a very busy period in progress or checkpoints that are not happening.
// Both are things an operator on a 25 GB disk would want to know before the
// disk tells them.
const largeWALBytes = 256 << 20

// MachineSize reports what size is running, what that means, and what is
// worth changing.
//
// Every string here is written for somebody who has never read this
// repository. The size is "a 1 GB machine", not a profile name; the remedy is
// what to change, not which Go field holds it.
func MachineSize(in MachineSizeInput) []Check {
	var out []Check
	d := in.Sizing

	// Nothing decided at all. Decide always sets a reason, so an empty one
	// means this process never worked out a size — a caller that did not wire
	// it, or a test harness. Reporting that as a warning about the machine
	// would be inventing a finding out of a missing input, and the words would
	// be nonsense: "this looks like a ." So it says nothing, which is what it
	// knows.
	if d.Reason == "" {
		return nil
	}

	main := Check{Section: SectionResource, Name: "Machine size"}
	switch {
	case in.NoDatabase:
		// Nothing has run here yet. Report what it will choose, which is the
		// useful thing to tell somebody checking a box before they start.
		main.Status = StatusPass
		main.Summary = fmt.Sprintf("This looks like a %s. DNS Daddy will size itself "+
			"for it when it first starts.", d.Detected.Label())
		main.Evidence = []string{
			d.Machine.Describe(),
			"nothing has run on this machine yet, so there is nothing to change",
		}
	case !d.Applied:
		// An upgrade from a release before sizing existed. Nothing has been
		// changed, and saying so plainly matters more than the warning itself:
		// an operator who reads this must not go looking for limits that were
		// silently applied to their running resolver.
		main.Status = StatusWarn
		main.Summary = fmt.Sprintf(
			"No size saved yet. This looks like a %s. Nothing was changed.", d.Detected.Label())
		main.Evidence = []string{
			d.Machine.Describe(),
			"limits are exactly as this installation has been running them",
		}
		main.Action = "Set the size to Automatic and restart if you want the " +
			d.Detected.Label() + " limits applied. In the configuration file that is " +
			"resources.profile: auto."
	case d.Mismatch():
		main.Status = StatusWarn
		main.Summary = fmt.Sprintf("This looks like a %s, but the size is set to %s. "+
			"The box may run out of memory.", d.Detected.Label(), d.Running.Label())
		main.Evidence = []string{d.Machine.Describe()}
		main.Action = "Set the size back to Automatic, or move to a larger VPS."
	case d.Machine.Unreadable:
		// The size is applied and correct to run; what is missing is the
		// evidence for it. Reporting that as a failure would be the program
		// treating its own blind spot as the operator's problem.
		main.Status = StatusWarn
		main.Summary = fmt.Sprintf("Running the %s limits, but this machine's memory "+
			"could not be read.", d.Running.Label())
		main.Evidence = []string{"the smallest size was assumed, which is the safe guess"}
		main.Action = "If this machine has more memory than that, set the size to match it."
	default:
		main.Status = StatusPass
		main.Summary = fmt.Sprintf("%s %s", d.Running.Label()+".", d.Summary())
		main.Evidence = []string{d.Machine.Describe()}
	}
	out = append(out, main)

	if len(in.Limits) > 0 {
		out = append(out, Check{
			Section:  SectionResource,
			Name:     "Limits in force",
			Status:   StatusPass,
			Summary:  "What this size holds before it starts discarding the oldest.",
			Evidence: append(append([]string(nil), in.Limits...), in.KeptByOperator...),
		})
	}

	// The features that cost real memory on a small box.
	//
	// A size never switches either of these on or off, so anything on here is
	// either something the operator asked for or something a fresh install
	// turned on before it knew how large this machine was — which is why this
	// is a warning with the numbers behind it, not a correction.
	//
	// Reported at one feature, not two. The published budget for the smallest
	// size does not include either of them, so an operator running one on a
	// 1 GB box is outside the figures this project has measured, and that is
	// worth saying before the machine says it.
	if d.Applied && d.Running == resources.ProfileTiny && (in.DecisionRecords || in.LocalDNSSECLearn) {
		var on, why []string
		if in.DecisionRecords {
			on = append(on, "decision history")
			why = append(why, "decision history writes a row for every blocked query")
		}
		if in.LocalDNSSECLearn {
			on = append(on, "local DNSSEC Learn")
			why = append(why, "local DNSSEC Learn looks each name up a second time and checks "+
				"its signatures, using memory and processor")
		}
		why = append(why, "the memory figures published for a 1 GB machine do not include "+
			joinWords(on))

		c := Check{
			Section:  SectionResource,
			Name:     "Heavy features on a small machine",
			Status:   StatusWarn,
			Evidence: why,
		}
		if len(on) > 1 {
			c.Summary = "Decision history and local DNSSEC Learn are on, on a 1 GB machine."
			c.Action = "Turn them off or use a 2 GB VPS."
		} else {
			c.Summary = capitaliseFirst(on[0]) + " is on, on a 1 GB machine."
			c.Action = "Leave it if this machine copes. Turn it off, or use a 2 GB VPS, " +
				"if it runs short of memory."
		}
		out = append(out, c)
	}

	if in.WALBytes > largeWALBytes {
		out = append(out, Check{
			Section: SectionResource,
			Name:    "Database log file is large",
			Status:  StatusWarn,
			Summary: fmt.Sprintf("The database's write-ahead log is %s.", humanBytes(in.WALBytes)),
			Evidence: []string{
				"it is normally trimmed back after each write is settled",
				"a large one means either a very busy period right now, or writes that are not settling",
			},
			Action: "Check free disk space. If this persists while the resolver is idle, " +
				"restart it and please report it.",
		})
	}

	return out
}

// humanBytes renders a file size the way an operator reads one.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f kB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}

// joinWords renders a short list the way a sentence does.
func joinWords(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
	}
}

// capitaliseFirst starts a sentence with a capital, for a phrase assembled
// from a list rather than written out.
func capitaliseFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
