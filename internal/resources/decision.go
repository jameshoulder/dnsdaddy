package resources

import "fmt"

// Reason is why the running size is what it is. It is a closed set, so it is
// safe as a metric label and there is one sentence per value.
type Reason string

const (
	// ReasonOperator: the operator chose this size.
	ReasonOperator Reason = "operator"
	// ReasonAutomatic: chosen from the machine, on an installation that is
	// sized automatically.
	ReasonAutomatic Reason = "automatic"
	// ReasonUpgradeKept: this installation predates machine sizing, so its
	// limits were left exactly as they were.
	ReasonUpgradeKept Reason = "upgrade-kept"
)

// Decision is the whole answer to "what size is running, and why?".
type Decision struct {
	// Running is the size whose limits apply. On an upgrade that was left
	// alone this is empty: no size is in force.
	Running Profile
	// Detected is what the machine would have been sized as. Always filled in,
	// so that a mismatch between it and Running can be reported.
	Detected Profile
	// Machine is what was read.
	Machine Detected
	// Reason is why Running is what it is.
	Reason Reason
	// Applied reports whether limits were actually changed.
	Applied bool
}

// Decide works out the running size from the operator's setting and this
// installation's record.
//
// installDefault is what seed wrote: "auto" to size from the machine, "keep"
// to leave an upgraded installation alone, or empty when no record exists —
// which is itself the upgrade case, since a fresh install always gets one.
func Decide(configured Profile, installDefault string, machine Detected) Decision {
	d := Decision{Machine: machine, Detected: Choose(machine)}

	if configured != "" && configured != ProfileAuto {
		d.Running, d.Reason, d.Applied = configured, ReasonOperator, true
		return d
	}
	if installDefault == "auto" {
		d.Running, d.Reason, d.Applied = d.Detected, ReasonAutomatic, true
		return d
	}
	// No record, or a record saying leave it alone. Both are upgrades of an
	// installation that has been running some set of limits for a while, and
	// neither is a reason to change them today.
	d.Reason = ReasonUpgradeKept
	return d
}

// Mismatch reports that the operator chose a size larger than this machine
// looks able to run.
//
// Only ever a warning. The operator may know something the program does not —
// memory is about to be added, or the reading is wrong — and refusing to start
// over a guess about hardware would be a worse failure than using more memory
// than is available.
func (d Decision) Mismatch() bool {
	if d.Reason != ReasonOperator || d.Machine.Unreadable {
		return false
	}
	return sizeRank(d.Running) > sizeRank(d.Detected)
}

// sizeRank orders the three sizes so they can be compared.
func sizeRank(p Profile) int {
	switch p {
	case ProfileTiny:
		return 1
	case ProfileSmall:
		return 2
	case ProfileFull:
		return 3
	}
	return 0
}

// Summary is the sentence shown wherever the running size appears.
func (d Decision) Summary() string {
	switch d.Reason {
	case ReasonOperator:
		return fmt.Sprintf("Set to %s.", d.Running.Label())
	case ReasonAutomatic:
		return DefaultSentence
	default:
		return "No size saved yet. Limits are exactly as this installation has been running them."
	}
}

// Caps is the set of ceilings this decision puts in force.
//
// The distinction that matters is the upgrade case. When no size was applied
// there is no size to take ceilings from, and CapsFor would fall through to
// the smallest set — which would quietly shrink an installation that was
// deliberately left alone, in exactly the code path whose whole purpose is to
// change nothing. So an unsized installation gets the documented defaults, and
// this method exists so no caller has to remember that.
func (d Decision) Caps() Caps {
	if !d.Applied {
		return documentedDefaults()
	}
	return CapsFor(d.Running)
}

// documentedDefaults is the ceilings an installation runs when no size applies
// to it: whatever each package's own default already was.
//
// Only the detector scaling is meaningful here — every other field is read
// from the configuration, which an unsized installation keeps untouched — so
// the rest is deliberately left at zero rather than filled in with figures
// nothing will use.
func documentedDefaults() Caps {
	return Caps{DetectorTrackedNumerator: 1, DetectorTrackedDenominator: 1}
}
