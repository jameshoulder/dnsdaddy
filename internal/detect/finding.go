// Package detect turns DNS query observations into explainable security
// findings.
//
// It is deliberately separate from the resolution path. Nothing in this
// package can block, delay, or fail a DNS answer: the resolver hands
// observations to a buffered channel and moves on, exactly as the query log
// does. If the channel is full, observations are dropped and counted.
//
// Every finding this package emits is an *alert*, never an enforcement action.
// The heuristics here are behavioural, they have false positives, and turning
// a false positive into a block means silently breaking a working network. The
// design point is therefore: observe, score, explain, alert. Blocking remains
// the job of the reputation and policy engine in internal/policy, which is
// driven by curated threat intelligence rather than by inference.
package detect

import (
	"strings"
	"time"
)

// SchemaVersion identifies the finding document format. Consumers (SIEM
// pipelines, Wazuh decoders, dashboards) key off this, so it changes only when
// the shape changes in a way that would break a parser.
//
// The compatibility promise: within a major version, fields may be added but
// never removed or repurposed.
const SchemaVersion = "1.0"

// Severity is the operational weight of a finding.
//
// It answers "how much should this interrupt someone", which is not the same
// question as Confidence ("how sure are we"). A high-confidence advertising
// beacon is still informational; a medium-confidence tunnelling signal on a
// server VLAN is worth a look tonight.
type Severity string

const (
	// SeverityInfo is telemetry worth keeping but not worth waking anyone for.
	SeverityInfo Severity = "info"
	// SeverityLow is a hunting lead: interesting in aggregate, weak alone.
	SeverityLow Severity = "low"
	// SeverityMedium warrants investigation during the working day.
	SeverityMedium Severity = "medium"
	// SeverityHigh warrants investigation now.
	SeverityHigh Severity = "high"
)

// Rank returns an ordering weight, so callers can sort or threshold without
// hard-coding the string set.
func (s Severity) Rank() int {
	switch s {
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// Valid reports whether s is a severity the engine emits.
func (s Severity) Valid() bool { return s.Rank() > 0 }

// ParseSeverity converts a string to a Severity, reporting whether it was one.
func ParseSeverity(s string) (Severity, bool) {
	v := Severity(strings.ToLower(strings.TrimSpace(s)))
	return v, v.Valid()
}

// Event types. These are stable identifiers: they appear in stored findings,
// exported NDJSON, and SIEM rules, so renaming one is a breaking change.
const (
	EventTunnelSuspected  = "dns_tunnel_suspected"
	EventBeaconing        = "dns_beaconing_suspected"
	EventNXDomainBurst    = "nxdomain_burst"
	EventTXTAnomaly       = "txt_activity_anomaly"
	EventDGALike          = "dga_like_domains"
	EventResolutionFailed = "resolution_failure_burst"
)

// Signal is one measured input to a finding's score.
//
// Signals are the reason a finding exists, and they are recorded individually
// rather than collapsed into a single number because "suspicious DNS traffic"
// is not actionable and "412 unique subdomains under one parent, mean label
// entropy 4.4 bits per character, 91% of them NXDOMAIN" is.
type Signal struct {
	// Name is a stable machine identifier, e.g. "unique_subdomains".
	Name string `json:"name"`
	// Description explains what was measured, in words an analyst who has
	// never read this source file can act on.
	Description string `json:"description"`
	// Value is the measurement.
	Value float64 `json:"value"`
	// Floor is the value at which this signal starts contributing, and Ceiling
	// the value at which it contributes fully. Exposing both makes a score
	// reproducible by hand: an analyst can see exactly how far into the band a
	// measurement fell.
	Floor   float64 `json:"floor"`
	Ceiling float64 `json:"ceiling"`
	// Normalised is Value mapped onto 0..1 by the floor/ceiling ramp.
	Normalised float64 `json:"normalised"`
	// Weight is this signal's share of the detector's total score.
	Weight float64 `json:"weight"`
	// Contribution is Normalised * Weight — what this signal actually added.
	Contribution float64 `json:"contribution"`
}

// Technique is a MITRE ATT&CK mapping.
//
// Rationale is required by convention in this package. An ATT&CK ID with no
// explanation of why it applies is decoration: it makes a finding look
// authoritative without making it more useful, and it pollutes any coverage
// measurement built on top of it.
type Technique struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Tactic    string `json:"tactic"`
	URL       string `json:"url"`
	Rationale string `json:"rationale"`
	// Hypothesis marks a mapping that describes what the behaviour *would* be
	// if the finding is a true positive, rather than something the evidence
	// establishes on its own. NXDOMAIN bursts are the clearest case: they are
	// the expected observable of a DGA, and also of a laptop with a stale
	// search domain.
	Hypothesis bool `json:"hypothesis"`
}

// Window describes the observation period a finding was drawn from.
type Window struct {
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Queries int       `json:"queries"`
}

// Client identifies who asked.
//
// IP and Name are empty when log.log_client_ip is off. A finding is still
// emitted in that case — the behaviour happened — but it is attributed to the
// network rather than the device, which is the honest limit of what the
// operator chose to record.
type Client struct {
	IP        string `json:"ip,omitempty"`
	Name      string `json:"name,omitempty"`
	NetworkID string `json:"networkId,omitempty"`
}

// Finding is one explainable security observation.
//
// The JSON encoding of this struct is the integration contract: it is what
// lands in the NDJSON sink, what /api/v1/findings returns, and what a SIEM
// ingests. See docs/siem.md.
type Finding struct {
	SchemaVersion string    `json:"schemaVersion"`
	ID            string    `json:"id"`
	Time          time.Time `json:"time"`
	EventType     string    `json:"eventType"`
	Severity      Severity  `json:"severity"`

	// Confidence is how strongly the evidence supports the stated conclusion,
	// on 0..1. It is derived from the score and then damped by sample size:
	// the same score over 40 queries is less trustworthy than over 400, and
	// pretending otherwise is how behavioural detection loses an analyst's
	// trust.
	Confidence float64 `json:"confidence"`
	// Score is the raw weighted signal total before sample-size damping.
	Score float64 `json:"score"`

	Client Client `json:"client"`
	// Domain is the subject of the finding: the registered domain for
	// tunnelling, the exact name for beaconing, empty for client-wide findings.
	Domain string `json:"domain,omitempty"`
	QType  string `json:"qtype,omitempty"`

	// Title is a short human label, e.g. "Possible DNS tunnelling".
	Title string `json:"title"`
	// Summary is one sentence stating the conclusion and its basis.
	Summary string `json:"summary"`

	Signals  []Signal       `json:"signals"`
	Evidence map[string]any `json:"evidence"`
	Window   Window         `json:"window"`

	MITRE []Technique `json:"mitre"`

	// FalsePositives lists the benign explanations that produce this shape of
	// traffic. It ships inside the finding rather than living only in the
	// documentation because the moment an analyst needs it is the moment they
	// are looking at the alert.
	FalsePositives []string `json:"falsePositives"`
	// NextSteps is the short investigation path for this finding type.
	NextSteps []string `json:"nextSteps"`

	// Detector names the heuristic that produced this, and Maturity states how
	// much weight it should carry. See Maturity.
	Detector string   `json:"detector"`
	Maturity Maturity `json:"maturity"`
}

// Maturity states how well-validated a detector is.
//
// This is published in every finding, in the API, and in the documentation,
// because the alternative — presenting a heuristic written last month with the
// same authority as a curated threat feed — is how a security tool teaches
// people to ignore it.
type Maturity string

const (
	// MaturityAvailable means the detector is tested against benign and
	// malicious synthetic traffic, its thresholds are documented, and its
	// false-positive profile is understood.
	MaturityAvailable Maturity = "available"
	// MaturityExperimental means the logic works and is tested, but the
	// thresholds have not been validated against enough real-world traffic to
	// promise a false-positive rate. Treat these as hunting leads.
	MaturityExperimental Maturity = "experimental"
)

// severityFor maps a score onto a severity, bounded by the detector's ceiling.
//
// The ceiling exists because some behaviours are inherently ambiguous no
// matter how cleanly they score. Regular DNS timing is the example: perfect
// periodicity is exactly what a C2 implant does and exactly what a software
// updater does, so beaconing is capped at medium however tidy the maths looks.
func severityFor(score float64, ceiling Severity) Severity {
	var s Severity
	switch {
	case score >= 0.75:
		s = SeverityHigh
	case score >= 0.55:
		s = SeverityMedium
	case score >= 0.40:
		s = SeverityLow
	default:
		s = SeverityInfo
	}
	if ceiling.Valid() && s.Rank() > ceiling.Rank() {
		return ceiling
	}
	return s
}

// confidenceFor damps a score by how much evidence it rests on.
//
// samples below floor are not enough to conclude anything and are gated out by
// the detectors before reaching here; between floor and full the confidence is
// scaled from 0.7 to 1.0 of the score. A detector firing on the bare minimum
// sample says so in its confidence rather than in a footnote.
func confidenceFor(score float64, samples, floor, full int) float64 {
	if full <= floor {
		return round2(clamp01(score))
	}
	frac := float64(samples-floor) / float64(full-floor)
	frac = clamp01(frac)
	return round2(clamp01(score * (0.7 + 0.3*frac)))
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// round2 keeps emitted floats readable and stable across platforms, so a
// finding serialised on arm64 compares equal to the same finding on amd64.
func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}
