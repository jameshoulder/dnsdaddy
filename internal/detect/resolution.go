package detect

import (
	"fmt"
	"time"
)

// ResolutionFailureDetector reports domains that consistently fail to resolve
// upstream.
//
// SERVFAIL means the upstream could not produce an answer it was willing to
// stand behind. The causes worth separating are:
//
//	the domain's authoritative servers are down or unreachable
//	the delegation is broken
//	DNSSEC validation failed — a bad signature, an expired RRSIG, a broken
//	chain of trust, or an algorithm the validator does not implement
//	the upstream itself is having a bad day
//
// DNS Daddy forwards to validating upstreams; it does not validate locally.
// That means it observes the *outcome* of validation and cannot see which of
// those causes applies — a validating resolver returns SERVFAIL for a bogus
// answer and SERVFAIL for an unreachable nameserver, and the wire response
// looks the same. So this detector reports the failure honestly as a
// resolution failure, lists DNSSEC validation among the causes, and stops
// there. Calling it a "DNSSEC validation failure" would be claiming a
// distinction the telemetry does not support.
//
// Deliberately carries no MITRE ATT&CK mapping. See mitre.go.
type ResolutionFailureDetector struct {
	cfg   ResolutionFailureConfig
	track *tracker[*resolutionState]
}

// ResolutionFailureConfig holds the tunable thresholds.
type ResolutionFailureConfig struct {
	Window     time.Duration
	MaxTracked int

	MinFailures int
	// MinFailureRatio requires that most lookups for the domain fail, so a
	// popular domain with occasional upstream hiccups stays quiet.
	MinFailureRatio float64

	FullConfidenceFailures int
}

// DefaultResolutionFailureConfig returns the shipped thresholds.
func DefaultResolutionFailureConfig() ResolutionFailureConfig {
	return ResolutionFailureConfig{
		Window:                 10 * time.Minute,
		MaxTracked:             4096,
		MinFailures:            5,
		MinFailureRatio:        0.5,
		FullConfidenceFailures: 100,
	}
}

type resolutionState struct {
	queries  int
	failures int
	clients  *boundedSet
	// validated counts answers the upstream marked as DNSSEC-validated, which
	// establishes that the domain is signed and that validation was working
	// for it earlier in the window.
	validated  int
	sampleName string
	networkID  string
}

// NewResolutionFailureDetector builds a resolution-failure detector.
func NewResolutionFailureDetector(cfg ResolutionFailureConfig) *ResolutionFailureDetector {
	if cfg.Window <= 0 {
		cfg = DefaultResolutionFailureConfig()
	}
	return &ResolutionFailureDetector{
		cfg: cfg,
		track: newTracker(cfg.MaxTracked, cfg.Window, func() *resolutionState {
			return &resolutionState{clients: newBoundedSet(256)}
		}),
	}
}

// Name implements Detector.
func (d *ResolutionFailureDetector) Name() string { return "resolution_failure" }

// Info implements Detector.
func (d *ResolutionFailureDetector) Info() DetectorInfo {
	return DetectorInfo{
		Name:      d.Name(),
		EventType: EventResolutionFailed,
		Title:     "Domain failing to resolve upstream",
		Description: "Reports registered domains where most lookups return SERVFAIL. Causes " +
			"include unreachable authoritative servers, broken delegation, DNSSEC validation " +
			"failure at the upstream, and upstream problems. DNS Daddy does not validate " +
			"DNSSEC locally and cannot distinguish between them.",
		Maturity:    MaturityExperimental,
		MaxSeverity: SeverityMedium,
		Window:      d.cfg.Window.String(),
		// No ATT&CK mapping: this is an operational signal, and attaching a
		// technique to infrastructure breakage would be decoration.
		MITRE:       nil,
		SignalNames: []string{"failed_lookups", "failure_ratio", "affected_clients"},
		FalsePositives: []string{
			"Transient upstream problems, which look identical to a broken domain for as long as " +
				"they last.",
			"A domain whose operator has genuinely misconfigured DNSSEC — a real fault, but " +
				"theirs, not an attack.",
			"Network egress problems on the DNS Daddy host itself will produce this for every " +
				"domain at once, which is the tell.",
		},
		Enforces: false,
	}
}

// Observe implements Detector.
func (d *ResolutionFailureDetector) Observe(e *Event) {
	if e.Blocked || !e.HasParent || e.Excluded {
		return
	}

	ent := d.track.get(e.Parent, e.Time)
	s := ent.state
	s.queries++

	if e.AuthenticatedData {
		s.validated++
	}
	if e.NetworkID != "" {
		s.networkID = e.NetworkID
	}

	if !e.ServFail {
		return
	}
	s.failures++
	if e.ClientIP != "" {
		s.clients.add(e.ClientIP)
	}
	if s.sampleName == "" {
		s.sampleName = e.QName
	}
}

// Evaluate implements Detector.
func (d *ResolutionFailureDetector) Evaluate(now time.Time) []Finding {
	var out []Finding
	for _, ent := range d.track.due(now) {
		if f, ok := d.score(ent, now); ok {
			out = append(out, f)
		}
		d.track.reset(ent, now)
	}
	return out
}

// Sweep implements Detector.
func (d *ResolutionFailureDetector) Sweep(now time.Time) { d.track.sweep(now) }

// Tracked implements Detector.
func (d *ResolutionFailureDetector) Tracked() int { return d.track.len() }

func (d *ResolutionFailureDetector) score(ent *entry[*resolutionState], now time.Time) (Finding, bool) {
	s := ent.state
	if s.failures < d.cfg.MinFailures || s.queries == 0 {
		return Finding{}, false
	}
	ratio := float64(s.failures) / float64(s.queries)
	if ratio < d.cfg.MinFailureRatio {
		return Finding{}, false
	}

	signals := []Signal{
		signal("failed_lookups",
			"SERVFAIL responses for this registered domain within the window.",
			float64(s.failures), 5, 100, 0.50),
		signal("failure_ratio",
			"Share of lookups for this domain that failed. A domain that sometimes works is a "+
				"different problem from one that never does.",
			ratio, 0.50, 1.0, 0.30),
		signal("affected_clients",
			"Distinct clients that hit the failure. One client suggests a local problem; many "+
				"point at the domain or the upstream.",
			float64(s.clients.count()), 1, 10, 0.20),
	}

	var score float64
	for _, sig := range signals {
		score += sig.Contribution
	}

	severity := severityFor(score, SeverityMedium)
	if severity.Rank() < SeverityLow.Rank() {
		severity = SeverityLow
	}

	domain := ent.key
	signedNote := "DNS Daddy did not observe a DNSSEC-validated answer for this domain in the window."
	if s.validated > 0 {
		signedNote = fmt.Sprintf(
			"The upstream returned %d DNSSEC-validated answers for this domain earlier in the "+
				"window, so the zone is signed and validation was working for it recently.",
			s.validated)
	}

	return Finding{
		Time:       now,
		EventType:  EventResolutionFailed,
		Severity:   severity,
		Score:      round2(score),
		Confidence: confidenceFor(score, s.failures, d.cfg.MinFailures, d.cfg.FullConfidenceFailures),
		Client:     Client{NetworkID: s.networkID},
		Domain:     domain,
		Title:      "Domain failing to resolve upstream",
		Summary: fmt.Sprintf(
			"%d of %d lookups for %s returned SERVFAIL in %s, affecting %d clients. %s",
			s.failures, s.queries, domain, d.cfg.Window, s.clients.count(), signedNote),
		Signals: signals,
		Evidence: map[string]any{
			"failed_lookups":           s.failures,
			"total_lookups":            s.queries,
			"failure_ratio":            round2(ratio),
			"affected_clients":         s.clients.count(),
			"dnssec_validated_answers": s.validated,
			"example_name":             s.sampleName,
			"local_dnssec_validation":  false,
			"possible_causes": []string{
				"authoritative nameservers unreachable",
				"broken delegation",
				"DNSSEC validation failure at the upstream resolver",
				"upstream resolver problem",
			},
		},
		Window: Window{Start: ent.start, End: now, Queries: s.queries},
		MITRE:  nil,
		FalsePositives: []string{
			"Transient upstream trouble.",
			"A genuine DNSSEC misconfiguration by the domain's own operator.",
			"Egress problems on the DNS Daddy host, which produce this for every domain at once.",
		},
		NextSteps: []string{
			"Check whether other domains are failing at the same time. If they are, the problem " +
				"is DNS Daddy's upstream or its network, not the domain.",
			"Validate independently: `dig +dnssec " + domain + " @9.9.9.9` and " +
				"`delv " + domain + "` will say whether the chain is broken and where.",
			"Verify against an external checker before contacting the domain owner.",
			"If the domain matters to the business, the workaround is an upstream that does not " +
				"validate — understand that this trades authenticity for availability before " +
				"choosing it.",
		},
		Detector: d.Name(),
		Maturity: MaturityExperimental,
	}, true
}
