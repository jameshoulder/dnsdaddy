package detect

import (
	"fmt"
	"time"
)

// NXDomainDetector looks for bursts of failed lookups from one client.
//
// The framing matters. An individual NXDOMAIN is not suspicious — it is the
// single most common non-success response on any network, produced by typos,
// dead links, and search-suffix expansion all day long. What is worth
// reporting is a *rate*: one host failing hundreds of lookups across dozens of
// unrelated domains in a few minutes is doing something no browser does.
//
// Two exclusions do most of the work in keeping this usable:
//
//	Blocked queries are not counted. DNS Daddy answers a blocked name with
//	NXDOMAIN by default, so counting those would mean the better the filtering
//	works, the more it looks like an incident.
//
//	Names with no registered domain are counted separately and never scored.
//	Single-label lookups, names under .local/.internal/.corp and the like, and
//	the random labels Chrome resolves at startup to detect NXDOMAIN hijacking
//	all land here. Between them they would otherwise dominate the detector on
//	every network that has ever had a search suffix configured.
type NXDomainDetector struct {
	cfg   NXDomainConfig
	track *tracker[*nxState]
}

// NXDomainConfig holds the tunable thresholds.
type NXDomainConfig struct {
	Window     time.Duration
	MaxTracked int

	MinFailures int
	MinQueries  int

	FullConfidenceFailures int
	DomainCap              int
}

// DefaultNXDomainConfig returns the shipped thresholds.
func DefaultNXDomainConfig() NXDomainConfig {
	return NXDomainConfig{
		Window:                 5 * time.Minute,
		MaxTracked:             4096,
		MinFailures:            40,
		MinQueries:             60,
		FullConfidenceFailures: 400,
		DomainCap:              1024,
	}
}

type nxState struct {
	queries  int
	failures int
	// failedParents counts distinct registered domains that failed, which is
	// what separates one dead service from a client walking a domain list.
	failedParents *boundedSet
	failedNames   *boundedSet

	// noSuffixFailures are failures for names with no registered domain.
	// Reported for context, never scored.
	noSuffixFailures int
	blockedQueries   int

	clientName string
	networkID  string
	sampleName string
}

// NewNXDomainDetector builds an NXDOMAIN anomaly detector.
func NewNXDomainDetector(cfg NXDomainConfig) *NXDomainDetector {
	if cfg.Window <= 0 {
		cfg = DefaultNXDomainConfig()
	}
	capacity := cfg.DomainCap
	return &NXDomainDetector{
		cfg: cfg,
		track: newTracker(cfg.MaxTracked, cfg.Window, func() *nxState {
			return &nxState{
				failedParents: newBoundedSet(capacity),
				failedNames:   newBoundedSet(capacity),
			}
		}),
	}
}

// Name implements Detector.
func (d *NXDomainDetector) Name() string { return "nxdomain_anomaly" }

// Info implements Detector.
func (d *NXDomainDetector) Info() DetectorInfo {
	return DetectorInfo{
		Name:      d.Name(),
		EventType: EventNXDomainBurst,
		Title:     "Burst of failed DNS lookups",
		Description: "Scores the rate, ratio and domain spread of NXDOMAIN responses per client. " +
			"Queries blocked by DNS Daddy and names with no registered domain are excluded " +
			"scoring, since both otherwise dominate the measurement.",
		Maturity:    MaturityExperimental,
		MaxSeverity: SeverityMedium,
		Window:      d.cfg.Window.String(),
		MITRE:       nxdomainTechniques(),
		SignalNames: []string{"failed_lookups", "failure_ratio", "distinct_failed_domains"},
		FalsePositives: []string{
			"A stale DNS search suffix causes every short name to be tried against a domain that " +
				"no longer exists.",
			"Captive-portal and connectivity checks deliberately resolve names that should fail.",
			"A decommissioned internal service that clients still reference.",
			"Security scanners and asset-discovery tools enumerate names by design.",
		},
		Enforces: false,
	}
}

// Observe implements Detector.
func (d *NXDomainDetector) Observe(e *Event) {
	ent := d.track.get(e.ClientKey(), e.Time)
	s := ent.state

	if e.Blocked {
		s.blockedQueries++
		return
	}
	if e.Excluded {
		return
	}

	s.queries++
	if e.ClientName != "" {
		s.clientName = e.ClientName
	}
	if e.NetworkID != "" {
		s.networkID = e.NetworkID
	}

	if !e.NXDomain {
		return
	}
	if !e.HasParent {
		s.noSuffixFailures++
		return
	}

	s.failures++
	s.failedParents.add(e.Parent)
	s.failedNames.add(e.QName)
	if s.sampleName == "" {
		s.sampleName = e.QName
	}
}

// Evaluate implements Detector.
func (d *NXDomainDetector) Evaluate(now time.Time) []Finding {
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
func (d *NXDomainDetector) Sweep(now time.Time) { d.track.sweep(now) }

// Tracked implements Detector.
func (d *NXDomainDetector) Tracked() int { return d.track.len() }

func (d *NXDomainDetector) score(ent *entry[*nxState], now time.Time) (Finding, bool) {
	s := ent.state
	if s.failures < d.cfg.MinFailures || s.queries < d.cfg.MinQueries {
		return Finding{}, false
	}

	ratio := float64(s.failures) / float64(s.queries)
	parents := s.failedParents.count()

	signals := []Signal{
		signal("failed_lookups",
			"NXDOMAIN responses received from upstream within the window, excluding names DNS "+
				"Daddy blocked itself and names with no registered domain.",
			float64(s.failures), 50, 500, 0.40),
		signal("failure_ratio",
			"Share of this client's resolvable queries that failed. A high count with a low ratio "+
				"is a busy host; a high count with a high ratio is a host doing little else.",
			ratio, 0.30, 0.90, 0.30),
		signal("distinct_failed_domains",
			"Distinct registered domains that failed. One dead service produces one; a client "+
				"working through a generated list produces many.",
			float64(parents), 10, 100, 0.30),
	}

	var score float64
	for _, sig := range signals {
		score += sig.Contribution
	}

	severity := severityFor(score, SeverityMedium)
	if severity.Rank() < SeverityLow.Rank() {
		return Finding{}, false
	}

	clientIP := clientIPOf(ent.key)

	return Finding{
		Time:       now,
		EventType:  EventNXDomainBurst,
		Severity:   severity,
		Score:      round2(score),
		Confidence: confidenceFor(score, s.failures, d.cfg.MinFailures, d.cfg.FullConfidenceFailures),
		Client: Client{
			IP:        clientIP,
			Name:      s.clientName,
			NetworkID: s.networkID,
		},
		Title: "Burst of failed DNS lookups",
		Summary: fmt.Sprintf(
			"%s received %d NXDOMAIN responses across %d distinct registered domains in %s — "+
				"%.0f%% of its resolvable queries. Example: %s.",
			describeClient(clientIP, s.clientName, s.networkID),
			s.failures, parents, d.cfg.Window, ratio*100, s.sampleName),
		Signals: signals,
		Evidence: map[string]any{
			"queries":                        s.queries,
			"failed_lookups":                 s.failures,
			"failure_ratio":                  round2(ratio),
			"distinct_failed_domains":        parents,
			"distinct_failed_names":          s.failedNames.count(),
			"failures_without_public_suffix": s.noSuffixFailures,
			"blocked_by_policy":              s.blockedQueries,
			"example_name":                   s.sampleName,
		},
		Window: Window{Start: ent.start, End: now, Queries: s.queries},
		MITRE:  nxdomainTechniques(),
		FalsePositives: []string{
			"A stale search suffix in DHCP or on the host.",
			"Connectivity and captive-portal checks.",
			"An internal service that has been decommissioned but is still referenced.",
			"Vulnerability scanners and asset discovery.",
		},
		NextSteps: []string{
			"Read the failing names. Generated names look nothing like typos, and that single " +
				"observation resolves most of these findings in seconds.",
			"Check whether the dga_like_domains detector also fired for this client in the same " +
				"period — together they are a much stronger signal than either alone.",
			"Check whether other hosts on the same subnet show the same failures. Shared failures " +
				"point at configuration; one host alone points at that host.",
			"If the names look generated, treat the endpoint as suspect and preserve the query log " +
				"before it is pruned.",
		},
		Detector: d.Name(),
		Maturity: MaturityExperimental,
	}, true
}
