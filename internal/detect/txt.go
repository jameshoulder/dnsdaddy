package detect

import (
	"fmt"
	"time"
)

// TXTDetector looks for unusual use of TXT records.
//
// TXT is the only widely permitted record type that carries arbitrary text, so
// it is the natural choice for anything that wants to move data through DNS:
// C2 tasking, staged payloads, and exfiltration all use it. It is also how SPF,
// DKIM, DMARC, MTA-STS, ACME, and roughly every SaaS domain-verification
// scheme in existence publish their policy.
//
// That second list is the entire difficulty. On a network with a mail server,
// TXT lookups are among the most common queries there are, and a detector that
// counts them naively reports the mail server every five minutes forever. So
// the standard infrastructure lookups are identified by their label structure
// and excluded before anything is measured — see txtInfrastructurePrefixes —
// and the count that remains is what gets scored.
type TXTDetector struct {
	cfg   TXTConfig
	track *tracker[*txtState]
}

// TXTConfig holds the tunable thresholds.
type TXTConfig struct {
	Window     time.Duration
	MaxTracked int

	MinTXTQueries int

	FullConfidenceQueries int
	NameCap               int
}

// DefaultTXTConfig returns the shipped thresholds.
func DefaultTXTConfig() TXTConfig {
	return TXTConfig{
		Window:                5 * time.Minute,
		MaxTracked:            4096,
		MinTXTQueries:         25,
		FullConfidenceQueries: 200,
		NameCap:               1024,
	}
}

type txtState struct {
	queries int
	txt     int
	// infrastructure counts the SPF/DKIM/DMARC-style lookups that were
	// excluded, so a finding can show what was filtered out rather than
	// leaving the reader to wonder.
	infrastructure int

	names   *boundedSet
	parents *boundedSet

	entropySum float64
	entropyN   int
	nxdomain   int

	clientName string
	networkID  string
	examples   []string
}

// NewTXTDetector builds a TXT anomaly detector.
func NewTXTDetector(cfg TXTConfig) *TXTDetector {
	if cfg.Window <= 0 {
		cfg = DefaultTXTConfig()
	}
	capacity := cfg.NameCap
	return &TXTDetector{
		cfg: cfg,
		track: newTracker(cfg.MaxTracked, cfg.Window, func() *txtState {
			return &txtState{
				names:   newBoundedSet(capacity),
				parents: newBoundedSet(256),
			}
		}),
	}
}

// Name implements Detector.
func (d *TXTDetector) Name() string { return "txt_anomaly" }

// Info implements Detector.
func (d *TXTDetector) Info() DetectorInfo {
	return DetectorInfo{
		Name:      d.Name(),
		EventType: EventTXTAnomaly,
		Title:     "Unusual TXT record activity",
		Description: "Counts a client's TXT lookups after excluding SPF, DKIM, DMARC, MTA-STS, " +
			"ACME and domain-verification queries, and scores the remainder on volume, share " +
			"of total traffic, distinct names, and label entropy.",
		Maturity:    MaturityExperimental,
		MaxSeverity: SeverityMedium,
		Window:      d.cfg.Window.String(),
		MITRE:       txtTechniques(),
		SignalNames: []string{
			"txt_query_count", "txt_query_ratio", "distinct_txt_names",
			"mean_txt_subdomain_entropy",
		},
		FalsePositives: []string{
			"Mail servers and mail security gateways perform very high volumes of TXT lookups. " +
				"The standard record prefixes are excluded, but a vendor using a non-standard " +
				"selector will not be.",
			"Some licence-check and anti-abuse services distribute state through TXT records.",
			"Domain-verification sweeps during a migration will spike TXT volume legitimately.",
		},
		Enforces: false,
	}
}

// Observe implements Detector.
func (d *TXTDetector) Observe(e *Event) {
	if e.Excluded {
		return
	}

	ent := d.track.get(e.ClientKey(), e.Time)
	s := ent.state
	s.queries++

	if e.ClientName != "" {
		s.clientName = e.ClientName
	}
	if e.NetworkID != "" {
		s.networkID = e.NetworkID
	}

	if e.QType != "TXT" {
		return
	}
	if isTXTInfrastructure(e.QName) {
		s.infrastructure++
		return
	}

	s.txt++
	s.names.add(e.QName)
	if e.HasParent {
		s.parents.add(e.Parent)
	}
	if e.NXDomain {
		s.nxdomain++
	}
	if len(s.examples) < 5 && !containsString(s.examples, e.QName) {
		s.examples = append(s.examples, e.QName)
	}

	for _, label := range labelsOf(e.Sub) {
		if len(label) >= minEntropyLabelLen && !isInternationalised(label) {
			s.entropySum += shannonEntropy(label)
			s.entropyN++
		}
	}
}

// Evaluate implements Detector.
func (d *TXTDetector) Evaluate(now time.Time) []Finding {
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
func (d *TXTDetector) Sweep(now time.Time) { d.track.sweep(now) }

// Tracked implements Detector.
func (d *TXTDetector) Tracked() int { return d.track.len() }

func (d *TXTDetector) score(ent *entry[*txtState], now time.Time) (Finding, bool) {
	s := ent.state
	if s.txt < d.cfg.MinTXTQueries {
		return Finding{}, false
	}

	ratio := 0.0
	if s.queries > 0 {
		ratio = float64(s.txt) / float64(s.queries)
	}
	meanEntropy := 0.0
	if s.entropyN > 0 {
		meanEntropy = s.entropySum / float64(s.entropyN)
	}

	signals := []Signal{
		signal("txt_query_count",
			"TXT lookups in the window after excluding mail, certificate and domain-verification "+
				"records.",
			float64(s.txt), 30, 300, 0.35),
		signal("txt_query_ratio",
			"Share of this client's queries that were TXT. Ordinary end-user devices are well "+
				"under 5%; a mail server is legitimately much higher, which is why volume alone "+
				"does not raise this finding.",
			ratio, 0.10, 0.60, 0.25),
		signal("distinct_txt_names",
			"Distinct names queried for TXT. Reading a policy record means asking for the same "+
				"few names repeatedly; moving data means asking for new ones.",
			float64(s.names.count()), 15, 150, 0.25),
		signal("mean_txt_subdomain_entropy",
			"Mean entropy of long labels below the registered domain in those queries, in bits "+
				"per character.",
			meanEntropy, 3.2, 4.2, 0.15),
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
		EventType:  EventTXTAnomaly,
		Severity:   severity,
		Score:      round2(score),
		Confidence: confidenceFor(score, s.txt, d.cfg.MinTXTQueries, d.cfg.FullConfidenceQueries),
		Client: Client{
			IP:        clientIP,
			Name:      s.clientName,
			NetworkID: s.networkID,
		},
		Domain: dominantParent(s),
		QType:  "TXT",
		Title:  "Unusual TXT record activity",
		Summary: fmt.Sprintf(
			"%s made %d non-infrastructure TXT lookups across %d distinct names under %d "+
				"registered domains in %s (%.0f%% of its queries). %d standard mail and "+
				"verification lookups were excluded.",
			describeClient(clientIP, s.clientName, s.networkID),
			s.txt, s.names.count(), s.parents.count(), d.cfg.Window, ratio*100, s.infrastructure),
		Signals: signals,
		Evidence: map[string]any{
			"txt_queries":                 s.txt,
			"txt_infrastructure_excluded": s.infrastructure,
			"total_queries":               s.queries,
			"txt_ratio":                   round2(ratio),
			"distinct_txt_names":          s.names.count(),
			"distinct_txt_domains":        s.parents.count(),
			"mean_subdomain_entropy":      round2(meanEntropy),
			"entropy_label_samples":       s.entropyN,
			"nxdomain_responses":          s.nxdomain,
			"examples":                    s.examples,
		},
		Window: Window{Start: ent.start, End: now, Queries: s.queries},
		MITRE:  txtTechniques(),
		FalsePositives: []string{
			"A mail server or mail security gateway using non-standard selector names.",
			"Licence checks and anti-abuse services that distribute state over TXT.",
			"A bulk domain-verification exercise during a migration.",
		},
		NextSteps: []string{
			"Check whether the client is a mail server. If it is, decide whether its selectors " +
				"should be added to detection.excluded_domains rather than tuning thresholds.",
			"Look at the names: policy lookups repeat a handful of names, data transfer does not.",
			"Check whether the dns_tunnel detector fired for the same client and parent domain.",
			"Query the same names from an analyst workstation and read the returned records.",
		},
		Detector: d.Name(),
		Maturity: MaturityExperimental,
	}, true
}

// dominantParent returns a representative registered domain for the finding's
// Domain field, or empty when the activity spanned many.
func dominantParent(s *txtState) string {
	if s.parents.count() != 1 {
		return ""
	}
	for k := range s.parents.seen {
		return k
	}
	return ""
}

func containsString(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
