package detect

import (
	"fmt"
	"strings"
	"time"
)

// TunnelDetector looks for DNS being used as a data carrier.
//
// The mechanism it is built around: to move bytes over DNS you must put those
// bytes somewhere the resolver will forward to a server you control. The only
// generous place in a query is the name itself, so a tunnel encodes its
// payload into labels below a domain it owns, and does so repeatedly. That
// produces a signature no amount of tuning on the attacker's side removes
// entirely — many distinct, long, high-entropy names under a single parent —
// because it is what the transport requires.
//
// Seven independent measurements are taken and combined. No single one can
// raise a finding: a minimum of three must be meaningfully present, because
// each of them alone has a common benign cause.
//
//	unique subdomains     a CDN generates these too
//	label entropy         so do hashes, GUIDs and cache-busting tokens
//	name length           so do deeply nested service-discovery names
//	max label length      so do some API endpoints
//	encoded-looking labels  so do reputation lookups
//	payload-capable qtype   TXT is used legitimately everywhere
//	NXDOMAIN ratio          so does a stale search suffix
//
// Together, sustained, under one parent, from one client, they are difficult
// to produce accidentally.
type TunnelDetector struct {
	cfg   TunnelConfig
	track *tracker[*tunnelState]
}

// TunnelConfig holds the tunable thresholds. Defaults are set by
// DefaultTunnelConfig and every value is published in the finding, so an
// operator can see exactly which threshold a measurement crossed.
type TunnelConfig struct {
	Window     time.Duration
	MaxTracked int

	// MinQueries and MinUniqueSubdomains gate the detector. Below these it
	// stays silent regardless of how extreme the other measurements look,
	// because a handful of odd names is not evidence of a channel.
	MinQueries          int
	MinUniqueSubdomains int
	// MinContributingSignals is how many signals must be meaningfully present
	// before a finding is raised.
	MinContributingSignals int
	// FullConfidenceQueries is the sample size at which confidence stops being
	// damped.
	FullConfidenceQueries int

	// SubdomainCap bounds the distinct-subdomain set per tracked key.
	SubdomainCap int
}

// DefaultTunnelConfig returns the shipped thresholds.
//
// These are calibrated against the synthetic corpora in tunnel_test.go, not
// against a production network, which is why this detector is marked
// experimental. They are deliberately on the conservative side: a missed
// tunnel is a gap, a false positive on a mail server is an operator turning
// the whole feature off.
func DefaultTunnelConfig() TunnelConfig {
	return TunnelConfig{
		Window:                 5 * time.Minute,
		MaxTracked:             8192,
		MinQueries:             30,
		MinUniqueSubdomains:    15,
		MinContributingSignals: 3,
		FullConfidenceQueries:  300,
		SubdomainCap:           2048,
	}
}

type tunnelState struct {
	queries int
	subs    *boundedSet

	entropySum float64
	entropyN   int

	nameLenSum   int
	maxLabel     int
	encodedCount int
	labelSamples int

	nxdomain int
	payload  int
	qtypes   map[string]int

	clientName string
	networkID  string
}

// NewTunnelDetector builds a tunnelling detector.
func NewTunnelDetector(cfg TunnelConfig) *TunnelDetector {
	if cfg.Window <= 0 {
		cfg = DefaultTunnelConfig()
	}
	capacity := cfg.SubdomainCap
	return &TunnelDetector{
		cfg: cfg,
		track: newTracker(cfg.MaxTracked, cfg.Window, func() *tunnelState {
			return &tunnelState{subs: newBoundedSet(capacity), qtypes: map[string]int{}}
		}),
	}
}

// Name implements Detector.
func (d *TunnelDetector) Name() string { return "dns_tunnel" }

// Info implements Detector.
func (d *TunnelDetector) Info() DetectorInfo {
	return DetectorInfo{
		Name:      d.Name(),
		EventType: EventTunnelSuspected,
		Title:     "Possible DNS tunnelling",
		Description: "Scores each client/registered-domain pair on seven independent properties of " +
			"DNS-as-a-transport: distinct subdomain cardinality, label entropy, name length, " +
			"longest label, encoded-looking labels, payload-capable query types, and NXDOMAIN " +
			"ratio. At least three must be meaningfully present before a finding is raised.",
		Maturity:    MaturityExperimental,
		MaxSeverity: SeverityHigh,
		Window:      d.cfg.Window.String(),
		MITRE:       tunnelTechniques(),
		SignalNames: []string{
			"unique_subdomains", "mean_subdomain_entropy", "mean_qname_length",
			"max_label_length", "encoded_label_ratio", "payload_qtype_ratio", "nxdomain_ratio",
		},
		FalsePositives: []string{
			"Anti-spam and file-reputation lookups (DNSBL, endpoint agents) encode the item being " +
				"checked into the label and are indistinguishable by shape. The shipped exclusion " +
				"list covers the common providers.",
			"Content delivery networks issue per-request hostnames, producing high cardinality " +
				"under one parent.",
			"Reverse DNS for IPv6 is 32 hex labels per lookup; the .arpa zone is excluded outright.",
			"Some telemetry and analytics SDKs encode a session or device identifier into a " +
				"hostname.",
		},
		Enforces: false,
	}
}

// payloadCapable reports whether a query type can carry a useful amount of
// data back to the client. These are the record types tunnelling tools reach
// for: TXT for capacity, NULL where it is permitted, CNAME and MX because
// their targets are names and so can themselves be encoded.
func payloadCapable(qtype string) bool {
	switch qtype {
	case "TXT", "NULL", "CNAME", "MX":
		return true
	}
	return false
}

// Observe implements Detector.
func (d *TunnelDetector) Observe(e *Event) {
	// A tunnel needs a registered domain it controls. Names with no registered
	// domain are internal or malformed, and internal name churn is the loudest
	// false positive there is.
	if !e.HasParent || e.Excluded || e.Sub == "" {
		return
	}

	ent := d.track.get(e.ClientKey()+"|"+e.Parent, e.Time)
	s := ent.state

	s.queries++
	if e.ClientName != "" {
		s.clientName = e.ClientName
	}
	if e.NetworkID != "" {
		s.networkID = e.NetworkID
	}

	s.subs.add(e.Sub)
	s.nameLenSum += len(e.QName)
	s.qtypes[e.QType]++

	if payloadCapable(e.QType) {
		s.payload++
	}
	if e.NXDomain {
		s.nxdomain++
	}

	// Label-level measurements are taken over the payload portion only: the
	// registered domain is the attacker's choice of carrier, not their data,
	// and including it would dilute the very signal we are measuring.
	for _, label := range labelsOf(e.Sub) {
		if label == "" || isInternationalised(label) {
			continue
		}
		if len(label) > s.maxLabel {
			s.maxLabel = len(label)
		}
		s.labelSamples++
		if looksEncoded(label) {
			s.encodedCount++
		}
		// Entropy is only meaningful on a label long enough for it to be —
		// see shannonEntropy.
		if len(label) >= minEntropyLabelLen {
			s.entropySum += shannonEntropy(label)
			s.entropyN++
		}
	}
}

// Evaluate implements Detector.
func (d *TunnelDetector) Evaluate(now time.Time) []Finding {
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
func (d *TunnelDetector) Sweep(now time.Time) { d.track.sweep(now) }

// Tracked implements Detector.
func (d *TunnelDetector) Tracked() int { return d.track.len() }

func (d *TunnelDetector) score(ent *entry[*tunnelState], now time.Time) (Finding, bool) {
	s := ent.state
	unique := s.subs.count()

	if s.queries < d.cfg.MinQueries || unique < d.cfg.MinUniqueSubdomains {
		return Finding{}, false
	}

	meanEntropy := 0.0
	if s.entropyN > 0 {
		meanEntropy = s.entropySum / float64(s.entropyN)
	}
	meanLen := float64(s.nameLenSum) / float64(s.queries)
	encodedRatio := 0.0
	if s.labelSamples > 0 {
		encodedRatio = float64(s.encodedCount) / float64(s.labelSamples)
	}
	nxRatio := float64(s.nxdomain) / float64(s.queries)
	payloadRatio := float64(s.payload) / float64(s.queries)

	signals := []Signal{
		signal("unique_subdomains",
			"Distinct names seen below this registered domain from this client. A tunnel needs a "+
				"new name per message because a repeated name is answered from cache and never "+
				"reaches the attacker's server.",
			float64(unique), 20, 200, 0.28),
		signal("mean_subdomain_entropy",
			fmt.Sprintf("Mean Shannon entropy of labels at least %d characters long, in bits per "+
				"character. Encoded payloads approach the ~5 bits of a uniform draw; English "+
				"words sit nearer 3.", minEntropyLabelLen),
			meanEntropy, 3.2, 4.2, 0.18),
		signal("mean_qname_length",
			"Mean length of the full query name. Tunnels push towards the 253-byte limit to move "+
				"more per request.",
			meanLen, 45, 100, 0.14),
		signal("max_label_length",
			"Longest single label observed, against the 63-byte protocol maximum.",
			float64(s.maxLabel), 30, 63, 0.10),
		signal("encoded_label_ratio",
			"Share of labels whose character distribution matches an encoding alphabet (hex, "+
				"base32, or a low-vowel alphanumeric mix) rather than written language.",
			encodedRatio, 0.25, 0.85, 0.12),
		signal("payload_qtype_ratio",
			"Share of queries using a record type that can carry data back to the client: TXT, "+
				"NULL, CNAME or MX.",
			payloadRatio, 0.10, 0.60, 0.10),
		signal("nxdomain_ratio",
			"Share of queries the upstream could not resolve. Some tunnel modes never expect an "+
				"answer, and encoded names that miss produce NXDOMAIN. Queries DNS Daddy blocked "+
				"itself are excluded from this ratio.",
			nxRatio, 0.20, 0.80, 0.08),
	}

	var score float64
	contributing := 0
	for i := range signals {
		score += signals[i].Contribution
		if signals[i].Normalised >= 0.25 {
			contributing++
		}
	}

	// The multi-signal gate. One extreme measurement is a property of some
	// service on the network; three at once is a channel.
	if contributing < d.cfg.MinContributingSignals {
		return Finding{}, false
	}

	severity := severityFor(score, SeverityHigh)
	if severity.Rank() < SeverityLow.Rank() {
		return Finding{}, false
	}

	clientIP := ""
	if k := ent.key; k != "" {
		clientIP = keyClientIP(k)
	}

	evidence := map[string]any{
		"queries":                s.queries,
		"unique_subdomains":      unique,
		"cardinality_is_capped":  s.subs.overflow,
		"average_entropy":        round2(meanEntropy),
		"entropy_label_samples":  s.entropyN,
		"mean_qname_length":      round2(meanLen),
		"max_label_length":       s.maxLabel,
		"encoded_labels":         s.encodedCount,
		"labels_examined":        s.labelSamples,
		"nxdomain_responses":     s.nxdomain,
		"payload_capable_qtypes": s.payload,
		"query_types":            s.qtypes,
	}

	f := Finding{
		Time:       now,
		EventType:  EventTunnelSuspected,
		Severity:   severity,
		Score:      round2(score),
		Confidence: confidenceFor(score, s.queries, d.cfg.MinQueries, d.cfg.FullConfidenceQueries),
		Client: Client{
			IP:        clientIP,
			Name:      s.clientName,
			NetworkID: s.networkID,
		},
		Domain: keyDomain(ent.key),
		QType:  dominantQType(s.qtypes),
		Title:  "Possible DNS tunnelling",
		Summary: fmt.Sprintf(
			"%s queried %d distinct subdomains of %s across %d lookups in %s. "+
				"Mean label entropy %.2f bits/char, mean name length %.0f characters, "+
				"%.0f%% encoded-looking labels, %.0f%% payload-capable record types, "+
				"%.0f%% NXDOMAIN.",
			describeClient(clientIP, s.clientName, s.networkID),
			unique, keyDomain(ent.key), s.queries, d.cfg.Window,
			meanEntropy, meanLen, encodedRatio*100, payloadRatio*100, nxRatio*100),
		Signals:  signals,
		Evidence: evidence,
		Window:   Window{Start: ent.start, End: now, Queries: s.queries},
		MITRE:    tunnelTechniques(),
		FalsePositives: []string{
			"Anti-spam (DNSBL) and endpoint file-reputation lookups produce this exact shape. " +
				"Check whether the parent domain belongs to a security vendor before escalating.",
			"A CDN or analytics provider issuing per-request hostnames.",
			"An internal service using DNS for discovery with generated names.",
		},
		NextSteps: []string{
			"Identify the parent domain's owner and whether the network has any business with it.",
			"Check whether the domain's authoritative nameservers were registered recently.",
			"Confirm from the query log whether the behaviour is continuous or bursty, and " +
				"whether it started at a time that matches any other event on the host.",
			"Inspect the endpoint: a tunnel needs a process holding it open.",
			"If confirmed, add the parent domain to the policy block-list — that is an " +
				"enforcement decision for a human, which is why this finding does not make it.",
		},
		Detector: d.Name(),
		Maturity: MaturityExperimental,
	}
	return f, true
}

// signal builds a Signal, computing the ramp and contribution.
func signal(name, description string, value, floor, ceiling, weight float64) Signal {
	n := ramp(value, floor, ceiling)
	return Signal{
		Name:         name,
		Description:  description,
		Value:        round2(value),
		Floor:        floor,
		Ceiling:      ceiling,
		Normalised:   round2(n),
		Weight:       weight,
		Contribution: round2(n * weight),
	}
}

// dominantQType returns the most frequent query type, for the finding's QType
// field. Ties break on name so output is deterministic.
func dominantQType(m map[string]int) string {
	best, bestN := "", 0
	for k, v := range m {
		if v > bestN || (v == bestN && k < best) {
			best, bestN = k, v
		}
	}
	return best
}

// clientIPOf returns the IP a client key names.
//
// A key is an IP when device attribution is on, and a "network:<id>" or
// "unattributed" placeholder when it is not. Those placeholders must never be
// written into a finding's client.ip field: doing so would put a synthetic
// string where a SIEM expects an address.
func clientIPOf(key string) string {
	if key == "" || key == "unattributed" || strings.HasPrefix(key, "network:") {
		return ""
	}
	return key
}

// keyClientIP and keyDomain unpack the composite tracker key. The key format
// is "<client>|<domain>", built in Observe.
func keyClientIP(key string) string {
	if i := strings.IndexByte(key, '|'); i >= 0 {
		return clientIPOf(key[:i])
	}
	return clientIPOf(key)
}

func keyDomain(key string) string {
	if i := strings.IndexByte(key, '|'); i >= 0 {
		return key[i+1:]
	}
	return ""
}

// describeClient produces the subject phrase for a finding summary.
func describeClient(ip, name, networkID string) string {
	switch {
	case name != "" && ip != "":
		return fmt.Sprintf("%s (%s)", name, ip)
	case ip != "":
		return ip
	case networkID != "":
		return "a client on network " + networkID
	}
	return "an unattributed client"
}
