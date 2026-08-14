package detect

import (
	"fmt"
	"math"
	"time"
)

// BeaconDetector looks for DNS queries arriving on a machine's schedule rather
// than a person's.
//
// Human-driven DNS is bursty and irregular: you open a page, twelve lookups
// happen, then nothing for four minutes. Software checking in on a timer
// produces the opposite — evenly spaced queries for the same name, sustained.
// That regularity is the signal.
//
// It is also, unavoidably, the signal produced by every legitimate updater,
// telemetry agent, and monitoring probe on the network, which is why this
// detector is capped at medium severity and framed as a hunting lead. It says
// "this host is talking to that name on a fixed cadence"; deciding whether
// that is Windows Update or an implant is analyst work.
//
// One benign cause is common enough to be worth removing mechanically: a
// client re-resolving a name because its own cache entry expired queries at
// exactly the record's TTL. Where the observed period matches the TTL, the
// finding is suppressed rather than downgraded — the periodicity has a
// complete, boring explanation and reporting it would be noise.
type BeaconDetector struct {
	cfg   BeaconConfig
	track *tracker[*beaconState]
}

// BeaconConfig holds the tunable thresholds.
type BeaconConfig struct {
	Window     time.Duration
	MaxTracked int

	// MinArrivals is how many queries for one name are needed before timing
	// can be assessed. Seven intervals is the minimum for a standard
	// deviation to mean much.
	MinArrivals int
	// MinInterval and MaxInterval bound the periods considered. Below the
	// floor is retry behaviour, above the ceiling the window cannot hold
	// enough samples.
	MinInterval time.Duration
	MaxInterval time.Duration
	// MinRegularity gates the detector.
	//
	// Regularity is not one signal among several here — it is the entire
	// premise. Without this gate a client that merely queried the same name
	// often enough, for long enough, could accumulate a low-severity finding
	// from the volume and duration signals alone while being visibly
	// irregular, which is precisely the "suspicious DNS traffic" alert this
	// package exists to avoid producing.
	MinRegularity float64
	// TTLTolerance is the relative difference below which an observed period
	// is treated as cache-expiry driven and suppressed.
	TTLTolerance float64
	// RingSize bounds the timestamps kept per name.
	RingSize int

	FullConfidenceArrivals int
}

// DefaultBeaconConfig returns the shipped thresholds.
func DefaultBeaconConfig() BeaconConfig {
	return BeaconConfig{
		Window:                 30 * time.Minute,
		MaxTracked:             16384,
		MinArrivals:            8,
		MinInterval:            10 * time.Second,
		MaxInterval:            15 * time.Minute,
		MinRegularity:          0.75,
		TTLTolerance:           0.15,
		RingSize:               32,
		FullConfidenceArrivals: 30,
	}
}

type beaconState struct {
	// first is recorded for every name; times is allocated only once a name is
	// seen twice. Most names on a network are queried once, and paying for a
	// slice each would dominate this detector's memory.
	first time.Time
	times []time.Time
	count int

	minTTL     uint32
	sawAnswer  bool
	qtype      string
	clientName string
	networkID  string
	blocked    int
}

// NewBeaconDetector builds a beaconing detector.
func NewBeaconDetector(cfg BeaconConfig) *BeaconDetector {
	if cfg.Window <= 0 {
		cfg = DefaultBeaconConfig()
	}
	return &BeaconDetector{
		cfg: cfg,
		track: newTracker(cfg.MaxTracked, cfg.Window, func() *beaconState {
			return &beaconState{}
		}),
	}
}

// Name implements Detector.
func (d *BeaconDetector) Name() string { return "dns_beaconing" }

// Info implements Detector.
func (d *BeaconDetector) Info() DetectorInfo {
	return DetectorInfo{
		Name:      d.Name(),
		EventType: EventBeaconing,
		Title:     "Regular DNS check-in pattern",
		Description: "Measures the regularity of repeated queries for a single name from a single " +
			"client, using the coefficient of variation of inter-arrival times. Periods that " +
			"match the answer's TTL are suppressed as cache-expiry refresh.",
		Maturity:    MaturityExperimental,
		MaxSeverity: SeverityMedium,
		Window:      d.cfg.Window.String(),
		MITRE:       beaconTechniques(),
		SignalNames: []string{
			"timing_regularity", "observation_count", "observed_duration", "ttl_independence",
		},
		FalsePositives: []string{
			"Software update checks, telemetry agents, and monitoring probes poll on fixed timers " +
				"by design and are indistinguishable from an implant by timing alone.",
			"A client re-resolving on TTL expiry produces perfect periodicity. This is suppressed " +
				"automatically when the period matches the TTL, but only when an answer with a " +
				"TTL was actually observed.",
			"NTP, certificate status, and presence/push services maintain regular cadences.",
		},
		Enforces: false,
	}
}

// Observe implements Detector.
func (d *BeaconDetector) Observe(e *Event) {
	if e.Excluded || !e.HasParent {
		return
	}

	ent := d.track.get(e.ClientKey()+"|"+e.QName, e.Time)
	s := ent.state

	s.count++
	if s.count == 1 {
		s.first = e.Time
	} else {
		if s.times == nil {
			s.times = make([]time.Time, 0, d.cfg.RingSize)
			s.times = append(s.times, s.first)
		}
		if len(s.times) < d.cfg.RingSize {
			s.times = append(s.times, e.Time)
		} else {
			// Keep the most recent RingSize arrivals. Regularity is a property
			// of the recent cadence; a beacon that changed period an hour ago
			// should be judged on what it is doing now.
			copy(s.times, s.times[1:])
			s.times[len(s.times)-1] = e.Time
		}
	}

	if e.Blocked {
		s.blocked++
	}
	if e.AnswerTTL > 0 {
		if !s.sawAnswer || e.AnswerTTL < s.minTTL {
			s.minTTL = e.AnswerTTL
		}
		s.sawAnswer = true
	}
	s.qtype = e.QType
	if e.ClientName != "" {
		s.clientName = e.ClientName
	}
	if e.NetworkID != "" {
		s.networkID = e.NetworkID
	}
}

// Evaluate implements Detector.
func (d *BeaconDetector) Evaluate(now time.Time) []Finding {
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
func (d *BeaconDetector) Sweep(now time.Time) { d.track.sweep(now) }

// Tracked implements Detector.
func (d *BeaconDetector) Tracked() int { return d.track.len() }

func (d *BeaconDetector) score(ent *entry[*beaconState], now time.Time) (Finding, bool) {
	s := ent.state
	if len(s.times) < d.cfg.MinArrivals {
		return Finding{}, false
	}

	intervals := make([]float64, 0, len(s.times)-1)
	for i := 1; i < len(s.times); i++ {
		intervals = append(intervals, s.times[i].Sub(s.times[i-1]).Seconds())
	}
	mean, stddev := meanStdDev(intervals)
	if mean <= 0 {
		return Finding{}, false
	}
	period := time.Duration(mean * float64(time.Second))
	if period < d.cfg.MinInterval || period > d.cfg.MaxInterval {
		return Finding{}, false
	}

	// Coefficient of variation: standard deviation relative to the mean, which
	// makes regularity comparable across a 30-second beacon and a 10-minute
	// one. Poisson-like human traffic sits near 1.0; a fixed timer near 0.
	cv := stddev / mean
	regularity := clamp01(1 - cv)
	if regularity < d.cfg.MinRegularity {
		return Finding{}, false
	}

	// TTL-driven re-resolution check. If we saw an answer and the cadence
	// matches its TTL, the periodicity is explained.
	ttlIndependence := 1.0
	ttlRelDiff := math.Inf(1)
	if s.sawAnswer && s.minTTL > 0 {
		ttl := float64(s.minTTL)
		ttlRelDiff = math.Abs(mean-ttl) / ttl
		if ttlRelDiff <= d.cfg.TTLTolerance {
			// Fully explained: a cache expiring on schedule.
			return Finding{}, false
		}
		ttlIndependence = ramp(ttlRelDiff, d.cfg.TTLTolerance, 0.6)
	}

	duration := s.times[len(s.times)-1].Sub(s.times[0]).Seconds()

	signals := []Signal{
		signal("timing_regularity",
			"One minus the coefficient of variation of inter-arrival times. A fixed timer "+
				"approaches 1.0; irregular, human-driven traffic sits near 0.",
			regularity, 0.75, 0.97, 0.45),
		signal("observation_count",
			"Queries for this exact name from this client within the window.",
			float64(len(s.times)), float64(d.cfg.MinArrivals), 40, 0.20),
		signal("observed_duration",
			"Seconds between the first and last observation. A cadence sustained for longer is "+
				"harder to explain as a coincidence of timing.",
			duration, 300, 1800, 0.15),
		signal("ttl_independence",
			"How far the observed period sits from the answer's TTL, relatively. A client "+
				"re-resolving on cache expiry queries at the TTL; a beacon runs on its own clock. "+
				"Scored at maximum when no answer TTL was observed.",
			ttlIndependenceValue(ttlRelDiff), d.cfg.TTLTolerance, 0.6, 0.20),
	}
	// The ttl_independence signal is computed from a possibly-infinite
	// relative difference, so its normalised value is set explicitly.
	signals[3].Normalised = round2(ttlIndependence)
	signals[3].Contribution = round2(ttlIndependence * signals[3].Weight)

	var score float64
	for _, sig := range signals {
		score += sig.Contribution
	}

	severity := severityFor(score, SeverityMedium)
	if severity.Rank() < SeverityLow.Rank() {
		return Finding{}, false
	}

	clientIP := keyClientIP(ent.key)
	name := keyDomain(ent.key)

	evidence := map[string]any{
		"observations":             len(s.times),
		"queries_in_window":        s.count,
		"mean_interval_s":          round2(mean),
		"stddev_interval_s":        round2(stddev),
		"coefficient_of_variation": round2(cv),
		"observed_duration_s":      round2(duration),
		"blocked_responses":        s.blocked,
	}
	if s.sawAnswer && s.minTTL > 0 {
		evidence["answer_min_ttl_s"] = s.minTTL
		evidence["period_vs_ttl_relative_difference"] = round2(ttlRelDiff)
	} else {
		evidence["answer_min_ttl_s"] = nil
	}

	return Finding{
		Time:       now,
		EventType:  EventBeaconing,
		Severity:   severity,
		Score:      round2(score),
		Confidence: confidenceFor(score, len(s.times), d.cfg.MinArrivals, d.cfg.FullConfidenceArrivals),
		Client: Client{
			IP:        clientIP,
			Name:      s.clientName,
			NetworkID: s.networkID,
		},
		Domain: name,
		QType:  s.qtype,
		Title:  "Regular DNS check-in pattern",
		Summary: fmt.Sprintf(
			"%s queried %s %d times at a mean interval of %.0fs (variation %.0f%%) over %.0f "+
				"minutes. The cadence does not match the answer's TTL, so it is not explained by "+
				"cache expiry.",
			describeClient(clientIP, s.clientName, s.networkID),
			name, len(s.times), mean, cv*100, duration/60),
		Signals:  signals,
		Evidence: evidence,
		Window:   Window{Start: ent.start, End: now, Queries: s.count},
		MITRE:    beaconTechniques(),
		FalsePositives: []string{
			"Update checkers, telemetry agents and monitoring probes are periodic by design.",
			"A client with a fixed polling interval shorter than the record TTL.",
			"Push and presence services maintaining a session.",
		},
		NextSteps: []string{
			"Establish what the name is and who operates it before looking at the host.",
			"Check whether every device of this type shows the same cadence — fleet-wide " +
				"regularity is a product, one host alone is worth explaining.",
			"On the endpoint, identify the process making the lookups.",
			"Correlate the start of the cadence with software installs or user activity.",
		},
		Detector: d.Name(),
		Maturity: MaturityExperimental,
	}, true
}

// ttlIndependenceValue converts a possibly-infinite relative difference into a
// finite value for display. Infinity means no TTL was observed at all.
func ttlIndependenceValue(relDiff float64) float64 {
	if math.IsInf(relDiff, 1) {
		return 1
	}
	return relDiff
}

// meanStdDev returns the mean and population standard deviation of v.
func meanStdDev(v []float64) (mean, stddev float64) {
	if len(v) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range v {
		sum += x
	}
	mean = sum / float64(len(v))

	var sq float64
	for _, x := range v {
		d := x - mean
		sq += d * d
	}
	return mean, math.Sqrt(sq / float64(len(v)))
}
