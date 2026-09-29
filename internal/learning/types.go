// Package learning fits an experimental local DNS traffic baseline from
// completed windows. It produces investigation leads, never DNS verdicts.
// Daddybound's DNSSEC validator answers a different, cryptographic question.
package learning

import (
	"fmt"
	"math"
	"time"
)

const (
	Algorithm      = "robust-ewma-v1"
	ModelVersion   = 1
	FeatureVersion = 1
	FeatureCount   = 6
	EventType      = "local_behavior_anomaly"
)

// Options bounds both memory and adaptation. A zero field selects the default.
// StatePath empty deliberately selects volatile state, useful in offline labs.
type Options struct {
	StatePath          string
	BufferSize         int
	MaxClients         int
	MaxWindowQueries   int
	MaxUniqueDomains   int
	RecentLimit        int
	Window             time.Duration
	MinWindowQueries   int
	WarmupWindows      int
	WarmupDuration     time.Duration
	IdleTTL            time.Duration
	CheckpointInterval time.Duration
	Alpha              float64
	Threshold          float64
	Cooldown           time.Duration
}

func (o Options) withDefaults() (Options, error) {
	if o.BufferSize == 0 {
		o.BufferSize = 2048
	}
	if o.MaxClients == 0 {
		o.MaxClients = 1024
	}
	if o.MaxWindowQueries == 0 {
		o.MaxWindowQueries = 8192
	}
	if o.MaxUniqueDomains == 0 {
		o.MaxUniqueDomains = 512
	}
	if o.RecentLimit == 0 {
		o.RecentLimit = 100
	}
	if o.Window == 0 {
		o.Window = 5 * time.Minute
	}
	if o.MinWindowQueries == 0 {
		o.MinWindowQueries = 20
	}
	if o.WarmupWindows == 0 {
		o.WarmupWindows = 12
	}
	if o.WarmupDuration == 0 {
		o.WarmupDuration = time.Hour
	}
	if o.IdleTTL == 0 {
		o.IdleTTL = 24 * time.Hour
	}
	if o.CheckpointInterval == 0 {
		o.CheckpointInterval = time.Minute
	}
	if o.Alpha == 0 {
		o.Alpha = 0.05
	}
	if o.Threshold == 0 {
		o.Threshold = 2.5
	}
	if o.Cooldown == 0 {
		o.Cooldown = 30 * time.Minute
	}
	if o.BufferSize < 1 || o.BufferSize > 65536 || o.MaxClients < 1 || o.MaxClients > 4096 || o.MaxWindowQueries < 2 || o.MaxWindowQueries > 65536 || o.MaxUniqueDomains < 2 || o.MaxUniqueDomains > 4096 || o.RecentLimit < 1 || o.RecentLimit > 500 {
		return o, fmt.Errorf("learning bounds out of range: use 1..65536 queued observations, 1..4096 clients, 2..65536 queries, 2..4096 unique hashes and 1..500 recent results")
	}
	if o.Window < time.Second || o.Window > time.Hour || o.MinWindowQueries < 2 || o.MinWindowQueries > o.MaxWindowQueries || o.WarmupWindows < 2 || o.WarmupWindows > 10000 || o.WarmupDuration < o.Window || o.WarmupDuration > 30*24*time.Hour || o.IdleTTL < o.Window || o.IdleTTL > 90*24*time.Hour || o.CheckpointInterval < time.Second || o.CheckpointInterval > time.Hour || o.Cooldown < o.Window || o.Cooldown > 24*time.Hour {
		return o, fmt.Errorf("learning timing/sample settings out of range")
	}
	if math.IsNaN(o.Alpha) || o.Alpha < 0.001 || o.Alpha > 0.2 || math.IsNaN(o.Threshold) || o.Threshold < 1 || o.Threshold > 10 {
		return o, fmt.Errorf("learning alpha must be 0.001..0.2 and threshold 1..10")
	}
	return o, nil
}

type Feature struct {
	Name         string   `json:"name"`
	Value        float64  `json:"value"`
	BaselineMean *float64 `json:"baselineMean"`
	BaselineStd  *float64 `json:"baselineStd"`
	Z            *float64 `json:"z"`
}

type Window struct {
	Start           time.Time `json:"start"`
	End             time.Time `json:"end"`
	Queries         int       `json:"queries"`
	EligibleQueries int       `json:"eligibleQueries"`
}

// Score is nil until the subject has a baseline. It is the mean capped
// absolute standardised deviation, NOT a probability of maliciousness.
type Result struct {
	Client             string    `json:"client"`
	NetworkID          string    `json:"networkId,omitempty"`
	State              string    `json:"state"`
	Window             Window    `json:"window"`
	Score              *float64  `json:"score"`
	Threshold          float64   `json:"threshold"`
	AnomalousSignals   int       `json:"anomalousSignals"`
	Features           []Feature `json:"features"`
	Trained            bool      `json:"trained"`
	ExcludedReasons    []string  `json:"excludedReasons"`
	BaselineWindows    uint64    `json:"baselineWindows"`
	BaselineQueries    uint64    `json:"baselineQueries"`
	BaselineAgeSeconds int64     `json:"baselineAgeSeconds"`
}

type ClientView struct {
	Client          string    `json:"client"`
	NetworkID       string    `json:"networkId,omitempty"`
	Ready           bool      `json:"ready"`
	BaselineWindows uint64    `json:"baselineWindows"`
	BaselineQueries uint64    `json:"baselineQueries"`
	FirstTrainedAt  time.Time `json:"firstTrainedAt"`
	LastTrainedAt   time.Time `json:"lastTrainedAt"`
	LastSeenAt      time.Time `json:"lastSeenAt"`
	PendingQueries  int       `json:"pendingQueries"`
	Features        []Feature `json:"features"`
}

type ClientCounts struct {
	Tracked int    `json:"tracked"`
	Ready   int    `json:"ready"`
	Warming int    `json:"warming"`
	Max     int    `json:"max"`
	Evicted uint64 `json:"evicted"`
}
type ObservationCounts struct {
	Received        uint64 `json:"received"`
	Processed       uint64 `json:"processed"`
	Dropped         uint64 `json:"dropped"`
	Invalid         uint64 `json:"invalid"`
	Blocked         uint64 `json:"blocked"`
	Errors          uint64 `json:"errors"`
	Late            uint64 `json:"late"`
	WindowOverflow  uint64 `json:"windowOverflow"`
	UniqueSaturated uint64 `json:"uniqueSaturated"`
	PrivacySkipped  uint64 `json:"privacySkipped"`
}
type WindowCounts struct {
	Completed        uint64 `json:"completed"`
	Trained          uint64 `json:"trained"`
	Quarantined      uint64 `json:"quarantined"`
	Insufficient     uint64 `json:"insufficient"`
	Anomalous        uint64 `json:"anomalous"`
	EvictedPending   uint64 `json:"evictedPending"`
	RestartDiscarded uint64 `json:"restartDiscarded"`
}
type PersistenceStatus struct {
	Enabled     bool      `json:"enabled"`
	Loaded      bool      `json:"loaded"`
	LastSavedAt time.Time `json:"lastSavedAt"`
	SaveErrors  uint64    `json:"saveErrors"`
	LastError   string    `json:"lastError"`
}
type Status struct {
	Enabled               bool              `json:"enabled"`
	Available             bool              `json:"available"`
	Running               bool              `json:"running"`
	Mode                  string            `json:"mode"`
	Enforces              bool              `json:"enforces"`
	Experimental          bool              `json:"experimental"`
	Algorithm             string            `json:"algorithm"`
	ModelVersion          int               `json:"modelVersion"`
	CounterScope          string            `json:"counterScope"`
	ScoreMeaning          string            `json:"scoreMeaning"`
	WindowSeconds         int64             `json:"windowSeconds"`
	MinWindowQueries      int               `json:"minWindowQueries"`
	WarmupWindows         int               `json:"warmupWindows"`
	WarmupSeconds         int64             `json:"warmupSeconds"`
	MemoryHalfLifeWindows float64           `json:"memoryHalfLifeWindows"`
	Clients               ClientCounts      `json:"clients"`
	Observations          ObservationCounts `json:"observations"`
	Windows               WindowCounts      `json:"windows"`
	Queue                 struct {
		Depth    int `json:"depth"`
		Capacity int `json:"capacity"`
	} `json:"queue"`
	Persistence       PersistenceStatus `json:"persistence"`
	LastProcessedAt   time.Time         `json:"lastProcessedAt"`
	Recent            []Result          `json:"recent"`
	FindingsEmitted   uint64            `json:"findingsEmitted"`
	FindingErrors     uint64            `json:"findingErrors"`
	FindingSuppressed uint64            `json:"findingSuppressed"`
	Limitations       []string          `json:"limitations"`
	Error             string            `json:"error,omitempty"`
}

// DisabledStatus keeps the API explicit even when learning was disabled in
// configuration. Zero counters are not evidence that traffic was observed.
func DisabledStatus() Status {
	return Status{Mode: "off", Experimental: true, Algorithm: Algorithm, ModelVersion: ModelVersion, CounterScope: "since_start", ScoreMeaning: "mean capped absolute standardised deviation; not maliciousness probability", Recent: []Result{}, Limitations: sampleLimitations()}
}

// UnavailableStatus distinguishes an explicit startup failure from a disabled
// or cold-start model. Local error details can include private filesystem
// paths; callers log those locally and return this actionable public message.
func UnavailableStatus() Status {
	s := DisabledStatus()
	s.Enabled = true
	s.Mode = "unavailable"
	s.CounterScope = "unavailable; learning observations and counters are not being collected"
	s.Error = "Local learning could not start. DNS continues. Inspect local logs and restore compatible model state, or explicitly archive the saved state while stopped. No new baseline has replaced the saved model."
	s.Limitations = append([]string{"The learner is unavailable; zero-valued counter fields are not measurements of traffic or baseline readiness."}, s.Limitations...)
	return s
}

func sampleLimitations() []string {
	return []string{
		"A ready local baseline is a sample/readiness state, not evidence of security efficacy.",
		"Only privacy-permitted observations are ingested. Known blocks, unsuccessful responses, incomplete windows and extreme changes do not train normal behaviour.",
		"Anomaly scores are deviations from prior traffic, not calibrated maliciousness probabilities. The model never blocks DNS.",
		"Traffic behind one attributed address can represent multiple devices; address reassignment can change the subject of a baseline.",
		"Queue loss, bounded client eviction and diversity/query limits reduce coverage. Active partial windows are discarded at restart.",
		"Unknown malicious traffic can contaminate cold start or imitate benign behaviour; clipping and quarantine do not prevent every poisoning strategy.",
		"Finding review labels preserve analyst feedback but do not automatically train this model or allow domains.",
	}
}

var featureNames = [FeatureCount]string{"log_query_rate", "mean_label_length", "mean_label_entropy", "unique_domain_ratio", "txt_ratio", "mean_label_count"}

// Variance floors prevent a stable baseline from assigning enormous scores to
// harmless rounding noise or one additional TXT query.
var stdFloors = [FeatureCount]float64{0.25, 2, 0.2, 0.1, 0.08, 0.4}
