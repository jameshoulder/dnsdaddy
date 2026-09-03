package config

import (
	"path/filepath"
	"testing"
)

// The shipped example config is documentation that has to stay executable.
// It drifts silently otherwise: a renamed key keeps parsing as an unknown
// field, and the operator who copied it wonders why their setting does
// nothing.
func TestShippedExampleConfigParses(t *testing.T) {
	path := filepath.Join("..", "..", "dnsdaddy.example.yaml")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("dnsdaddy.example.yaml does not load: %v", err)
	}

	// Spot-check the values the file documents, so a key renamed in Go but not
	// in the YAML is caught rather than silently ignored.
	if !cfg.DNS.DNSSECTelemetry {
		t.Error("dns.dnssec_telemetry did not parse")
	}
	if !cfg.DNS.RefuseANY {
		t.Error("dns.refuse_any did not parse")
	}
	if !cfg.Detection.Enabled {
		t.Error("detection.enabled did not parse")
	}
	if cfg.Detection.MinSeverity != "low" {
		t.Errorf("detection.min_severity = %q, want low", cfg.Detection.MinSeverity)
	}
	if cfg.Detection.RetentionDays != 30 {
		t.Errorf("detection.retention_days = %d, want 30", cfg.Detection.RetentionDays)
	}
	if cfg.Detection.WindowScale != 1.0 {
		t.Errorf("detection.window_scale = %v, want 1.0", cfg.Detection.WindowScale)
	}
	if cfg.Detection.EvalInterval.D().String() != "30s" {
		t.Errorf("detection.eval_interval = %v, want 30s", cfg.Detection.EvalInterval)
	}
	// Decision records are off in the shipped example. A copy-and-paste must
	// not start writing a second row per block on somebody's resolver.
	if cfg.Log.DecisionRecords {
		t.Error("the shipped example config enables decision records")
	}
	if cfg.Log.DecisionRetentionDays != 30 {
		t.Errorf("log.decision_retention_days = %d, want 30", cfg.Log.DecisionRetentionDays)
	}
	if cfg.Log.RetentionDays != 7 {
		t.Errorf("log.retention_days = %d, want 7", cfg.Log.RetentionDays)
	}

	// The integrations block. Every value here is inert by design, and the
	// example shipping anything else would enable, on a copy-and-paste, a
	// feature that sends this network's query names to a third party.
	if cfg.Integrations.Enabled {
		t.Error("the shipped example config enables external API integrations")
	}
	if cfg.Integrations.ReputationMode != "off" {
		t.Errorf("integrations.reputation_mode = %q, want off", cfg.Integrations.ReputationMode)
	}
	if cfg.Integrations.Enrichment {
		t.Error("the shipped example config enables enrichment")
	}
	// And the tuning keys parse, so a rename in Go without one in the YAML is
	// caught rather than silently ignored.
	if cfg.Integrations.Workers != 2 {
		t.Errorf("integrations.workers = %d, want 2", cfg.Integrations.Workers)
	}
	if cfg.Integrations.QueueSize != 1024 {
		t.Errorf("integrations.queue_size = %d, want 1024", cfg.Integrations.QueueSize)
	}
	if cfg.Integrations.CacheEntries != 4096 {
		t.Errorf("integrations.cache_entries = %d, want 4096", cfg.Integrations.CacheEntries)
	}
	if cfg.Integrations.ReputationBudget.D().String() != "50ms" {
		t.Errorf("integrations.reputation_budget = %v, want 50ms", cfg.Integrations.ReputationBudget)
	}
	if cfg.Integrations.DefaultCacheTTL.D().String() != "6h0m0s" {
		t.Errorf("integrations.default_cache_ttl = %v, want 6h", cfg.Integrations.DefaultCacheTTL)
	}

	// The example must never ship a configuration that would refuse to start.
	if err := cfg.validate(); err != nil {
		t.Errorf("the shipped example config would fail validation: %v", err)
	}
}

// window_scale is a demonstration setting with real consequences, so its
// bounds are enforced rather than clamped silently.
func TestWindowScaleBounds(t *testing.T) {
	for _, tc := range []struct {
		scale float64
		ok    bool
	}{
		{0, true}, // unset; treated as 1.0
		{1, true},
		{0.1, true},
		{10, true},
		{0.001, false},
		{100, false},
		{-1, false},
	} {
		cfg := Default()
		cfg.Detection.WindowScale = tc.scale
		err := cfg.validate()
		if tc.ok && err != nil {
			t.Errorf("window_scale %v rejected: %v", tc.scale, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("window_scale %v accepted, want rejection", tc.scale)
		}
	}
}
