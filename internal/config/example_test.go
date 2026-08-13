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
	if cfg.Log.RetentionDays != 7 {
		t.Errorf("log.retention_days = %d, want 7", cfg.Log.RetentionDays)
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
