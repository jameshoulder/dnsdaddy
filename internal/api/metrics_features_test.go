package api

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/learning"
	"github.com/jameshoulder/dnsdaddy/internal/protection"
)

type metricsDNSSECControl struct{ state DNSSECRuntimeState }

func (c *metricsDNSSECControl) State() DNSSECRuntimeState             { return c.state }
func (c *metricsDNSSECControl) SetMode(context.Context, string) error { return nil }

func TestLearningOnlyInstanceKeepsFindingsCatalogueEnabled(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.api.Detector = nil
	e, err := learning.New(learning.Options{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.api.Learning = e
	var body struct {
		Enabled          bool                  `json:"enabled"`
		HeuristicEnabled bool                  `json:"heuristicEnabled"`
		LearningEnabled  bool                  `json:"learningEnabled"`
		Detectors        []detect.DetectorInfo `json:"detectors"`
	}
	h.getJSON("/api/v1/detectors", &body)
	if !body.Enabled || body.HeuristicEnabled || !body.LearningEnabled || len(body.Detectors) != 1 || body.Detectors[0].Name != learning.Algorithm || body.Detectors[0].Enforces {
		t.Fatalf("learning source disappeared: %+v", body)
	}
	var summary struct {
		Enabled bool `json:"enabled"`
	}
	h.getJSON("/api/v1/findings/summary", &summary)
	if !summary.Enabled {
		t.Fatal("summary hides independent learner")
	}
}

func TestMetricsUseEffectiveRuntimeInsteadOfStaleDNSSECDependencies(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.api.DNSSEC = fixedStats{observe.Stats{Observed: 99, ByStatus: map[observe.Status]uint64{observe.StatusBogus: 99}}}
	h.api.Config.DNS.LocalDNSSECValidation = config.LocalDNSSECObserve
	control := &metricsDNSSECControl{state: DNSSECRuntimeState{Effective: config.LocalDNSSECOff}}
	h.api.DNSSECControl = control
	body := h.getMetrics()
	if strings.Contains(body, "dnsdaddy_dnssec_local_validation_total") || !strings.Contains(body, `dnsdaddy_dnssec_mode{mode="off"} 1`) {
		t.Fatalf("metrics report stale runtime: %s", body)
	}
	control.state = DNSSECRuntimeState{Effective: config.LocalDNSSECEnforce, NativeAvailable: true, Native: native.ClientStats{Queries: 7, Secure: 4, Bogus: 2, Indeterminate: 1, InflightPeak: 3, MaxInflight: 128}}
	body = h.getMetrics()
	for _, want := range []string{`dnsdaddy_dnssec_mode{mode="enforce"} 1`, "dnsdaddy_dnssec_native_enforcing 1", "dnsdaddy_dnssec_native_queries_total 7", "dnsdaddy_dnssec_native_bogus_total 2", "dnsdaddy_dnssec_native_inflight_peak 3"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestFeatureMetricsExposeBoundedCountsAndNoIdentities(t *testing.T) {
	h := newHarness(t)
	h.login()
	e, err := learning.New(learning.Options{BufferSize: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.api.Learning = e
	o := detect.Observation{Time: time.Now(), ClientIP: "192.0.2.195", QName: "sensitive-model-name.example", QType: "A", Rcode: "NOERROR"}
	e.Observe(o)
	e.Observe(o)
	e.SkipPrivacy()
	cfg := protection.Default()
	cfg.RateLimit.MaxClients = 1
	cfg.RateLimit.Burst = 1
	cfg.RateLimit.QPS = 1
	p, err := protection.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.api.Protection = p
	now := time.Now()
	p.Allow(netip.MustParseAddr("192.0.2.195"), "confidential-network", now)
	p.Allow(netip.MustParseAddr("192.0.2.195"), "confidential-network", now)
	p.Allow(netip.MustParseAddr("192.0.2.196"), "confidential-network", now)
	p.Allow(netip.MustParseAddr("192.0.2.196"), "confidential-network", now)
	body := h.getMetrics()
	for _, want := range []string{"dnsdaddy_learning_received_total 2", "dnsdaddy_learning_dropped_total 1", "dnsdaddy_learning_privacy_skipped_total 1", "dnsdaddy_learning_clients_ready 0", "dnsdaddy_learning_warmup_windows 12", "dnsdaddy_rate_limited_total 2", "dnsdaddy_rate_limit_overflow_total 2", "dnsdaddy_rate_limit_clients_tracked 1", "dnsdaddy_webhook_stats_available 1", "Persistent webhook delivered total since webhook storage was created"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, secret := range []string{"sensitive-model-name.example", "192.0.2.195", "192.0.2.196", "confidential-network"} {
		if strings.Contains(body, secret) {
			t.Errorf("metric exposed %q", secret)
		}
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "dnsdaddy_learning_") || strings.HasPrefix(line, "dnsdaddy_rate_") || strings.HasPrefix(line, "dnsdaddy_webhook_") {
			if strings.Contains(line, "{") {
				t.Errorf("unbounded metric label: %s", line)
			}
		}
	}
}
