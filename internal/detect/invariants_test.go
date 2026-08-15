package detect

import (
	"testing"
	"time"
)

// Findings claim, in their own published fields, that each signal's
// contribution is its normalised value times its weight and that the
// contributions sum to the score. An analyst is invited to check that
// arithmetic by hand, so it has to hold for every detector rather than only
// for the one that happened to get a test.
//
// This is the invariant the whole "explainable" claim rests on. It is asserted
// here across every detector at once so a new one cannot be added without it.
func TestEveryDetectorPublishesConsistentArithmetic(t *testing.T) {
	for _, tc := range allDetectorCorpora() {
		t.Run(tc.name, func(t *testing.T) {
			ex := NewExclusions(nil, false)
			findings := feed(tc.detector, ex, tc.corpus, windowEnd(tc.window))
			if len(findings) == 0 {
				t.Fatalf("%s produced no finding on its own corpus; the invariant "+
					"cannot be checked and the corpus needs revisiting", tc.name)
			}

			for _, f := range findings {
				var weightSum, contribSum float64
				for _, s := range f.Signals {
					weightSum += s.Weight
					contribSum += s.Contribution

					// Contribution must be normalised × weight, within the
					// rounding the finding publishes.
					want := s.Normalised * s.Weight
					if diff := s.Contribution - want; diff > 0.02 || diff < -0.02 {
						t.Errorf("signal %q: contribution %.3f != normalised %.3f × weight %.3f",
							s.Name, s.Contribution, s.Normalised, s.Weight)
					}
					if s.Normalised < 0 || s.Normalised > 1 {
						t.Errorf("signal %q: normalised %.3f outside 0..1", s.Name, s.Normalised)
					}
					if s.Floor >= s.Ceiling {
						t.Errorf("signal %q: floor %.3f is not below ceiling %.3f",
							s.Name, s.Floor, s.Ceiling)
					}
					if s.Description == "" {
						t.Errorf("signal %q has no description", s.Name)
					}
				}

				// Weights are a published contract: a finding says its
				// contributions sum to its score, which is only true if the
				// weights sum to 1.
				if weightSum < 0.999 || weightSum > 1.001 {
					t.Errorf("weights sum to %.4f, want 1.0", weightSum)
				}
				if diff := contribSum - f.Score; diff > 0.02 || diff < -0.02 {
					t.Errorf("contributions sum to %.3f but the finding reports score %.3f",
						contribSum, f.Score)
				}

				// Confidence is damped from the score, so it can never exceed
				// it — that would be claiming more certainty than evidence.
				if f.Confidence > f.Score+0.001 {
					t.Errorf("confidence %.3f exceeds score %.3f", f.Confidence, f.Score)
				}
				if f.Confidence < 0 || f.Confidence > 1 {
					t.Errorf("confidence %.3f outside 0..1", f.Confidence)
				}

				// Severity must respect the detector's declared ceiling, or the
				// catalogue lies about the worst a detector can report.
				ceiling := tc.detector.Info().MaxSeverity
				if f.Severity.Rank() > ceiling.Rank() {
					t.Errorf("severity %q exceeds the detector's declared maximum %q",
						f.Severity, ceiling)
				}

				// Every finding must be attributable and explainable.
				if f.EventType == "" || f.Title == "" || f.Summary == "" {
					t.Errorf("finding is missing identity fields: %+v", f.EventType)
				}
				if f.Maturity != MaturityExperimental {
					t.Errorf("maturity = %q; every detector is experimental today", f.Maturity)
				}
				if len(f.FalsePositives) == 0 {
					t.Error("finding carries no false-positive guidance")
				}
				if len(f.NextSteps) == 0 {
					t.Error("finding carries no investigation guidance")
				}
				for _, m := range f.MITRE {
					if m.Rationale == "" {
						t.Errorf("ATT&CK technique %s attached with no rationale", m.ID)
					}
				}
			}
		})
	}
}

// The catalogue is what the API and the documentation both quote. Every entry
// has to be complete, or the software misrepresents itself.
func TestDetectorCatalogueIsComplete(t *testing.T) {
	for _, d := range defaultDetectorsForTest() {
		info := d.Info()
		t.Run(info.Name, func(t *testing.T) {
			if info.Name == "" || info.EventType == "" || info.Title == "" || info.Description == "" {
				t.Error("catalogue entry is incomplete")
			}
			if !info.Maturity.valid() {
				t.Errorf("maturity %q is not a known value", info.Maturity)
			}
			if !info.MaxSeverity.Valid() {
				t.Errorf("max severity %q is not a known value", info.MaxSeverity)
			}
			if info.Window == "" {
				t.Error("no observation window published")
			}
			if len(info.SignalNames) == 0 {
				t.Error("no signals published")
			}
			if len(info.FalsePositives) == 0 {
				t.Error("no false positives documented")
			}
			if info.Enforces {
				t.Error("behavioural detection is alert-only; Enforces must be false")
			}
			for _, m := range info.MITRE {
				if m.Rationale == "" {
					t.Errorf("technique %s has no rationale", m.ID)
				}
				if m.ID == "" || m.URL == "" {
					t.Errorf("technique entry is incomplete: %+v", m)
				}
			}
		})
	}
}

// detectorCorpus pairs a detector with traffic that should make it fire.
type detectorCorpus struct {
	name     string
	detector Detector
	corpus   []Observation
	window   time.Duration
}

func allDetectorCorpora() []detectorCorpus {
	servfail := func() []Observation {
		var out []Observation
		t := baseTime
		for i := 0; i < 40; i++ {
			out = append(out, obs(t, "10.0.0.60", "www.broken.example", "A", "SERVFAIL"))
			t = t.Add(2 * time.Second)
		}
		return out
	}()

	return []detectorCorpus{
		{"dns_tunnel", NewTunnelDetector(DefaultTunnelConfig()),
			tunnelTraffic("10.0.0.5", "tunnel.example", 300, 1), DefaultTunnelConfig().Window},
		{"dga_like", NewDGADetector(DefaultDGAConfig()),
			dgaTraffic("10.0.0.40", 200, 70), DefaultDGAConfig().Window},
		{"nxdomain_anomaly", NewNXDomainDetector(DefaultNXDomainConfig()),
			dgaTraffic("10.0.0.30", 200, 60), DefaultNXDomainConfig().Window},
		{"txt_anomaly", NewTXTDetector(DefaultTXTConfig()),
			txtChannelTraffic("10.0.0.50", "c2.example", 150, 80), DefaultTXTConfig().Window},
		{"dns_beaconing", NewBeaconDetector(DefaultBeaconConfig()),
			beaconTraffic("10.0.0.20", "checkin.malware.example", 25, time.Minute, 0.05, 300, 50),
			DefaultBeaconConfig().Window},
		{"resolution_failure", NewResolutionFailureDetector(DefaultResolutionFailureConfig()),
			servfail, DefaultResolutionFailureConfig().Window},
	}
}
