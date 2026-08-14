package detect

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTunnelDetectorFiresOnSustainedTunnel(t *testing.T) {
	cfg := DefaultTunnelConfig()
	ex := NewExclusions(nil, false)
	d := NewTunnelDetector(cfg)

	findings := feed(d, ex, tunnelTraffic("10.0.0.5", "tunnel.example", 300, 1), windowEnd(cfg.Window))

	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %d", len(findings))
	}
	f := findings[0]

	if f.EventType != EventTunnelSuspected {
		t.Errorf("event type = %q, want %q", f.EventType, EventTunnelSuspected)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high (score %.2f)", f.Severity, f.Score)
	}
	if f.Confidence < 0.7 {
		t.Errorf("confidence = %.2f, want at least 0.7", f.Confidence)
	}
	if f.Client.IP != "10.0.0.5" {
		t.Errorf("client = %q, want 10.0.0.5", f.Client.IP)
	}
	if f.Domain != "tunnel.example" {
		t.Errorf("domain = %q, want tunnel.example", f.Domain)
	}
	if f.Maturity != MaturityExperimental {
		t.Errorf("maturity = %q, want experimental", f.Maturity)
	}
}

// A finding that cannot be explained is not actionable, so the explanation is
// tested as a feature rather than assumed to be decoration.
func TestTunnelFindingIsExplainable(t *testing.T) {
	cfg := DefaultTunnelConfig()
	ex := NewExclusions(nil, false)
	d := NewTunnelDetector(cfg)

	findings := feed(d, ex, tunnelTraffic("10.0.0.5", "tunnel.example", 300, 2), windowEnd(cfg.Window))
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	f := findings[0]

	if len(f.Signals) != 7 {
		t.Fatalf("expected 7 signals, got %d", len(f.Signals))
	}

	// The published contributions must add up to the published score, or the
	// numbers in the finding cannot be checked by hand.
	var sum float64
	for _, s := range f.Signals {
		sum += s.Contribution
		if s.Description == "" {
			t.Errorf("signal %q has no description", s.Name)
		}
		if s.Weight <= 0 {
			t.Errorf("signal %q has weight %v", s.Name, s.Weight)
		}
	}
	if diff := sum - f.Score; diff > 0.05 || diff < -0.05 {
		t.Errorf("signal contributions sum to %.3f but score is %.3f", sum, f.Score)
	}

	for _, want := range []string{"unique_subdomains", "mean_subdomain_entropy", "encoded_label_ratio"} {
		if !hasSignal(f, want) {
			t.Errorf("missing signal %q", want)
		}
	}

	if f.Summary == "" || !strings.Contains(f.Summary, "tunnel.example") {
		t.Errorf("summary does not name the domain: %q", f.Summary)
	}
	if len(f.FalsePositives) == 0 {
		t.Error("finding carries no false-positive guidance")
	}
	if len(f.NextSteps) == 0 {
		t.Error("finding carries no investigation guidance")
	}

	// Every ATT&CK mapping must justify itself.
	if len(f.MITRE) == 0 {
		t.Fatal("expected ATT&CK mappings")
	}
	for _, m := range f.MITRE {
		if m.Rationale == "" {
			t.Errorf("technique %s attached with no rationale", m.ID)
		}
	}
	if !hasTechnique(f, "T1071.004") {
		t.Error("expected T1071.004 on a tunnelling finding")
	}
}

// The signal weights are a published contract: a finding claims its
// contributions sum to its score, which is only true if the weights sum to 1.
func TestTunnelWeightsSumToOne(t *testing.T) {
	cfg := DefaultTunnelConfig()
	ex := NewExclusions(nil, false)
	d := NewTunnelDetector(cfg)

	findings := feed(d, ex, tunnelTraffic("10.0.0.5", "tunnel.example", 300, 3), windowEnd(cfg.Window))
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	var total float64
	for _, s := range findings[0].Signals {
		total += s.Weight
	}
	if total < 0.999 || total > 1.001 {
		t.Errorf("signal weights sum to %.4f, want 1.0", total)
	}
}

func TestTunnelDetectorQuietOnBenignTraffic(t *testing.T) {
	cfg := DefaultTunnelConfig()

	cases := []struct {
		name       string
		corpus     []Observation
		why        string
		exclusions *Exclusions
	}{
		{
			name:       "ordinary browsing",
			corpus:     browsingTraffic("10.0.0.7", 500, 10),
			why:        "short structured names, address lookups, low cardinality per parent",
			exclusions: NewExclusions(nil, false),
		},
		{
			name:       "CDN with very high subdomain cardinality",
			corpus:     cdnTraffic("10.0.0.8", "not-on-the-list.example", 600, 11),
			why:        "cardinality alone must not raise a finding",
			exclusions: NewExclusions(nil, false),
		},
		{
			name:       "mail server doing DNSBL lookups",
			corpus:     dnsblTraffic("10.0.0.9", "zen.spamhaus.org", 800, 12),
			why:        "covered by the shipped exclusion list",
			exclusions: NewExclusions(nil, false),
		},
		{
			name:       "IPv6 reverse DNS",
			corpus:     ipv6ReverseTraffic("10.0.0.10", 400, 13),
			why:        "32 hex labels per lookup; .arpa is excluded outright",
			exclusions: NewExclusions(nil, false),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewTunnelDetector(cfg)
			findings := feed(d, tc.exclusions, tc.corpus, windowEnd(cfg.Window))
			if len(findings) != 0 {
				t.Errorf("expected no findings (%s), got %d: %s",
					tc.why, len(findings), findings[0].Summary)
			}
		})
	}
}

// The exclusion list is a deliberate, documented trade-off, not an accident.
// This test pins both halves of it: DNSBL traffic is indistinguishable from a
// tunnel by shape, and is only quiet because the provider is excluded.
func TestDNSBLTrafficWouldFireWithoutExclusions(t *testing.T) {
	cfg := DefaultTunnelConfig()
	bare := NewExclusions(nil, true)
	d := NewTunnelDetector(cfg)

	// Long encoded labels beneath a reputation provider — the shape an
	// endpoint agent produces when it looks up a file hash.
	findings := feed(d, bare, hashReputationTraffic("10.0.0.9", "sophosxl.net", 300, 14), windowEnd(cfg.Window))
	if len(findings) == 0 {
		t.Fatal("expected the un-excluded corpus to fire — if it does not, the " +
			"exclusion list is not what is keeping it quiet and this trade-off " +
			"needs re-examining")
	}

	withDefaults := NewExclusions(nil, false)
	d2 := NewTunnelDetector(cfg)
	if got := feed(d2, withDefaults, hashReputationTraffic("10.0.0.9", "sophosxl.net", 300, 14), windowEnd(cfg.Window)); len(got) != 0 {
		t.Errorf("expected the default exclusions to suppress it, got %d findings", len(got))
	}
}

func TestTunnelDetectorRespectsGates(t *testing.T) {
	cfg := DefaultTunnelConfig()
	ex := NewExclusions(nil, false)

	t.Run("below the query floor", func(t *testing.T) {
		d := NewTunnelDetector(cfg)
		n := cfg.MinQueries - 1
		if got := feed(d, ex, tunnelTraffic("10.0.0.5", "tunnel.example", n, 20), windowEnd(cfg.Window)); len(got) != 0 {
			t.Errorf("fired on %d queries, below the floor of %d", n, cfg.MinQueries)
		}
	})

	t.Run("high entropy alone is not enough", func(t *testing.T) {
		// A single signal at maximum must not produce a finding. This is the
		// multi-signal gate, and it is the main defence against "high entropy
		// equals malicious".
		d := NewTunnelDetector(cfg)
		corpus := singleSignalTraffic("10.0.0.11", "widgets.example", 200, 21)
		if got := feed(d, ex, corpus, windowEnd(cfg.Window)); len(got) != 0 {
			t.Errorf("fired on a single extreme signal: %s", got[0].Summary)
		}
	})

	t.Run("names with no registered domain are ignored", func(t *testing.T) {
		d := NewTunnelDetector(cfg)
		var corpus []Observation
		for _, o := range tunnelTraffic("10.0.0.5", "tunnel.example", 300, 22) {
			o.QName = strings.TrimSuffix(o.QName, ".tunnel.example") + ".corp.internal"
			corpus = append(corpus, o)
		}
		if got := feed(d, ex, corpus, windowEnd(cfg.Window)); len(got) != 0 {
			t.Errorf("fired on internal names with no registered domain: %s", got[0].Summary)
		}
	})
}

// Blocked queries are answered NXDOMAIN by DNS Daddy itself. If those counted
// towards the NXDOMAIN signal, effective filtering would look like an attack.
func TestBlockedQueriesDoNotInflateNXDOMAINSignal(t *testing.T) {
	cfg := DefaultTunnelConfig()
	ex := NewExclusions(nil, false)
	d := NewTunnelDetector(cfg)

	corpus := tunnelTraffic("10.0.0.5", "tunnel.example", 200, 30)
	for i := range corpus {
		corpus[i].Blocked = true
		corpus[i].Rcode = "NXDOMAIN"
	}

	findings := feed(d, ex, corpus, windowEnd(cfg.Window))
	if len(findings) == 0 {
		t.Skip("no finding produced; the NXDOMAIN signal cannot be checked")
	}
	for _, s := range findings[0].Signals {
		if s.Name == "nxdomain_ratio" && s.Value != 0 {
			t.Errorf("nxdomain_ratio = %v on blocked-only traffic, want 0", s.Value)
		}
	}
}

// The JSON encoding is the integration contract with every SIEM downstream, so
// it is asserted directly rather than trusted to struct tags.
func TestFindingJSONShape(t *testing.T) {
	cfg := DefaultTunnelConfig()
	ex := NewExclusions(nil, false)
	d := NewTunnelDetector(cfg)

	findings := feed(d, ex, tunnelTraffic("10.0.0.5", "tunnel.example", 300, 40), windowEnd(cfg.Window))
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	f := findings[0]
	f.ID = "test"
	f.SchemaVersion = SchemaVersion

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{
		"schemaVersion", "id", "time", "eventType", "severity", "confidence",
		"score", "client", "domain", "title", "summary", "signals", "evidence",
		"window", "mitre", "falsePositives", "nextSteps", "detector", "maturity",
	} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("finding JSON is missing %q", key)
		}
	}

	if decoded["schemaVersion"] != SchemaVersion {
		t.Errorf("schemaVersion = %v, want %s", decoded["schemaVersion"], SchemaVersion)
	}

	// The evidence block is what an analyst reads first.
	evidence, ok := decoded["evidence"].(map[string]any)
	if !ok {
		t.Fatal("evidence is not an object")
	}
	for _, key := range []string{"unique_subdomains", "average_entropy", "queries"} {
		if _, ok := evidence[key]; !ok {
			t.Errorf("evidence is missing %q", key)
		}
	}
}

func hasSignal(f Finding, name string) bool {
	for _, s := range f.Signals {
		if s.Name == name {
			return true
		}
	}
	return false
}

func hasTechnique(f Finding, id string) bool {
	for _, m := range f.MITRE {
		if m.ID == id {
			return true
		}
	}
	return false
}
