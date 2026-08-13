package detect

import (
	"strings"
	"testing"
	"time"
)

// --- beaconing --------------------------------------------------------------

func TestBeaconDetectorFiresOnFixedCadence(t *testing.T) {
	cfg := DefaultBeaconConfig()
	ex := NewExclusions(nil, false)
	d := NewBeaconDetector(cfg)

	// 60-second cadence with 5% jitter, against a 300-second TTL — so the
	// period cannot be explained by cache expiry.
	corpus := beaconTraffic("10.0.0.20", "checkin.malware.example", 25, time.Minute, 0.05, 300, 50)

	findings := feed(d, ex, corpus, windowEnd(cfg.Window))
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	f := findings[0]

	if f.EventType != EventBeaconing {
		t.Errorf("event type = %q", f.EventType)
	}
	// Beaconing is capped at medium however clean the maths looks, because
	// timing alone cannot distinguish an implant from an updater.
	if f.Severity.Rank() > SeverityMedium.Rank() {
		t.Errorf("severity = %q, must not exceed medium", f.Severity)
	}
	if f.Domain != "checkin.malware.example" {
		t.Errorf("domain = %q", f.Domain)
	}
	if !hasSignal(f, "timing_regularity") {
		t.Error("missing timing_regularity signal")
	}
	if _, ok := f.Evidence["mean_interval_s"]; !ok {
		t.Error("evidence does not state the measured interval")
	}
}

// A client re-resolving because its cache expired queries at exactly the TTL.
// That is a complete, boring explanation for perfect periodicity, so the
// finding is suppressed rather than reported at low confidence.
func TestBeaconDetectorSuppressesTTLDrivenRefresh(t *testing.T) {
	cfg := DefaultBeaconConfig()
	ex := NewExclusions(nil, false)
	d := NewBeaconDetector(cfg)

	// Period equals the TTL: this is a cache refreshing, not a beacon.
	corpus := beaconTraffic("10.0.0.21", "www.busy-site.example", 25, 60*time.Second, 0.02, 60, 51)

	if got := feed(d, ex, corpus, windowEnd(cfg.Window)); len(got) != 0 {
		t.Errorf("fired on TTL-driven re-resolution: %s", got[0].Summary)
	}
}

func TestBeaconDetectorQuietOnIrregularTraffic(t *testing.T) {
	cfg := DefaultBeaconConfig()
	ex := NewExclusions(nil, false)
	d := NewBeaconDetector(cfg)

	if got := feed(d, ex, browsingTraffic("10.0.0.22", 800, 52), windowEnd(cfg.Window)); len(got) != 0 {
		t.Errorf("fired on ordinary browsing: %s", got[0].Summary)
	}
}

func TestBeaconDetectorNeedsEnoughSamples(t *testing.T) {
	cfg := DefaultBeaconConfig()
	ex := NewExclusions(nil, false)
	d := NewBeaconDetector(cfg)

	corpus := beaconTraffic("10.0.0.23", "checkin.malware.example", cfg.MinArrivals-1, time.Minute, 0.02, 300, 53)
	if got := feed(d, ex, corpus, windowEnd(cfg.Window)); len(got) != 0 {
		t.Errorf("fired on %d samples, below the floor of %d", cfg.MinArrivals-1, cfg.MinArrivals)
	}
}

// --- NXDOMAIN ---------------------------------------------------------------

func TestNXDomainDetectorFiresOnBurst(t *testing.T) {
	cfg := DefaultNXDomainConfig()
	ex := NewExclusions(nil, false)
	d := NewNXDomainDetector(cfg)

	findings := feed(d, ex, dgaTraffic("10.0.0.30", 200, 60), windowEnd(cfg.Window))
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	f := findings[0]
	if f.EventType != EventNXDomainBurst {
		t.Errorf("event type = %q", f.EventType)
	}
	if f.Severity.Rank() > SeverityMedium.Rank() {
		t.Errorf("severity = %q, must not exceed medium", f.Severity)
	}
	// The ATT&CK mapping here is explicitly a hypothesis, not a determination.
	for _, m := range f.MITRE {
		if !m.Hypothesis {
			t.Errorf("technique %s on an NXDOMAIN burst should be marked as a hypothesis", m.ID)
		}
	}
}

// The stale-search-suffix false positive is the loudest one this detector
// has, and it is handled structurally rather than by threshold tuning.
func TestNXDomainDetectorIgnoresInternalSearchSuffix(t *testing.T) {
	cfg := DefaultNXDomainConfig()
	ex := NewExclusions(nil, false)
	d := NewNXDomainDetector(cfg)

	corpus := nxdomainSearchSuffixTraffic("10.0.0.31", 400, 61)
	if got := feed(d, ex, corpus, windowEnd(cfg.Window)); len(got) != 0 {
		t.Errorf("fired on a stale internal search suffix: %s", got[0].Summary)
	}
}

// If policy blocks produced NXDOMAIN findings, the better the filtering
// worked, the louder the false alarm would be.
func TestNXDomainDetectorIgnoresPolicyBlocks(t *testing.T) {
	cfg := DefaultNXDomainConfig()
	ex := NewExclusions(nil, false)
	d := NewNXDomainDetector(cfg)

	corpus := dgaTraffic("10.0.0.32", 400, 62)
	for i := range corpus {
		corpus[i].Blocked = true
		corpus[i].Rcode = "NXDOMAIN"
	}
	if got := feed(d, ex, corpus, windowEnd(cfg.Window)); len(got) != 0 {
		t.Errorf("fired on queries DNS Daddy blocked itself: %s", got[0].Summary)
	}
}

func TestNXDomainDetectorQuietOnBrowsing(t *testing.T) {
	cfg := DefaultNXDomainConfig()
	ex := NewExclusions(nil, false)
	d := NewNXDomainDetector(cfg)

	if got := feed(d, ex, browsingTraffic("10.0.0.33", 1000, 63), windowEnd(cfg.Window)); len(got) != 0 {
		t.Errorf("fired on ordinary browsing: %s", got[0].Summary)
	}
}

// --- DGA --------------------------------------------------------------------

func TestDGADetectorFiresOnGeneratedDomains(t *testing.T) {
	cfg := DefaultDGAConfig()
	ex := NewExclusions(nil, false)
	d := NewDGADetector(cfg)

	findings := feed(d, ex, dgaTraffic("10.0.0.40", 200, 70), windowEnd(cfg.Window))
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	f := findings[0]
	if f.EventType != EventDGALike {
		t.Errorf("event type = %q", f.EventType)
	}
	if !hasTechnique(f, "T1568.002") {
		t.Error("expected T1568.002 on a DGA finding")
	}
	examples, ok := f.Evidence["examples"].([]string)
	if !ok || len(examples) == 0 {
		t.Error("finding does not include example domains, so it cannot be checked by eye")
	}
}

func TestDGADetectorQuietOnRealDomains(t *testing.T) {
	cfg := DefaultDGAConfig()
	ex := NewExclusions(nil, false)
	d := NewDGADetector(cfg)

	if got := feed(d, ex, browsingTraffic("10.0.0.41", 1200, 71), windowEnd(cfg.Window)); len(got) != 0 {
		t.Errorf("fired on real domains: %s", got[0].Summary)
	}
}

// The randomness heuristic is the whole detector, so its behaviour on known
// inputs is pinned directly rather than only through the corpora.
func TestRandomnessIndexSeparatesWordsFromGeneratedLabels(t *testing.T) {
	words := []string{
		"google", "wikipedia", "microsoft", "cloudflare", "theguardian",
		"stackoverflow", "nationaltrust", "sainsburys",
	}
	generated := []string{
		"xkqwmzrvbtdh", "qzbxkvnmrtwp", "hjkxzqvwmnbt", "vbnmqxzkwrth",
		"kqxzvwbnmrtj", "zxcvbnmqwrtp",
	}

	for _, w := range words {
		if r := randomnessIndex(w); r >= 0.45 {
			t.Errorf("randomnessIndex(%q) = %.2f, want below the 0.45 threshold", w, r)
		}
	}
	for _, g := range generated {
		if r := randomnessIndex(g); r < 0.45 {
			t.Errorf("randomnessIndex(%q) = %.2f, want at or above the 0.45 threshold", g, r)
		}
	}
}

// --- TXT --------------------------------------------------------------------

func TestTXTDetectorFiresOnTXTChannel(t *testing.T) {
	cfg := DefaultTXTConfig()
	ex := NewExclusions(nil, false)
	d := NewTXTDetector(cfg)

	findings := feed(d, ex, txtChannelTraffic("10.0.0.50", "c2.example", 150, 80), windowEnd(cfg.Window))
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	f := findings[0]
	if f.EventType != EventTXTAnomaly {
		t.Errorf("event type = %q", f.EventType)
	}
	if f.QType != "TXT" {
		t.Errorf("qtype = %q", f.QType)
	}
}

// A mail server is the reason this detector needs an exclusion step at all:
// it produces more TXT lookups than any tunnel would.
func TestTXTDetectorQuietOnMailInfrastructure(t *testing.T) {
	cfg := DefaultTXTConfig()
	ex := NewExclusions(nil, false)
	d := NewTXTDetector(cfg)

	findings := feed(d, ex, mailTXTTraffic("10.0.0.51", 600, 81), windowEnd(cfg.Window))
	if len(findings) != 0 {
		t.Errorf("fired on SPF/DKIM/DMARC traffic: %s", findings[0].Summary)
	}
}

func TestTXTInfrastructureRecognition(t *testing.T) {
	infrastructure := []string{
		"_dmarc.example.com",
		"selector1._domainkey.example.com",
		"mail._domainkey.supplier.co.uk",
		"_mta-sts.example.com",
		"_acme-challenge.example.com",
	}
	channel := []string{
		"mfzwizltoqyc4ylbmnqxgzjan52geylu.c2.example",
		"data001.exfil.example",
	}

	for _, n := range infrastructure {
		if !isTXTInfrastructure(n) {
			t.Errorf("%q should be recognised as infrastructure", n)
		}
	}
	for _, n := range channel {
		if isTXTInfrastructure(n) {
			t.Errorf("%q should not be recognised as infrastructure", n)
		}
	}
}

// --- resolution failure -----------------------------------------------------

func TestResolutionFailureDetectorFiresOnPersistentSERVFAIL(t *testing.T) {
	cfg := DefaultResolutionFailureConfig()
	ex := NewExclusions(nil, false)
	d := NewResolutionFailureDetector(cfg)

	var corpus []Observation
	t0 := baseTime
	for i := 0; i < 40; i++ {
		corpus = append(corpus, obs(t0, "10.0.0.60", "www.broken-dnssec.example", "A", "SERVFAIL"))
		t0 = t0.Add(2 * time.Second)
	}

	findings := feed(d, ex, corpus, windowEnd(cfg.Window))
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	f := findings[0]

	// This detector deliberately carries no ATT&CK mapping: infrastructure
	// breakage is not an adversary technique, and attaching one would be
	// exactly the decoration the mapping policy forbids.
	if len(f.MITRE) != 0 {
		t.Errorf("resolution failures must not carry ATT&CK mappings, got %v", f.MITRE)
	}

	// It must not overclaim: DNS Daddy does not validate DNSSEC locally and
	// cannot tell a bogus signature from an unreachable nameserver.
	causes, ok := f.Evidence["possible_causes"].([]string)
	if !ok || len(causes) < 2 {
		t.Fatal("finding does not list the alternative causes")
	}
	if got := f.Evidence["local_dnssec_validation"]; got != false {
		t.Errorf("local_dnssec_validation = %v, want false", got)
	}
	if strings.Contains(strings.ToLower(f.Title), "dnssec") {
		t.Errorf("title claims a DNSSEC verdict the telemetry cannot support: %q", f.Title)
	}
}

func TestResolutionFailureDetectorQuietOnOccasionalFailure(t *testing.T) {
	cfg := DefaultResolutionFailureConfig()
	ex := NewExclusions(nil, false)
	d := NewResolutionFailureDetector(cfg)

	// Mostly working, occasionally not: below the failure-ratio floor.
	var corpus []Observation
	t0 := baseTime
	for i := 0; i < 100; i++ {
		rcode := "NOERROR"
		if i%12 == 0 {
			rcode = "SERVFAIL"
		}
		corpus = append(corpus, obs(t0, "10.0.0.61", "www.mostly-fine.example", "A", rcode))
		t0 = t0.Add(time.Second)
	}
	if got := feed(d, ex, corpus, windowEnd(cfg.Window)); len(got) != 0 {
		t.Errorf("fired on an intermittently failing domain: %s", got[0].Summary)
	}
}
