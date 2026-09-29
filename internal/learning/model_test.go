package learning

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
)

// The benign profile comes first: repeated service lookups, mixed record
// types, and ordinary label variation. The malicious-labelled stress cases
// below are synthetic hypotheses, never real-world accuracy evidence.
func testOptions() Options {
	return Options{Window: time.Minute, MinWindowQueries: 20, WarmupWindows: 4, WarmupDuration: 4 * time.Minute, IdleTTL: time.Hour, MaxClients: 4, MaxWindowQueries: 256, MaxUniqueDomains: 128, Cooldown: time.Minute}
}
func benignWindow(at time.Time, client string, count int) []detect.Observation {
	labels := []string{"login", "updates", "mail", "calendar", "portal", "assets", "search", "storage"}
	out := make([]detect.Observation, 0, count)
	for i := range count {
		qtype := "A"
		if i%4 == 0 {
			qtype = "AAAA"
		}
		if i%23 == 0 {
			qtype = "TXT"
		}
		out = append(out, detect.Observation{Time: at.Add(time.Duration(i) * time.Second), ClientIP: client, NetworkID: "lab", QName: labels[i%len(labels)] + ".service.example", QType: qtype, Rcode: "NOERROR"})
	}
	return out
}
func unusualWindow(at time.Time, client string, count int) []detect.Observation {
	out := make([]detect.Observation, 0, count)
	for i := range count {
		out = append(out, detect.Observation{Time: at.Add(time.Duration(i) * time.Second), ClientIP: client, NetworkID: "lab", QName: fmt.Sprintf("q%02d-a1b2c3d4e5f6g7h8a1b2c3d4e5f6g7h8a1b2c3d4.exfil.example", i), QType: "TXT", Rcode: "NOERROR"})
	}
	return out
}
func feedWindow(m *Model, observations []detect.Observation, at time.Time) Result {
	var out []Result
	for _, o := range observations {
		out = append(out, m.Observe(o)...)
	}
	out = append(out, m.Advance(at.Add(m.opts.Window))...)
	if len(out) != 1 {
		panic(fmt.Sprintf("expected one completed window, got %d", len(out)))
	}
	return out[0]
}
func trainedModel(t *testing.T) (*Model, time.Time) {
	t.Helper()
	m, err := NewModel(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for range 4 {
		r := feedWindow(m, benignWindow(at, "192.0.2.10", 40), at)
		if !r.Trained {
			t.Fatalf("benign warmup not trained: %+v", r)
		}
		at = at.Add(time.Minute)
	}
	return m, at
}

func TestColdStartHasNoFabricatedAnomalyScore(t *testing.T) {
	m, _ := NewModel(testOptions())
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := range 4 {
		r := feedWindow(m, benignWindow(at, "192.0.2.10", 40), at)
		if r.Score != nil || r.State != "learning" || !r.Trained {
			t.Fatalf("window %d: %+v", i, r)
		}
		at = at.Add(time.Minute)
	}
	view, _ := m.Inspect("192.0.2.10")
	if !view.Ready || view.BaselineWindows != 4 || view.BaselineQueries != 160 {
		t.Fatalf("readiness: %+v", view)
	}
	r := feedWindow(m, benignWindow(at, "192.0.2.10", 40), at)
	if r.Score == nil || *r.Score > 1e-9 || r.State != "typical" {
		t.Fatalf("normal holdout: %+v", r)
	}
}

func TestTimeAndSampleRequirementsBothGateReadiness(t *testing.T) {
	o := testOptions()
	o.WarmupDuration = 10 * time.Minute
	m, _ := NewModel(o)
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for range 4 {
		feedWindow(m, benignWindow(at, "192.0.2.10", 40), at)
		at = at.Add(time.Minute)
	}
	v, _ := m.Inspect("192.0.2.10")
	if v.Ready {
		t.Fatal("window count replaced elapsed history requirement")
	}
	r := feedWindow(m, benignWindow(at, "192.0.2.10", 19), at)
	if r.Score != nil || r.Trained || r.State != "insufficient" {
		t.Fatalf("too few queries: %+v", r)
	}
}

func TestNewTrafficActuallyFitsParametersAndGradualDriftAdapts(t *testing.T) {
	m, at := trainedModel(t)
	before, _ := m.Inspect("192.0.2.10")
	var first, last float64
	for i := range 30 {
		obs := benignWindow(at, "192.0.2.10", 48)
		for j := range obs {
			obs[j].QName = "workspace" + fmt.Sprintf("%d", j%8) + ".service.example"
		}
		r := feedWindow(m, obs, at)
		if !r.Trained || r.State != "typical" || r.Score == nil {
			t.Fatalf("ordinary changed work pattern must fit: %+v", r)
		}
		if i == 0 {
			first = *r.Score
		}
		last = *r.Score
		at = at.Add(time.Minute)
	}
	after, _ := m.Inspect("192.0.2.10")
	if *after.Features[1].BaselineMean <= *before.Features[1].BaselineMean || last >= first || after.BaselineWindows != 34 {
		t.Fatalf("no online fitting: before=%+v after=%+v distance %.4f -> %.4f", before, after, first, last)
	}
}

func TestAnomalyIsScoredBeforeTrainingAndQuarantined(t *testing.T) {
	m, at := trainedModel(t)
	before := m.clients["192.0.2.10"].Baseline
	r := feedWindow(m, unusualWindow(at, "192.0.2.10", 40), at)
	if r.Score == nil || *r.Score < m.opts.Threshold || r.AnomalousSignals < 2 || r.State != "anomaly" || r.Trained {
		t.Fatalf("unusual holdout: %+v", r)
	}
	if m.clients["192.0.2.10"].Baseline != before {
		t.Fatal("anomaly contaminated the normal baseline")
	}
	for range 20 {
		at = at.Add(time.Minute)
		feedWindow(m, unusualWindow(at, "192.0.2.10", 40), at)
	}
	if m.clients["192.0.2.10"].Baseline != before {
		t.Fatal("repeated extreme outliers were silently absorbed")
	}
}

func TestBlockedAndFailedQueriesNeverBecomeNormalTraining(t *testing.T) {
	for _, kind := range []string{"blocked", "SERVFAIL", "NXDOMAIN"} {
		t.Run(kind, func(t *testing.T) {
			m, at := trainedModel(t)
			before := m.clients["192.0.2.10"].Baseline
			obs := benignWindow(at, "192.0.2.10", 40)
			if kind == "blocked" {
				obs[0].Blocked = true
			} else {
				obs[0].Rcode = kind
			}
			r := feedWindow(m, obs, at)
			if r.Trained || len(r.ExcludedReasons) == 0 || m.clients["192.0.2.10"].Baseline != before {
				t.Fatalf("contaminated normal: %+v", r)
			}
		})
	}
}

func TestObviousEncodedTrafficCannotBootstrapItsOwnNormal(t *testing.T) {
	m, _ := NewModel(testOptions())
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for range 8 {
		r := feedWindow(m, unusualWindow(at, "192.0.2.10", 40), at)
		if r.Trained || r.Score != nil || r.State != "excluded" {
			t.Fatalf("bootstrap contamination: %+v", r)
		}
		at = at.Add(time.Minute)
	}
	v, _ := m.Inspect("192.0.2.10")
	if v.Ready || v.BaselineWindows != 0 {
		t.Fatal("hostile cold start became ready")
	}
}

func TestBoundsAccountForEvictionsOverflowAndSaturatedDiversity(t *testing.T) {
	o := testOptions()
	o.MaxClients = 2
	o.MaxUniqueDomains = 2
	o.MaxWindowQueries = 20
	m, _ := NewModel(o)
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= 30; i++ {
		m.Observe(detect.Observation{Time: at, ClientIP: fmt.Sprintf("192.0.2.%d", i), QName: "mail.example", QType: "A", Rcode: "NOERROR"})
	}
	if len(m.clients) != 2 || m.evicted != 28 || m.windows.EvictedPending != 28 {
		t.Fatalf("unbounded subjects: %d %d", len(m.clients), m.evicted)
	}
	obs := benignWindow(at, "192.0.2.30", 40)
	for _, v := range obs {
		m.Observe(v)
	}
	out := m.Advance(at.Add(time.Minute))
	if m.observations.WindowOverflow != 21 || m.observations.UniqueSaturated != 1 {
		t.Fatalf("loss not counted: %+v", m.observations)
	}
	for _, r := range out {
		if r.Client == "192.0.2.30" && (r.Trained || r.Window.Queries != 20 || !strings.Contains(strings.Join(r.ExcludedReasons, ","), "unique_domain_limit")) {
			t.Fatalf("partial window trained: %+v", r)
		}
	}
}

func TestOutOfOrderAndInvalidObservationsDoNotReopenHistory(t *testing.T) {
	m, at := trainedModel(t)
	before := m.clients["192.0.2.10"].Baseline
	m.Observe(benignWindow(at.Add(-time.Minute), "192.0.2.10", 1)[0])
	m.Observe(detect.Observation{Time: at, ClientIP: "not an IP", QName: "mail.example", Rcode: "NOERROR"})
	m.Observe(detect.Observation{Time: at, ClientIP: "192.0.2.10", QName: strings.Repeat("x", 2000), Rcode: "NOERROR"})
	if m.observations.Late != 1 || m.observations.Invalid != 2 || m.clients["192.0.2.10"].Baseline != before {
		t.Fatalf("bad events changed history: %+v", m.observations)
	}
}

func TestPrivacyAttributionAggregatesWithoutInventingDevices(t *testing.T) {
	m, _ := NewModel(testOptions())
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	obs := benignWindow(at, "", 40)
	for i := range obs {
		obs[i].ClientName = "should-not-be-retained"
	}
	feedWindow(m, obs, at)
	v, ok := m.Inspect("network:lab")
	if !ok || v.Client != "network:lab" || len(m.clients) != 1 {
		t.Fatalf("privacy attribution: %+v", v)
	}
}

func TestFittedVarianceAndFindingArithmeticRemainFinite(t *testing.T) {
	m, at := trainedModel(t)
	r := feedWindow(m, unusualWindow(at, "192.0.2.10", 40), at)
	f := finding(r)
	sum := 0.0
	for _, s := range f.Signals {
		sum += s.Contribution
	}
	if math.Abs(f.Score-sum) > 1e-12 || f.Confidence != 0 || f.Evidence["confidenceAvailable"] != false || f.Evidence["enforces"] != false || f.Maturity != detect.MaturityExperimental {
		t.Fatalf("misleading score semantics: %+v", f)
	}
}
