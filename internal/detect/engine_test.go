package detect

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// recordingSink collects findings for assertions.
type recordingSink struct {
	mu       sync.Mutex
	findings []Finding
	err      error
}

func (s *recordingSink) Emit(_ context.Context, f Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = append(s.findings, f)
	return s.err
}

func (s *recordingSink) all() []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Finding(nil), s.findings...)
}

// stubDetector emits a fixed finding whenever Evaluate is called, so engine
// behaviour can be tested without depending on any heuristic's thresholds.
type stubDetector struct {
	observed int
	emit     *Finding
	sweeps   int
}

func (d *stubDetector) Name() string { return "stub" }
func (d *stubDetector) Info() DetectorInfo {
	return DetectorInfo{Name: "stub", EventType: "stub_event", Maturity: MaturityExperimental}
}
func (d *stubDetector) Observe(*Event) { d.observed++ }
func (d *stubDetector) Evaluate(now time.Time) []Finding {
	if d.emit == nil {
		return nil
	}
	f := *d.emit
	f.Time = now
	return []Finding{f}
}
func (d *stubDetector) Sweep(time.Time) { d.sweeps++ }
func (d *stubDetector) Tracked() int    { return 1 }

func stubFinding(sev Severity) *Finding {
	return &Finding{
		EventType: "stub_event",
		Severity:  sev,
		Client:    Client{IP: "10.0.0.1"},
		Domain:    "example.com",
		Title:     "stub",
		Summary:   "stub",
	}
}

// The single most important property of this package: a full detection queue
// must never make a DNS query wait.
func TestObserveNeverBlocks(t *testing.T) {
	sink := &recordingSink{}
	e := New(nil, sink, NewExclusions(nil, false), Options{BufferSize: 4}, testLogger())

	// Nothing is draining the channel, so everything past the buffer must be
	// dropped rather than block. A deadline makes the failure a test failure
	// rather than a hung suite.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			e.Observe(Observation{Time: time.Now(), QName: "example.com", QType: "A"})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe blocked when the buffer was full; the DNS path would have stalled")
	}

	if got := e.Stats().Dropped; got == 0 {
		t.Error("expected dropped observations to be counted")
	}
}

func TestEngineEnrichesObservations(t *testing.T) {
	var captured *Event
	capture := &captureDetector{fn: func(e *Event) { captured = e }}

	e := New([]Detector{capture}, &recordingSink{}, NewExclusions(nil, false), Options{}, testLogger())
	e.ingest(Observation{
		Time:  time.Now(),
		QName: "a.b.example.co.uk",
		QType: "A",
		Rcode: "NXDOMAIN",
	})

	if captured == nil {
		t.Fatal("detector saw no event")
	}
	if captured.Parent != "example.co.uk" {
		t.Errorf("parent = %q, want example.co.uk", captured.Parent)
	}
	if captured.Sub != "a.b" {
		t.Errorf("sub = %q, want a.b", captured.Sub)
	}
	if !captured.NXDomain {
		t.Error("NXDomain not derived from rcode")
	}
}

// Blocked queries carry an NXDOMAIN rcode that DNS Daddy synthesised itself.
// Deriving NXDomain from it would make effective filtering look like an
// incident, so the engine must not.
func TestEngineDoesNotTreatPolicyBlocksAsUpstreamFailures(t *testing.T) {
	var captured *Event
	capture := &captureDetector{fn: func(e *Event) { captured = e }}

	e := New([]Detector{capture}, &recordingSink{}, NewExclusions(nil, false), Options{}, testLogger())
	e.ingest(Observation{
		Time:    time.Now(),
		QName:   "malware.example",
		QType:   "A",
		Rcode:   "NXDOMAIN",
		Blocked: true,
	})

	if captured.NXDomain {
		t.Error("a policy block was recorded as an upstream NXDOMAIN")
	}
}

func TestEngineMarksExcludedNames(t *testing.T) {
	var captured *Event
	capture := &captureDetector{fn: func(e *Event) { captured = e }}

	e := New([]Detector{capture}, &recordingSink{}, NewExclusions([]string{"vendor.example"}, false), Options{}, testLogger())
	e.ingest(Observation{Time: time.Now(), QName: "deep.sub.vendor.example", QType: "A"})

	if !captured.Excluded {
		t.Error("name beneath an excluded parent was not marked excluded")
	}
	if got := e.Stats().Excluded; got != 1 {
		t.Errorf("excluded count = %d, want 1", got)
	}
}

func TestEngineCooldownSuppressesRepeats(t *testing.T) {
	sink := &recordingSink{}
	d := &stubDetector{emit: stubFinding(SeverityHigh)}
	e := New([]Detector{d}, sink, NewExclusions(nil, false), Options{Cooldown: time.Hour}, testLogger())

	now := time.Now()
	e.evaluate(context.Background(), now)
	e.evaluate(context.Background(), now.Add(time.Minute))
	e.evaluate(context.Background(), now.Add(2*time.Minute))

	if got := len(sink.all()); got != 1 {
		t.Errorf("emitted %d findings, want 1 with the cooldown active", got)
	}
	if got := e.Stats().Suppressed; got != 2 {
		t.Errorf("suppressed = %d, want 2", got)
	}

	// Past the cooldown it must report again — an ongoing problem should not
	// go silent forever.
	e.evaluate(context.Background(), now.Add(2*time.Hour))
	if got := len(sink.all()); got != 2 {
		t.Errorf("emitted %d findings after the cooldown expired, want 2", got)
	}
}

func TestEngineMinSeverityFilter(t *testing.T) {
	sink := &recordingSink{}
	d := &stubDetector{emit: stubFinding(SeverityLow)}
	e := New([]Detector{d}, sink, NewExclusions(nil, false), Options{MinSeverity: SeverityHigh}, testLogger())

	e.evaluate(context.Background(), time.Now())
	if got := len(sink.all()); got != 0 {
		t.Errorf("emitted %d findings below min_severity, want 0", got)
	}
}

func TestEngineAssignsIDsAndSchemaVersion(t *testing.T) {
	sink := &recordingSink{}
	d := &stubDetector{emit: stubFinding(SeverityHigh)}
	e := New([]Detector{d}, sink, NewExclusions(nil, false), Options{}, testLogger())

	e.evaluate(context.Background(), time.Now())
	all := sink.all()
	if len(all) != 1 {
		t.Fatalf("expected one finding, got %d", len(all))
	}
	if all[0].ID == "" {
		t.Error("finding has no ID; SIEM deduplication depends on it")
	}
	if all[0].SchemaVersion != SchemaVersion {
		t.Errorf("schema version = %q, want %q", all[0].SchemaVersion, SchemaVersion)
	}
}

// A sink that fails must not stop the engine, and must not stop other sinks.
func TestMultiSinkContinuesAfterFailure(t *testing.T) {
	failing := &recordingSink{err: io.ErrUnexpectedEOF}
	working := &recordingSink{}

	m := MultiSink{failing, working}
	if err := m.Emit(context.Background(), *stubFinding(SeverityHigh)); err == nil {
		t.Error("expected the failure to be reported")
	}
	if len(working.all()) != 1 {
		t.Error("a failing sink prevented a working one from receiving the finding")
	}
}

func TestEngineRunDrainsOnShutdown(t *testing.T) {
	sink := &recordingSink{}
	d := &stubDetector{emit: stubFinding(SeverityHigh)}
	e := New([]Detector{d}, sink, NewExclusions(nil, false), Options{
		EvalInterval: time.Hour, // never fires during the test
	}, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)

	for i := 0; i < 10; i++ {
		e.Observe(Observation{Time: time.Now(), QName: "example.com", QType: "A"})
	}
	cancel()
	e.Wait()

	if d.observed == 0 {
		t.Error("queued observations were discarded on shutdown")
	}
	// The shutdown path evaluates once so a window that closed during
	// shutdown still reports.
	if len(sink.all()) == 0 {
		t.Error("no final evaluation ran on shutdown")
	}
}

func TestEngineCatalogueDescribesDetectors(t *testing.T) {
	e := New(defaultDetectorsForTest(), &recordingSink{}, NewExclusions(nil, false), Options{}, testLogger())

	cat := e.Catalogue()
	if len(cat) == 0 {
		t.Fatal("catalogue is empty")
	}
	for _, info := range cat {
		if info.Name == "" || info.EventType == "" {
			t.Errorf("catalogue entry is incomplete: %+v", info)
		}
		if !info.Maturity.valid() {
			t.Errorf("detector %q has no maturity", info.Name)
		}
		if len(info.FalsePositives) == 0 {
			t.Errorf("detector %q documents no false positives", info.Name)
		}
		// No behavioural detector in this package enforces policy. If that
		// ever changes it must be a deliberate, reviewed decision, not a
		// default that slipped in.
		if info.Enforces {
			t.Errorf("detector %q claims to enforce policy; behavioural detection is alert-only", info.Name)
		}
	}
}

// captureDetector hands each event to a callback.
type captureDetector struct{ fn func(*Event) }

func (d *captureDetector) Name() string                 { return "capture" }
func (d *captureDetector) Info() DetectorInfo           { return DetectorInfo{Name: "capture"} }
func (d *captureDetector) Observe(e *Event)             { d.fn(e) }
func (d *captureDetector) Evaluate(time.Time) []Finding { return nil }
func (d *captureDetector) Sweep(time.Time)              {}
func (d *captureDetector) Tracked() int                 { return 0 }

func defaultDetectorsForTest() []Detector {
	return []Detector{
		NewTunnelDetector(DefaultTunnelConfig()),
		NewBeaconDetector(DefaultBeaconConfig()),
		NewNXDomainDetector(DefaultNXDomainConfig()),
		NewDGADetector(DefaultDGAConfig()),
		NewTXTDetector(DefaultTXTConfig()),
		NewResolutionFailureDetector(DefaultResolutionFailureConfig()),
	}
}

func (m Maturity) valid() bool {
	return m == MaturityAvailable || m == MaturityExperimental
}
