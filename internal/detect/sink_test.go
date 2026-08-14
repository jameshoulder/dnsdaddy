package detect

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileSinkWritesNDJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")

	s, err := NewFileSink(FileSinkOptions{Path: path})
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	defer s.Close()

	for i := 0; i < 3; i++ {
		f := *stubFinding(SeverityHigh)
		f.ID = "id-" + string(rune('a'+i))
		f.SchemaVersion = SchemaVersion
		f.Time = time.Unix(1700000000, 0).UTC()
		if err := s.Emit(context.Background(), f); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
	// Every line must be independently parseable: that is the whole point of
	// the format, and it is what lets a shipper resume mid-file.
	for i, line := range lines {
		var f Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i+1, err)
		}
		if f.SchemaVersion != SchemaVersion {
			t.Errorf("line %d has schema version %q", i+1, f.SchemaVersion)
		}
	}
}

func TestFileSinkRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")

	// A tiny cap so a handful of findings forces several rotations.
	s, err := NewFileSink(FileSinkOptions{Path: path, MaxBytes: 512, Keep: 2})
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	defer s.Close()

	for i := 0; i < 40; i++ {
		f := *stubFinding(SeverityHigh)
		f.ID = "id"
		f.Summary = strings.Repeat("x", 100)
		if err := s.Emit(context.Background(), f); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("current file missing: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("rotated file missing: %v", err)
	}
	// Retention must be bounded, or a busy instance fills the disk.
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Error("kept more rotations than configured")
	}
}

// Findings contain client IPs and the names those clients looked up. That is
// browsing history, and the file must not be world-readable.
func TestFileSinkPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")

	s, err := NewFileSink(FileSinkOptions{Path: path})
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	defer s.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		t.Errorf("findings file mode is %v; it must not be readable by other users", perm)
	}
}

func TestFileSinkEmitAfterCloseDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileSink(FileSinkOptions{Path: filepath.Join(dir, "f.jsonl")})
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Emit(context.Background(), *stubFinding(SeverityHigh)); err == nil {
		t.Error("expected an error emitting to a closed sink")
	}
}

// A finding must survive a round trip through the file unchanged in every
// field a downstream consumer keys on.
func TestFindingRoundTripsThroughFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	s, err := NewFileSink(FileSinkOptions{Path: path})
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}

	ex := NewExclusions(nil, false)
	d := NewTunnelDetector(DefaultTunnelConfig())
	findings := feed(d, ex, tunnelTraffic("10.0.0.5", "tunnel.example", 300, 90), windowEnd(DefaultTunnelConfig().Window))
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	original := findings[0]
	original.ID = "abc123"
	original.SchemaVersion = SchemaVersion

	if err := s.Emit(context.Background(), original); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatal("no line written")
	}
	var decoded Finding
	if err := json.Unmarshal(sc.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("id = %q, want %q", decoded.ID, original.ID)
	}
	if decoded.EventType != original.EventType {
		t.Errorf("eventType = %q, want %q", decoded.EventType, original.EventType)
	}
	if decoded.Severity != original.Severity {
		t.Errorf("severity = %q, want %q", decoded.Severity, original.Severity)
	}
	if decoded.Confidence != original.Confidence {
		t.Errorf("confidence = %v, want %v", decoded.Confidence, original.Confidence)
	}
	if len(decoded.Signals) != len(original.Signals) {
		t.Errorf("signals = %d, want %d", len(decoded.Signals), len(original.Signals))
	}
	if len(decoded.MITRE) != len(original.MITRE) {
		t.Errorf("mitre = %d, want %d", len(decoded.MITRE), len(original.MITRE))
	}
	if decoded.Client.IP != original.Client.IP {
		t.Errorf("client.ip = %q, want %q", decoded.Client.IP, original.Client.IP)
	}
}
