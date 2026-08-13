package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// Sinks deliver findings somewhere useful.
//
// The design goal is that DNS Daddy should be easy to consume from something
// else, not that it should grow an integration for every SIEM on the market.
// A newline-delimited JSON file and a documented schema are what every log
// shipper in existence already knows how to read — Wazuh, Filebeat, Fluent
// Bit, Vector, Splunk's universal forwarder, and rsyslog's imfile can all tail
// one with a few lines of configuration. Building six bespoke API clients
// instead would mean six things to keep working against vendors' release
// schedules, for no capability the file does not already provide.
//
// See docs/siem.md for the shipper configurations.

// MultiSink fans a finding out to several sinks.
//
// Every sink is attempted even if an earlier one fails: a full disk on the
// NDJSON file must not stop findings reaching the database.
type MultiSink []Sink

// Emit implements Sink.
func (m MultiSink) Emit(ctx context.Context, f Finding) error {
	var firstErr error
	for _, s := range m {
		if s == nil {
			continue
		}
		if err := s.Emit(ctx, f); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// LogSink writes findings to the application log.
type LogSink struct {
	Log *slog.Logger
}

// Emit implements Sink.
func (l LogSink) Emit(_ context.Context, f Finding) error {
	if l.Log == nil {
		return nil
	}
	// Logged at warn rather than info: a finding is by definition something an
	// operator asked to be told about, and info is where the routine startup
	// chatter lives.
	l.Log.Warn("security finding",
		"event_type", f.EventType,
		"severity", string(f.Severity),
		"confidence", f.Confidence,
		"client", f.Client.IP,
		"domain", f.Domain,
		"summary", f.Summary,
		"finding_id", f.ID)
	return nil
}

// FileSink appends findings to a newline-delimited JSON file.
type FileSink struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	size     int64
}

// FileSinkOptions configures a FileSink.
type FileSinkOptions struct {
	// Path is the NDJSON file. Its directory must already exist.
	Path string
	// MaxBytes triggers rotation. Zero means 32 MiB.
	MaxBytes int64
	// Keep is how many rotated files to retain. Zero means 3.
	Keep int
}

// findingsFileMode is the permission the NDJSON findings file is created with.
//
// 0640, not 0600, and the difference is load-bearing rather than lax.
//
// Findings contain client IPs and the names those clients looked up — this is
// browsing history and is treated as such. But the file exists to be read by a
// log shipper, which conventionally runs as its own user. The standard Unix
// answer to "one process writes, another reads" is a group, and it is exactly
// how /var/log works.
//
// In the shipped deployment this is equivalent to 0600: the process runs as a
// dedicated service account whose primary group contains only itself, so
// nothing else can read the file until an operator deliberately adds the
// shipper's user to that group. That deliberate act is the documented
// mechanism (docs/siem.md), and it is a decision an operator makes once.
//
// 0600 would force the alternative — chmod the file after creation — and that
// breaks silently on the first rotation, because rotation creates a new file
// with the mode below. A shipper that stops collecting security findings
// without saying so is a worse outcome than a group-readable file on a host
// where the only member of that group is the writer.
const findingsFileMode = 0o640

// NewFileSink opens the findings file, creating it if necessary.
//
// See findingsFileMode for why the file is group-readable, and docs/privacy.md
// for what is in it.
func NewFileSink(o FileSinkOptions) (*FileSink, error) {
	if o.Path == "" {
		return nil, fmt.Errorf("findings file path is empty")
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 32 << 20
	}
	if o.Keep <= 0 {
		o.Keep = 3
	}
	if err := os.MkdirAll(filepath.Dir(o.Path), 0o750); err != nil {
		return nil, fmt.Errorf("create findings directory: %w", err)
	}
	// #nosec G304,G302 -- G304: the path comes from the operator's configured
	// data directory, never from a request. G302: 0640 is deliberate and the
	// reasoning is on findingsFileMode; it is equivalent to 0600 until an
	// operator adds a shipper to the service account's group on purpose.
	f, err := os.OpenFile(o.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, findingsFileMode)
	if err != nil {
		return nil, fmt.Errorf("open findings file: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat findings file: %w", err)
	}
	return &FileSink{path: o.Path, maxBytes: o.MaxBytes, keep: o.Keep, f: f, size: info.Size()}, nil
}

// Emit implements Sink.
func (s *FileSink) Emit(_ context.Context, f Finding) error {
	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal finding: %w", err)
	}
	b = append(b, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.f == nil {
		return fmt.Errorf("findings file is closed")
	}
	if s.size+int64(len(b)) > s.maxBytes {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	n, err := s.f.Write(b)
	s.size += int64(n)
	if err != nil {
		return fmt.Errorf("write finding: %w", err)
	}
	return nil
}

// rotate renames the current file out of the way and starts a new one. The
// caller holds the lock.
func (s *FileSink) rotate() error {
	if err := s.f.Close(); err != nil {
		return fmt.Errorf("close findings file for rotation: %w", err)
	}
	// Shuffle .2 -> .3, .1 -> .2, current -> .1. Errors on the older files are
	// not fatal: losing a historical rotation is better than stopping the
	// current one.
	oldest := fmt.Sprintf("%s.%d", s.path, s.keep)
	_ = os.Remove(oldest)
	for i := s.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", s.path, i), fmt.Sprintf("%s.%d", s.path, i+1))
	}
	if err := os.Rename(s.path, s.path+".1"); err != nil {
		return fmt.Errorf("rotate findings file: %w", err)
	}

	// #nosec G304,G302 -- operator-configured path and deliberate mode, as
	// above. Rotation must recreate the file with the same permissions, or a
	// shipper reading it would stop at the first rotation.
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, findingsFileMode)
	if err != nil {
		return fmt.Errorf("reopen findings file: %w", err)
	}
	s.f = f
	s.size = 0
	return nil
}

// Close flushes and closes the file.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// Path reports where findings are being written.
func (s *FileSink) Path() string { return s.path }
