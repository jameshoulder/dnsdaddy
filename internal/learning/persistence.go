package learning

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxStateBytes = 8 << 20

type savedState struct {
	SchemaVersion  int            `json:"schemaVersion"`
	Algorithm      string         `json:"algorithm"`
	FeatureVersion int            `json:"featureVersion"`
	Fingerprint    string         `json:"fingerprint"`
	SavedAt        time.Time      `json:"savedAt"`
	PendingWindows int            `json:"pendingWindows"`
	Clients        []*clientState `json:"clients"`
}

func (e *Engine) fingerprint() string {
	// Queue capacity and checkpoint frequency do not change model semantics.
	// Training rules and feature layout do: changing those needs an explicit
	// migration/reset instead of silently reinterpreting old parameters.
	s := fmt.Sprintf("%s/%d/%d/%d/%d/%d/%d/%.17g/%.17g", Algorithm, FeatureVersion, e.opts.Window, e.opts.MinWindowQueries, e.opts.WarmupWindows, e.opts.WarmupDuration, e.opts.MaxUniqueDomains, e.opts.Alpha, e.opts.Threshold)
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (e *Engine) load() error {
	if e.opts.StatePath == "" {
		return nil
	}
	info, err := os.Lstat(e.opts.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read local learning state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("local learning state must be a regular file, not a link")
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("local learning state permissions must be 0600; restrict access before restarting")
	}
	if info.Size() > maxStateBytes {
		return fmt.Errorf("local learning state exceeds 8 MiB; restore a valid backup")
	}
	f, err := os.Open(e.opts.StatePath)
	if err != nil {
		return fmt.Errorf("open local learning state: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return fmt.Errorf("read local learning state: %w", err)
	}
	if len(data) > maxStateBytes {
		return fmt.Errorf("local learning state exceeds 8 MiB")
	}
	var saved savedState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&saved); err != nil {
		return fmt.Errorf("invalid local learning state; restore a valid backup: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("local learning state has trailing data")
	}
	if saved.SchemaVersion != ModelVersion || saved.FeatureVersion != FeatureVersion || saved.Algorithm != Algorithm || saved.Fingerprint != e.fingerprint() {
		return fmt.Errorf("incompatible local learning model; restore matching configuration or explicitly archive the state to start a new baseline")
	}
	if len(saved.Clients) > e.opts.MaxClients || saved.PendingWindows < 0 || saved.PendingWindows > e.opts.MaxClients || saved.SavedAt.IsZero() {
		return fmt.Errorf("local learning state exceeds configured client bounds or has invalid metadata")
	}
	for _, c := range saved.Clients {
		if c == nil || c.Client == "" || len(c.Client) > 136 || len(c.NetworkID) > 128 || c.LastSeen.IsZero() || strings.ContainsAny(c.Client, "\r\n\x00") || c.Baseline.Windows > 1<<40 || c.Baseline.Queries > 1<<53 {
			return fmt.Errorf("local learning state has invalid client metadata")
		}
		if c.Client != "unattributed" && !strings.HasPrefix(c.Client, "network:") {
			if ip, err := netip.ParseAddr(c.Client); err != nil || ip.Unmap().String() != c.Client {
				return fmt.Errorf("local learning state has a non-canonical client address")
			}
		} else if strings.HasPrefix(c.Client, "network:") && c.Client != "network:"+c.NetworkID {
			return fmt.Errorf("local learning state has inconsistent aggregate attribution")
		}
		if _, exists := e.model.clients[c.Client]; exists {
			return fmt.Errorf("local learning state has duplicate clients")
		}
		b := &c.Baseline
		if (b.Windows > 0 && (b.FirstAt.IsZero() || !b.LastAt.After(b.FirstAt) || b.LastAt.After(c.LastClosed))) || (b.Windows == 0 && b.Queries != 0) || b.Queries < b.Windows*uint64(e.opts.MinWindowQueries) || b.Queries > b.Windows*uint64(e.opts.MaxWindowQueries) {
			return fmt.Errorf("local learning state has invalid sample counts or chronology")
		}
		upper := [FeatureCount]float64{math.Log1p(float64(e.opts.MaxWindowQueries) / e.opts.Window.Minutes()), 63, 6, 1, 1, 127}
		for i := range FeatureCount {
			if math.IsNaN(b.Mean[i]) || math.IsInf(b.Mean[i], 0) || math.IsNaN(b.Variance[i]) || math.IsInf(b.Variance[i], 0) || math.IsNaN(b.M2[i]) || math.IsInf(b.M2[i], 0) || b.Mean[i] < 0 || b.Variance[i] < 0 || b.M2[i] < 0 || b.Mean[i] > upper[i] || b.Variance[i] > upper[i]*upper[i] || b.M2[i] > 1e18 {
				return fmt.Errorf("local learning state has invalid fitted parameters")
			}
		}
		e.model.clients[c.Client] = c
	}
	e.persistence.Loaded = true
	e.persistence.LastSavedAt = saved.SavedAt
	e.model.windows.RestartDiscarded = uint64(saved.PendingWindows)
	return nil
}

// Checkpoint flushes completed baselines only. It is safe for the backup API
// to call; no atomic transaction with SQLite is implied. Active window data
// is deliberately omitted and its count is reported after a restart.
func (e *Engine) Checkpoint() error {
	if e == nil || e.opts.StatePath == "" {
		return nil
	}
	e.checkpointMu.Lock()
	defer e.checkpointMu.Unlock()
	e.mu.RLock()
	saved := savedState{SchemaVersion: ModelVersion, Algorithm: Algorithm, FeatureVersion: FeatureVersion, Fingerprint: e.fingerprint(), SavedAt: time.Now().UTC(), Clients: make([]*clientState, 0, len(e.model.clients))}
	for _, c := range e.model.clients {
		copyClient := *c
		copyClient.window = nil
		saved.Clients = append(saved.Clients, &copyClient)
		if c.window != nil {
			saved.PendingWindows++
		}
	}
	e.mu.RUnlock()
	data, err := json.Marshal(saved)
	if err == nil && len(data) > maxStateBytes {
		err = fmt.Errorf("local learning checkpoint exceeds 8 MiB")
	}
	if err == nil {
		err = atomicWrite(e.opts.StatePath, data)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		e.persistence.SaveErrors++
		e.persistence.LastError = "model checkpoint failed; inspect local logs"
		return err
	}
	e.persistence.LastSavedAt = saved.SavedAt
	e.persistence.LastError = ""
	return nil
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace non-regular learning state")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(dir, ".learning-checkpoint-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	// Sync the directory entry as well as the file contents. A successful
	// rename alone does not guarantee persistence across a power failure.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
