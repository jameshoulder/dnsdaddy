package learning

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
)

func TestCheckpointRestoresFittedStateAndReportsPartialWindows(t *testing.T) {
	m, at := trainedModel(t)
	o := testOptions()
	o.StatePath = filepath.Join(t.TempDir(), "daddybound-learning.json")
	e, err := New(o, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.model = m
	m.Observe(benignWindow(at, "192.0.2.10", 1)[0])
	before, _ := e.Inspect("192.0.2.10")
	if err = e.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(o.StatePath)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions %o", info.Mode().Perm())
	}
	data, _ := os.ReadFile(o.StatePath)
	if strings.Contains(string(data), "service.example") || strings.Contains(string(data), "ClientName") {
		t.Fatal("checkpoint retained raw DNS names or client names")
	}
	restored, err := New(o, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := restored.Inspect("192.0.2.10")
	if !after.Ready || after.BaselineWindows != before.BaselineWindows || *after.Features[0].BaselineMean != *before.Features[0].BaselineMean || after.PendingQueries != 0 {
		t.Fatalf("restart changed fitted baseline: %+v", after)
	}
	status := restored.Status()
	if !status.Persistence.Loaded || status.Windows.RestartDiscarded != 1 || status.Observations.Processed != 0 {
		t.Fatalf("restart scope: %+v", status)
	}
}

func TestCorruptIncompatibleOrUnsafeStateIsNotSilentlyAccepted(t *testing.T) {
	o := testOptions()
	dir := t.TempDir()
	o.StatePath = filepath.Join(dir, "state.json")
	e, _ := New(o, nil, nil)
	if err := e.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	valid, _ := os.ReadFile(o.StatePath)
	cases := map[string][]byte{"truncated": []byte(`{"schemaVersion":`), "trailing": append(append([]byte{}, valid...), []byte(`{}`)...), "wrong_version": []byte(strings.Replace(string(valid), `"schemaVersion":1`, `"schemaVersion":99`, 1))}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(o.StatePath, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := New(o, nil, nil); err == nil {
				t.Fatal("accepted invalid state")
			}
		})
	}
	if err := os.WriteFile(o.StatePath, valid, 0600); err != nil {
		t.Fatal(err)
	}
	changed := o
	changed.Window = 2 * time.Minute
	if _, err := New(changed, nil, nil); err == nil {
		t.Fatal("accepted different feature-window semantics")
	}
	if err := os.Chmod(o.StatePath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(o, nil, nil); err == nil {
		t.Fatal("accepted broadly readable profile state")
	}
	if err := os.Remove(o.StatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "target"), valid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "target"), o.StatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := New(o, nil, nil); err == nil {
		t.Fatal("followed symlink state")
	}
}

func TestCheckpointFailureIsVisibleAndDoesNotDestroyModel(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(parent, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	e, _ := New(testOptions(), nil, nil)
	e.opts.StatePath = filepath.Join(parent, "state.json")
	if err := e.Checkpoint(); err == nil {
		t.Fatal("expected save failure")
	}
	s := e.Status()
	if s.Persistence.SaveErrors != 1 || s.Persistence.LastError == "" || strings.Contains(s.Persistence.LastError, dir) {
		t.Fatalf("unsafe or absent error reporting: %+v", s.Persistence)
	}
}

func TestFrozenEvaluationDoesNotTrainOnHeldOutData(t *testing.T) {
	m, at := trainedModel(t)
	before := m.clients["192.0.2.10"].Baseline
	counts := m.observations
	for range 3 {
		r, err := m.EvaluateWindow(unusualWindow(at, "192.0.2.10", 40))
		if err != nil {
			t.Fatal(err)
		}
		if r.State != "anomaly" {
			t.Fatalf("missing heldout anomaly: %+v", r)
		}
	}
	if m.clients["192.0.2.10"].Baseline != before || m.observations != counts {
		t.Fatal("test data altered training state or runtime counters")
	}
	if _, err := m.EvaluateWindow(benignWindow(at.Add(-2*time.Minute), "192.0.2.10", 40)); err == nil {
		t.Fatal("accepted training/test time overlap")
	}
}

func TestQueueIsBoundedLossAccountedAndCancellationDrains(t *testing.T) {
	o := testOptions()
	o.BufferSize = 1
	e, err := New(o, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	o1 := benignWindow(time.Now().UTC().Truncate(time.Minute), "192.0.2.10", 1)[0]
	if !e.Observe(o1) || e.Observe(o1) {
		t.Fatal("queue did not reject its overflow immediately")
	}
	e.SkipPrivacy()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	go e.Run(ctx)
	select {
	case <-e.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("engine did not stop")
	}
	if e.Observe(o1) {
		t.Fatal("accepted input after stopping")
	}
	s := e.Status()
	if s.Observations.Received != 3 || s.Observations.Processed != 1 || s.Observations.Dropped != 2 || s.Observations.PrivacySkipped != 1 || s.Queue.Depth != 0 || s.Running {
		t.Fatalf("queue accounting: %+v", s)
	}
}

func TestConcurrentIngestionStatusAndCheckpointRemainRaceFree(t *testing.T) {
	o := testOptions()
	o.StatePath = filepath.Join(t.TempDir(), "state.json")
	o.BufferSize = 64
	e, err := New(o, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	var wg sync.WaitGroup
	at := time.Now().UTC()
	for worker := range 8 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := range 200 {
				e.Observe(detect.Observation{Time: at, ClientIP: "192.0.2.10", QName: "mail.example", QType: "A", Rcode: "NOERROR"})
				if worker%2 == 0 {
					_ = e.Status()
					_, _ = e.Inspect("192.0.2.10")
				}
				if i%100 == 0 {
					if err := e.Checkpoint(); err != nil {
						t.Error(err)
					}
				}
			}
		}(worker)
	}
	wg.Wait()
	cancel()
	select {
	case <-e.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("engine did not stop")
	}
	s := e.Status()
	if s.Observations.Received != 1600 || s.Observations.Processed+s.Observations.Dropped != 1600 {
		t.Fatalf("lost accounting: %+v", s.Observations)
	}
	data, _ := os.ReadFile(o.StatePath)
	var saved savedState
	if err = json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("partial checkpoint: %v", err)
	}
}

func TestCancellationCannotAcceptAnObservationAfterFinalDrain(t *testing.T) {
	e, err := New(Options{BufferSize: 64}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	var wg sync.WaitGroup
	o := detect.Observation{Time: time.Now().UTC(), ClientIP: "192.0.2.1", QName: "mail.example", QType: "A", Rcode: "NOERROR"}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 3000 {
				e.Observe(o)
			}
		}()
	}
	cancel()
	wg.Wait()
	select {
	case <-e.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown was blocked by concurrent senders")
	}
	s := e.Status()
	if s.Queue.Depth != 0 || s.Observations.Received != 24000 || s.Observations.Processed+s.Observations.Dropped != 24000 {
		t.Fatalf("accepted sample was lost across cancellation: %+v", s)
	}
}
