package observe_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
)

func waitSignal(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

// One active request finishes as a cancelled observation. Accepted queued
// requests, full-queue attempts, and captured calls after stop are distinct
// ways work can be lost; none may disappear from Observed + Dropped.
func TestShutdownCountsQueuedFullAndCapturedLateObservations(t *testing.T) {
	started := make(chan struct{}, 1)
	var calls atomic.Uint64
	v := validatorFunc(func(ctx context.Context, _ string, _ uint16) dnssec.ValidationResult {
		calls.Add(1)
		started <- struct{}{}
		<-ctx.Done()
		return dnssec.ValidationResult{Status: dnssec.StatusIndeterminate, Reason: dnssec.ReasonCancelled}
	})
	sink := &collector{}
	o := observe.New(v, sink, observe.Options{Workers: 1, Queue: 3, Timeout: time.Second, Log: quietLog()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go func() { o.Run(ctx); close(stopped) }()
	captured := o.Observe
	r := request("shutdown.test.")
	if !captured(r) {
		t.Fatal("initial observation was rejected")
	}
	waitSignal(t, started, "active validation")
	for i := 0; i < 3; i++ {
		if !captured(r) {
			t.Fatalf("queue request %d was rejected", i)
		}
	}
	for i := 0; i < 2; i++ {
		if captured(r) {
			t.Fatal("a full queue accepted another request")
		}
	}
	if got := o.Stats().Dropped; got != 2 {
		t.Fatalf("full queue losses = %d, want 2", got)
	}
	cancel()
	if captured(r) {
		t.Fatal("a cancelled observer still accepted work")
	}
	waitSignal(t, stopped, "observer shutdown")
	o.Wait()
	for i := 0; i < 4; i++ {
		if captured(r) {
			t.Fatal("a captured observer accepted work after Wait")
		}
	}
	s := o.Stats()
	if s.Observed != 1 || s.Dropped != 10 || s.Observed+s.Dropped != 11 {
		t.Fatalf("lost or double-counted shutdown work: observed=%d dropped=%d, want 1/10", s.Observed, s.Dropped)
	}
	if calls.Load() != 1 || len(sink.all()) != 1 || s.ByStatus[observe.StatusTimeout] != 1 {
		t.Fatalf("queued work became artificial observations: calls=%d rows=%d statuses=%v", calls.Load(), len(sink.all()), s.ByStatus)
	}
}

// Concurrent callers can retain Observe while the mode controller retires
// this instance. After everyone returns, every attempted request must be
// either a completed observation or a counted loss, including accepted work
// that never reached a worker. Run under -race to cover the admission gate.
func TestConcurrentObserveAndShutdownAccountEveryAttempt(t *testing.T) {
	const workers, queue, producers, perProducer = 3, 32, 16, 128
	started := make(chan struct{}, workers)
	v := validatorFunc(func(ctx context.Context, _ string, _ uint16) dnssec.ValidationResult {
		started <- struct{}{}
		<-ctx.Done()
		return dnssec.ValidationResult{Status: dnssec.StatusIndeterminate, Reason: dnssec.ReasonCancelled}
	})
	o := observe.New(v, nil, observe.Options{Workers: workers, Queue: queue, Timeout: time.Second, Log: quietLog()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go func() { o.Run(ctx); close(stopped) }()
	captured := o.Observe
	r := request("shutdown-race.test.")
	for i := 0; i < workers; i++ {
		if !captured(r) {
			t.Fatal("initial worker request was rejected")
		}
		waitSignal(t, started, "active worker")
	}
	for i := 0; i < queue; i++ {
		if !captured(r) {
			t.Fatal("queue filled before its configured limit")
		}
	}
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			for j := 0; j < perProducer; j++ {
				captured(r)
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); <-gate; cancel() }()
	close(gate)
	wg.Wait()
	waitSignal(t, stopped, "racing observer shutdown")
	s := o.Stats()
	wantAttempts := uint64(workers + queue + producers*perProducer)
	if s.Observed != workers || s.Observed+s.Dropped != wantAttempts {
		t.Fatalf("attempts=%d observed=%d dropped=%d; accepted work vanished during stop", wantAttempts, s.Observed, s.Dropped)
	}
	if captured(r) {
		t.Fatal("stopped observer reopened admission")
	}
	if got := o.Stats().Dropped; got != s.Dropped+1 {
		t.Fatalf("late rejection not counted: %d -> %d", s.Dropped, got)
	}
}

func TestCancelledRunAccountsForPrequeuedRequestsWithoutValidation(t *testing.T) {
	var calls atomic.Uint64
	v := validatorFunc(func(context.Context, string, uint16) dnssec.ValidationResult {
		calls.Add(1)
		return dnssec.ValidationResult{Status: dnssec.StatusSecure, Reason: dnssec.ReasonVerified}
	})
	o := observe.New(v, nil, observe.Options{Workers: 1, Queue: 2, Log: quietLog()})
	r := request("prequeued.test.")
	if !o.Observe(r) || !o.Observe(r) {
		t.Fatal("bounded pre-Run queue rejected work")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o.Run(ctx)
	o.Wait()
	if s := o.Stats(); s.Observed != 0 || s.Dropped != 2 || calls.Load() != 0 {
		t.Fatalf("cancelled startup lost work or started validation: stats=%+v calls=%d", s, calls.Load())
	}
}
