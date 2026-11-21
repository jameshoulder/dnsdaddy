// Package firstseen maintains a retention-independent index of when each
// registered domain was first (and last) observed by this resolver.
//
// The query log answers "what happened in the retention window". This index
// answers "have we ever seen this registered domain before", which is the
// foundation for rarity hunts and first-contact investigation. One row per
// eTLD+1; no client addresses; no answer payloads.
//
// Writes are off the DNS path: a bounded queue drops rather than blocking.
package firstseen

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Event is one observed question, captured at answer time.
type Event struct {
	Time   time.Time
	Domain string
}

// Recorder queues observations and upserts the durable index.
type Recorder struct {
	store *store.Store
	log   *slog.Logger
	ch    chan Event
	done  chan struct{}
	gate  sync.RWMutex

	stopped atomic.Bool
	queued  atomic.Uint64
	dropped atomic.Uint64
	written atomic.Uint64
	failed  atomic.Uint64
	skipped atomic.Uint64
}

// Options configures a Recorder.
type Options struct {
	QueueSize int
	Log       *slog.Logger
}

// New returns a Recorder. Run must be called to drain the queue.
func New(st *store.Store, o Options) *Recorder {
	size := o.QueueSize
	if size <= 0 {
		size = 4096
	}
	lg := o.Log
	if lg == nil {
		lg = slog.Default()
	}
	return &Recorder{store: st, log: lg, ch: make(chan Event, size), done: make(chan struct{})}
}

// Record offers an observation. Non-blocking; full queues drop and count.
func (r *Recorder) Record(e Event) {
	if r == nil || e.Domain == "" {
		return
	}
	if !r.gate.TryRLock() {
		r.dropped.Add(1)
		return
	}
	defer r.gate.RUnlock()
	if r.stopped.Load() {
		r.dropped.Add(1)
		return
	}
	select {
	case r.ch <- e:
		r.queued.Add(1)
	default:
		r.dropped.Add(1)
	}
}

// Run drains the queue until ctx is cancelled, then drains remaining items.
func (r *Recorder) Run(ctx context.Context) {
	defer close(r.done)
	for {
		select {
		case <-ctx.Done():
			r.shutdown()
			return
		case e := <-r.ch:
			r.write(ctx, e)
		}
	}
}

func (r *Recorder) shutdown() {
	r.gate.Lock()
	r.stopped.Store(true)
	r.gate.Unlock()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case e := <-r.ch:
			r.write(context.Background(), e)
		case <-deadline:
			return
		default:
			return
		}
	}
}

// Wait blocks until Run has returned.
func (r *Recorder) Wait() {
	if r == nil {
		return
	}
	<-r.done
}

func (r *Recorder) write(ctx context.Context, e Event) {
	parent, ok := detect.RegisteredDomain(e.Domain)
	if !ok {
		r.skipped.Add(1)
		return
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := r.store.ObserveRegisteredDomain(wctx, parent, e.Time); err != nil {
		r.failed.Add(1)
		r.log.Warn("could not record registered-domain first-seen", "domain", parent, "error", err.Error())
		return
	}
	r.written.Add(1)
}

// Stats returns queue counters for diagnostics.
func (r *Recorder) Stats() (queued, dropped, written, failed, skipped uint64) {
	if r == nil {
		return 0, 0, 0, 0, 0
	}
	return r.queued.Load(), r.dropped.Load(), r.written.Load(), r.failed.Load(), r.skipped.Load()
}
