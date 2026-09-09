// Package dnssecobs persists Daddybound's local validation observations.
//
// It is the seam between internal/daddybound/observe, which must not know
// about storage, and internal/store, which must not know about validation.
// Both halves stay ignorant of each other and this package carries rows
// between them.
package dnssecobs

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Options configures a Writer.
type Options struct {
	// QueueSize bounds how many observations may wait to be written.
	QueueSize int
	// BatchSize is how many rows one transaction writes.
	BatchSize int
	// FlushInterval bounds how long a partial batch waits.
	FlushInterval time.Duration
	Log           *slog.Logger
}

// Writer buffers observations and writes them in batches.
//
// Separate from the observer's worker pool so that a slow disk stalls writing
// rather than validation, and separate from the query log so that neither
// feature's backlog can starve the other.
type Writer struct {
	store *store.Store
	log   *slog.Logger
	opts  Options

	ch   chan store.DNSSECObservation
	done chan struct{}

	written atomic.Uint64
	dropped atomic.Uint64
	errors  atomic.Uint64
}

// New builds a Writer. It does nothing until Run is called.
func New(st *store.Store, o Options) *Writer {
	if o.QueueSize <= 0 {
		// Sized for the observed failure rather than guessed. The query log
		// writes to the same SQLite database and SQLite serialises writers,
		// so this queue's job is to absorb a batch of observations while the
		// query log holds the write lock. 1024 was not enough under a load
		// test at 5,000 queries per second; this is, with the drop counter
		// above as the check on whether it stays enough.
		o.QueueSize = 8192
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 64
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = time.Second
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Writer{
		store: st, log: o.Log, opts: o,
		ch:   make(chan store.DNSSECObservation, o.QueueSize),
		done: make(chan struct{}),
	}
}

// Record accepts one observation. Never blocks.
//
// Called from an observer worker, whose other job is validating. A sink that
// waited on a database would convert a slow disk into a stalled observation
// queue, and from there into a growing backlog on the answer path's
// non-blocking send — which is exactly the coupling this whole design avoids.
func (w *Writer) Record(o observe.Observation) {
	row := store.DNSSECObservation{
		ID:           o.ID,
		Time:         o.Time,
		Domain:       o.Domain,
		QType:        o.QType,
		Cached:       o.Cached,
		Upstream:     o.UpstreamStatus,
		Status:       string(o.Status),
		ReasonCode:   o.ReasonCode,
		Reason:       o.Reason,
		DurationMS:   float64(o.Duration.Microseconds()) / 1000,
		Disagreement: observe.DisagreementClass(o.UpstreamStatus, o.Status),
	}
	select {
	case w.ch <- row:
	default:
		w.dropped.Add(1)
	}
}

// Run writes batches until ctx is cancelled, then drains what is queued.
func (w *Writer) Run(ctx context.Context) {
	defer close(w.done)

	ticker := time.NewTicker(w.opts.FlushInterval)
	defer ticker.Stop()

	batch := make([]store.DNSSECObservation, 0, w.opts.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// A fresh context: on shutdown the run context is already cancelled,
		// and passing it here would discard the observations being drained.
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if err := w.store.InsertDNSSECObservations(wctx, batch); err != nil {
			w.errors.Add(1)
			w.log.Warn("writing DNSSEC observations failed", "error", err, "rows", len(batch))
		} else {
			w.written.Add(uint64(len(batch)))
		}
		cancel()
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// Drain whatever is already queued rather than discarding it.
			for {
				select {
				case row := <-w.ch:
					batch = append(batch, row)
					if len(batch) >= w.opts.BatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case row := <-w.ch:
			batch = append(batch, row)
			if len(batch) >= w.opts.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Wait blocks until Run has returned.
func (w *Writer) Wait() { <-w.done }

// Stats reports what the writer has done.
//
// Dropped is the one that matters and the reason this is exposed rather than
// kept internal. Observations are the entire output of observe mode, and this
// counter is the only place a lost one is visible.
//
// It is not hypothetical. A live run recorded 1337 completed validations and
// stored 1088 of them: the query log was writing twenty thousand rows to the
// same SQLite database, SQLite serialises writers, and this queue filled while
// waiting behind it. Nothing said so, because nothing read this counter. An
// operator would have seen a smaller dataset than their traffic and had no way
// to tell that from a quieter network.
func (w *Writer) Stats() Stats {
	return Stats{
		Written: w.written.Load(),
		Dropped: w.dropped.Load(),
		Errors:  w.errors.Load(),
	}
}

// Stats is what the writer has done with the observations handed to it.
type Stats struct {
	// Written is how many rows reached the database.
	Written uint64
	// Dropped is how many completed observations were discarded because the
	// write queue was full. Evidence that was collected and then lost.
	Dropped uint64
	// Errors is how many batches failed to write.
	Errors uint64
}
