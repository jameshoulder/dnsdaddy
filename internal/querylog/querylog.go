// Package querylog buffers DNS query events and writes them to storage in
// batches.
//
// Nothing on the DNS hot path may wait for a disk write. Events are handed to a
// buffered channel and a single writer goroutine drains it; if the buffer is
// full the event is dropped and counted rather than blocking a resolution.
// Losing a log line under extreme load is an acceptable failure. Adding
// milliseconds to every lookup on the network is not.
package querylog

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Logger batches query events into the store.
type Logger struct {
	store   *store.Store
	ch      chan record
	log     *slog.Logger
	flush   time.Duration
	maxRows int

	dropped atomic.Uint64
	written atomic.Uint64
	rollups atomic.Uint64
	done    chan struct{}
}

type record struct {
	event   store.QueryEvent
	persist bool
}

// Options configures a Logger.
type Options struct {
	BufferSize      int
	FlushIntervalMS int
	MaxBatchRows    int
}

// New returns a Logger. Run must be called to start draining.
func New(st *store.Store, o Options, log *slog.Logger) *Logger {
	size := o.BufferSize
	if size <= 0 {
		size = 8192
	}
	flush := time.Duration(o.FlushIntervalMS) * time.Millisecond
	if flush <= 0 {
		flush = 500 * time.Millisecond
	}
	maxRows := o.MaxBatchRows
	if maxRows <= 0 {
		maxRows = 256
	}
	return &Logger{
		store:   st,
		ch:      make(chan record, size),
		log:     log,
		flush:   flush,
		maxRows: maxRows,
		done:    make(chan struct{}),
	}
}

// Record queues an event. persist=false updates the dashboard rollups without
// writing a per-query row, which is what a policy with query logging turned off
// gets: useful counts, no record of who asked for what.
//
// It never blocks.
func (l *Logger) Record(e store.QueryEvent, persist bool) {
	select {
	case l.ch <- record{event: e, persist: persist}:
	default:
		l.dropped.Add(1)
	}
}

// Run drains the buffer until ctx is cancelled, then flushes what is left.
func (l *Logger) Run(ctx context.Context) {
	defer close(l.done)

	ticker := time.NewTicker(l.flush)
	defer ticker.Stop()

	var persisted, countOnly []store.QueryEvent

	writeBatch := func() {
		if len(persisted) > 0 {
			// Use a detached context so a shutdown mid-flush still lands.
			wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			if err := l.store.InsertQueryBatch(wctx, persisted, true); err != nil {
				l.log.Error("write query log batch", "rows", len(persisted), "error", err)
			} else {
				l.written.Add(uint64(len(persisted)))
			}
			cancel()
			persisted = persisted[:0]
		}
		if len(countOnly) > 0 {
			wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			if err := l.store.InsertQueryBatch(wctx, countOnly, false); err != nil {
				l.log.Error("write query rollups", "rows", len(countOnly), "error", err)
			} else {
				l.rollups.Add(uint64(len(countOnly)))
			}
			cancel()
			countOnly = countOnly[:0]
		}
	}

	for {
		select {
		case <-ctx.Done():
			// Drain whatever is already queued before exiting.
			for {
				select {
				case r := <-l.ch:
					if r.persist {
						persisted = append(persisted, r.event)
					} else {
						countOnly = append(countOnly, r.event)
					}
					continue
				default:
				}
				break
			}
			writeBatch()
			return

		case r := <-l.ch:
			if r.persist {
				persisted = append(persisted, r.event)
			} else {
				countOnly = append(countOnly, r.event)
			}
			if len(persisted)+len(countOnly) >= l.maxRows {
				writeBatch()
			}

		case <-ticker.C:
			writeBatch()
		}
	}
}

// Wait blocks until Run has finished flushing.
func (l *Logger) Wait() { <-l.done }

// Stats reports written, rollup-only, and dropped event counts.
func (l *Logger) Stats() (written, rollups, dropped uint64) {
	return l.written.Load(), l.rollups.Load(), l.dropped.Load()
}
