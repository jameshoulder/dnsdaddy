package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// StoreSink persists findings to SQLite so the dashboard and API can read
// them back.
//
// Writes are synchronous. That is safe here in a way it would never be on the
// query path: the engine goroutine is already off the DNS hot path, and
// findings arrive at most a handful per evaluation cycle rather than once per
// lookup. Batching them would add a failure mode — findings lost in a buffer
// on shutdown — to save a transaction every thirty seconds.
type StoreSink struct {
	store   *store.Store
	timeout time.Duration
}

// NewStoreSink returns a sink writing to st.
func NewStoreSink(st *store.Store) *StoreSink {
	return &StoreSink{store: st, timeout: 10 * time.Second}
}

// Emit implements Sink.
func (s *StoreSink) Emit(ctx context.Context, f Finding) error {
	if s == nil || s.store == nil {
		return nil
	}

	// The full document is stored as JSON alongside the indexed columns, so a
	// finding written by a newer binary still round-trips through an older
	// one: unknown signals and evidence survive in detail even if no column
	// exists for them.
	detail, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal finding: %w", err)
	}

	// A detached context with its own deadline: a shutdown mid-write should
	// still land the finding rather than lose the reason the operator will
	// want tomorrow.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.timeout)
	defer cancel()

	return s.store.InsertFindings(wctx, []store.Finding{{
		ID:         f.ID,
		Time:       f.Time,
		EventType:  f.EventType,
		Severity:   string(f.Severity),
		Confidence: f.Confidence,
		Score:      f.Score,
		ClientIP:   f.Client.IP,
		ClientName: f.Client.Name,
		NetworkID:  f.Client.NetworkID,
		Domain:     f.Domain,
		QType:      f.QType,
		Detector:   f.Detector,
		Title:      f.Title,
		Summary:    f.Summary,
		Detail:     string(detail),
	}})
}
