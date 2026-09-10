package native

import (
	"context"
	"log/slog"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/trustanchors"
)

// RunAnchorRefresh keeps a trust point's keys up to date until ctx is
// cancelled.
//
// One refresh at startup, then on the schedule RFC 5011 §2.3 computes from the
// zone's own TTL and signature lifetimes. The manager decides when the next one
// is due — including the retry schedule after a failure — so the loop here has
// no timing policy of its own beyond the floor that stops a broken clock or a
// zero interval turning this into a hot loop.
//
// A failed refresh is not fatal and is not retried harder. The anchors already
// in force stay in force, which is the whole design: a resolver whose trust
// anchors evaporated because the network was down would be one that an outage
// turns into a non-validating resolver.
func RunAnchorRefresh(ctx context.Context, m *trustanchors.Manager, now func() time.Time, log *slog.Logger) {
	if m == nil {
		return
	}
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}

	// The first refresh is what seeds a fresh install: it fetches the zone's
	// DNSKEY RRset and matches it against the digests this build ships, which
	// is how a compiled-in DS becomes a usable key. Until it succeeds the
	// configured anchors are in force, so validation works from the first
	// query either way.
	res := m.Refresh(ctx)
	logRefresh(log, res)

	// A floor under the wait. The manager's schedule is derived from data a
	// zone publishes, and RFC 5011 §2.3's own floor is an hour; this is a
	// second, cruder guard against a next-refresh time that has already passed
	// — from a clock step, say — becoming a loop with no sleep in it.
	const floor = time.Minute

	timer := time.NewTimer(floor)
	defer timer.Stop()
	for {
		wait := res.NextRefresh.Sub(now())
		if wait < floor {
			wait = floor
		}
		timer.Reset(wait)

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		res = m.Refresh(ctx)
		logRefresh(log, res)
	}
}

func logRefresh(log *slog.Logger, res trustanchors.RefreshResult) {
	if !res.OK {
		// Already logged in detail by the manager, which knows why. This is
		// the one-line operational record.
		return
	}
	if len(res.Changes) == 0 {
		log.Debug("DNSSEC trust anchors refreshed; nothing changed",
			"nextRefresh", res.NextRefresh)
		return
	}
	log.Info("DNSSEC trust anchors refreshed",
		"changes", len(res.Changes), "nextRefresh", res.NextRefresh)
}
