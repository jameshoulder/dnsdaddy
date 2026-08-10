package api

import (
	"context"
	"time"
)

func timeNowMinus24h() time.Time { return time.Now().Add(-24 * time.Hour) }

// detachedContext returns a context for background work kicked off by a
// request, so the work is not cancelled when the client disconnects.
func detachedContext() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	// The cancel is intentionally deferred to the timeout: callers are
	// long-running background jobs whose lifetime is the timeout itself.
	_ = cancel
	return ctx
}
