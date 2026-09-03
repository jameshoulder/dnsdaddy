package api

import (
	"context"
	"time"
)

func timeNowMinus24h() time.Time { return time.Now().Add(-24 * time.Hour) }

// timeNow is the clock the evidence read path uses, named so that assessment
// expiry has one place to come from rather than scattered time.Now calls.
func timeNow() time.Time { return time.Now() }

// detachedWork bounds background work started by a request. Refreshing every
// feed is the long pole and finishes in minutes; the ceiling exists so a hung
// upstream cannot pin a goroutine and a refresh slot forever.
const detachedWork = 30 * time.Minute

// detachedContext returns a context for background work kicked off by a
// request. It keeps whatever values the request context carries but drops its
// cancellation, so the work survives the client disconnecting and the handler
// returning, and it bounds that work with a deadline of its own.
//
// The caller must call cancel when the work actually finishes. Letting the
// deadline do it instead leaks the timer and the context until it fires, which
// on a dashboard that refreshes feeds repeatedly is a slow accumulation rather
// than a one-off.
func detachedContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), detachedWork)
}
