package api

import (
	"context"
	"testing"
	"time"
)

type refreshKey struct{}

// A feed refresh outlives the request that asked for it — the browser gets 202
// and disconnects long before the downloads finish. If the background context
// inherited the request's cancellation, every manual refresh would be killed
// the moment the response was written, and the dashboard would report a
// refresh that silently did nothing.
func TestDetachedContextIgnoresTheRequestBeingCancelled(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	cancelParent()

	ctx, cancel := detachedContext(parent)
	defer cancel()

	select {
	case <-ctx.Done():
		t.Fatal("detached context is already cancelled; it inherited the request's cancellation")
	default:
	}
}

// Detaching from cancellation must not also detach from the values a request
// carries, or anything hung off the context — a request id, a trace — is lost
// from the logs the moment work moves to the background.
func TestDetachedContextKeepsRequestValues(t *testing.T) {
	parent := context.WithValue(context.Background(), refreshKey{}, "req-1")

	ctx, cancel := detachedContext(parent)
	defer cancel()

	if got := ctx.Value(refreshKey{}); got != "req-1" {
		t.Errorf("value = %v, want req-1", got)
	}
}

// Unbounded background work is how a hung upstream turns into a goroutine that
// never returns and a refresh slot that never frees.
func TestDetachedContextIsBounded(t *testing.T) {
	ctx, cancel := detachedContext(context.Background())
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("detached context has no deadline")
	}
	if d := time.Until(deadline); d <= 0 || d > detachedWork {
		t.Errorf("deadline is %v away, want a positive value no larger than %v", d, detachedWork)
	}
}

// The caller is expected to cancel when the work finishes rather than leaving
// the timer to expire, so cancel has to actually do something.
func TestDetachedContextCancelReleasesTheContext(t *testing.T) {
	ctx, cancel := detachedContext(context.Background())
	cancel()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("cancel did not release the detached context")
	}
	if err := ctx.Err(); err != context.Canceled {
		t.Errorf("Err = %v, want %v", err, context.Canceled)
	}
}
