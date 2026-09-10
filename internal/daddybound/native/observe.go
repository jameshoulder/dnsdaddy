package native

import (
	"context"
	"errors"
	"fmt"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
)

// Learn adapts an Engine to what observe mode drives.
//
// The classification of a resolution failure lives here because this is the
// only place that knows both halves: the resolver's sentinel errors are
// recursive's, and what may honestly be recorded is observe's. Putting it in
// either package would make that one import the other, and internal/daddybound/observe
// deliberately imports nothing that describes a deployment — the property
// TestDaddyboundDoesNotReachIntoTheResolver exists to keep.
//
// Every branch refuses to say anything about the zone. A resolver that reported
// Bogus when it could not reach a server would hand an attacker a way to
// condemn any zone by dropping its packets; one that reported Insecure would
// hand them a downgrade. So a failure is always operational, and the observer
// checks that again on the way past.
type Learn struct{ e *Engine }

// NewLearn wraps an Engine for observe mode.
func NewLearn(e *Engine) *Learn { return &Learn{e: e} }

// ResolveAndValidate resolves the name from the root, validates what it found,
// and reports the verdict with what the resolution cost.
//
// The answer itself is discarded. Learn mode does not return records to anyone
// — the client already has its answer from the forwarding path, decided before
// this was queued — so the message is worth nothing here and holding it would
// only invite somebody to use it. What is kept is the verdict and the cost,
// which is the evidence the mode exists to collect.
func (l *Learn) ResolveAndValidate(ctx context.Context, qname string, rrtype uint16) observe.Outcome {
	ans, err := l.e.Resolve(ctx, qname, rrtype)
	if err != nil {
		return failure(err)
	}
	return observe.Outcome{
		Result:      ans.Validation,
		Queries:     ans.Queries,
		Delegations: len(ans.Delegations),
		Lookups:     ans.Lookups,
	}
}

// failure classifies a resolution error into something recordable.
func failure(err error) observe.Outcome {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return observe.Outcome{
			Failure:     observe.StatusTimeout,
			FailureCode: "resolution_deadline",
			FailureReason: "the observation deadline expired before the authoritative servers " +
				"answered; nothing was concluded about this name",
		}
	case errors.Is(err, recursive.ErrLimit):
		return observe.Outcome{
			Failure:     observe.StatusResourceLimit,
			FailureCode: "resolution_limit",
			FailureReason: "resolution hit one of the resolver's own bounds and stopped early; " +
				"this is a statement about the resolver, not about the zone",
		}
	case errors.Is(err, recursive.ErrNoReachableServer), errors.Is(err, recursive.ErrLame):
		return observe.Outcome{
			Failure:     observe.StatusUnreachable,
			FailureCode: "no_authoritative_server",
			FailureReason: "no authoritative server for this zone could be reached, so no " +
				"records were obtained",
		}
	default:
		// An error this adapter does not recognise is still a failure to
		// obtain records, and unreachable is the honest reading of that. It
		// is not folded into indeterminate, which is a verdict, nor into
		// internal_error, which would accuse this code of a defect it may not
		// have committed.
		return observe.Outcome{
			Failure:       observe.StatusUnreachable,
			FailureCode:   "resolution_failed",
			FailureReason: fmt.Sprintf("native resolution failed: %v", err),
		}
	}
}
