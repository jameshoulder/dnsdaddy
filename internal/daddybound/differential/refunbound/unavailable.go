//go:build !cgo || !daddybound_unbound

// Package refunbound adapts libunbound as a differential test oracle.
//
// libunbound is a reference implementation. It is never Daddybound's backend
// and never produces a Daddybound verdict: it exists here only to disagree
// with one, so that disagreements can be investigated.
//
// The adapter is compiled only when both cgo is enabled and the
// daddybound_unbound build tag is set. Neither holds for any build this
// project ships:
//
//	make build      CGO_ENABLED=0, no tags
//	make release    CGO_ENABLED=0 across five platforms
//	Dockerfile      CGO_ENABLED=0
//	CI build job    CGO_ENABLED=0
//
// so the resolver binary cannot link against libunbound even by accident,
// and Daddybound stays pure Go. This file is the other half of that: without
// the tag the package still exists and still compiles, it simply reports
// that no oracle is available. A package that failed to build without the
// tag would break `go build ./...` for everyone.
package refunbound

import (
	"context"
	"errors"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential"
)

// Available reports whether this build includes the libunbound oracle.
func Available() bool { return false }

// Why explains the absence, for a test's skip message.
func Why() string {
	return "built without the libunbound oracle (needs CGO_ENABLED=1 and -tags daddybound_unbound)"
}

// New always fails in this build.
func New(Config) (differential.Reference, error) {
	return nil, errors.New("refunbound: " + Why())
}

// Config is the oracle's settings. Declared in both builds so that callers
// compile either way.
type Config struct {
	// Forward is the host:port of the authoritative server holding the
	// hierarchy under test.
	Forward string
	// TrustAnchor is a DS record in presentation form.
	TrustAnchor string
}

var _ = context.Background
