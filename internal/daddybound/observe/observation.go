// Package observe runs Daddybound against real DNS Daddy traffic without
// letting it affect the answer.
//
// The whole package exists to make one property structural rather than
// careful: a verdict reached here cannot change what a client is told. It is
// reached after the response is decided, on a worker that the answer path
// never waits for, and the result is written to storage rather than back into
// a message. See docs/decisions/0002-daddybound-observe-mode.md.
//
// This package deliberately does not import internal/resolver,
// internal/store, internal/config or anything else that describes a
// deployment. It declares the narrow interfaces it needs — Exchanger for the
// network, Sink for the results — and the wiring in cmd/dnsdaddy supplies
// them. That keeps TestDaddyboundDoesNotReachIntoTheResolver true: a verdict
// still cannot depend on deployment state.
package observe

import (
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// Status is what one observation concluded.
//
// Four of these are RFC 4033's security states. The rest are operational: they
// say the validator could not reach a verdict, which is a different kind of
// statement and must never be read as one.
//
// The distinction is the whole reason this is not simply dnssec.ValidationStatus.
// An attacker who can cause a timeout can cause `timeout`; if that were
// recorded as `insecure`, they could manufacture a DNSSEC state by dropping
// packets. RFC 4033 §5's Insecure is a claim that a proof was offered and
// showed the data to be unsigned. An operational failure offered no proof at
// all.
type Status string

const (
	// StatusSecure: Daddybound authenticated the answer, or the absence.
	StatusSecure Status = "secure"
	// StatusInsecure: Daddybound proved the data lies in an unsigned part of
	// the namespace. A proof, not a shrug.
	StatusInsecure Status = "insecure"
	// StatusBogus: a secure delegation was established and the data failed to
	// validate under it.
	StatusBogus Status = "bogus"
	// StatusIndeterminate: Daddybound could not decide, for a reason about
	// the data rather than about itself.
	StatusIndeterminate Status = "indeterminate"

	// StatusTimeout: the observation deadline expired.
	StatusTimeout Status = "timeout"
	// StatusResourceLimit: one of Daddybound's internal bounds was reached.
	StatusResourceLimit Status = "resource_limit"
	// StatusUnsupported: the algorithm, digest or shape is outside what this
	// build evaluates. Reported honestly rather than as Insecure, which would
	// let an attacker downgrade a zone by publishing something unreadable.
	StatusUnsupported Status = "unsupported"
	// StatusInternalError: the observer itself failed.
	StatusInternalError Status = "internal_error"
)

// Statuses is every status, in report order. Used by metrics so a counter
// exists at zero rather than appearing the first time something goes wrong.
func Statuses() []Status {
	return []Status{
		StatusSecure, StatusInsecure, StatusBogus, StatusIndeterminate,
		StatusTimeout, StatusResourceLimit, StatusUnsupported, StatusInternalError,
	}
}

// IsSecurityState reports whether s is one of RFC 4033's four, as opposed to
// a statement about the validator's own ability to answer.
func (s Status) IsSecurityState() bool {
	switch s {
	case StatusSecure, StatusInsecure, StatusBogus, StatusIndeterminate:
		return true
	default:
		return false
	}
}

// Observation is one completed local validation.
//
// Self-contained on purpose. Every field needed to interpret the row is in the
// row, including what the upstream said at the same moment, so that the
// disagreement matrix is a query over one table rather than a join whose
// correctness depends on clock skew.
type Observation struct {
	// ID correlates this observation with the query log row for the same
	// query. Assigned by the caller before the query is recorded, so the two
	// can be joined exactly rather than matched on name and time.
	ID string
	// Time is when the observation completed.
	Time time.Time
	// Domain and QType are the question that was observed.
	Domain string
	QType  string
	// Cached reports that the client's answer came from DNS Daddy's cache, so
	// it may be older than this observation. ADR 0002 §2: observe mode
	// validates the name, not the response bytes, and this is the field that
	// keeps the two populations separable.
	Cached bool
	// UpstreamStatus is what the upstream asserted for the same query, copied
	// from the query event. Never overwritten by the local verdict and never
	// consulted while reaching it.
	UpstreamStatus string

	// Status is the local verdict or the operational outcome.
	Status Status
	// ReasonCode is Daddybound's typed reason. A closed set; nothing branches
	// on the human-readable Reason.
	ReasonCode string
	// Reason is a sentence for a person to read. Bounded and sanitised.
	Reason string

	// Duration is how long the observation took.
	Duration time.Duration
	// Lookups is how many supporting DNSSEC queries it needed.
	Lookups int
}

// maxReasonLen bounds the stored sentence.
//
// The reason text comes from Daddybound rather than from the network, but it
// can quote a name that did, and a row whose size is chosen by whoever asked
// the question is a row an attacker can use to fill a disk.
const maxReasonLen = 300

// sanitiseReason bounds and cleans a diagnostic string for storage.
//
// Control characters are stripped rather than escaped: this ends up in a
// dashboard, a log line and a JSON document, and a string that can carry a
// newline or an ANSI escape into any of them is a string that can forge a log
// entry or move a terminal cursor.
func sanitiseReason(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > maxReasonLen {
		// Cut on a rune boundary so the result is still valid UTF-8.
		cut := maxReasonLen
		for cut > 0 && !utf8Start(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// classify turns a Daddybound result into a recorded status.
//
// The mapping is by typed reason, never by inspecting text. Two of
// Daddybound's Indeterminate reasons are statements about the validator rather
// than about the zone, and ADR 0002 §8 requires those to be recorded as what
// they are:
//
//   - ReasonCancelled: the deadline expired, so nothing was concluded;
//   - ReasonResourceLimit: an internal bound stopped the walk early.
//
// The unsupported-algorithm and unsupported-digest reasons are the same kind
// of statement — this build cannot read the delegation — and reporting them as
// Insecure would hand an attacker a downgrade: publish a delegation signed
// with something exotic and the zone below it becomes "provably unsigned".
func classify(res dnssec.ValidationResult) (Status, string) {
	reason := string(res.Reason)
	switch res.Reason {
	case dnssec.ReasonCancelled:
		return StatusTimeout, reason
	case dnssec.ReasonResourceLimit:
		return StatusResourceLimit, reason
	case dnssec.ReasonUnsupportedAlgorithm, dnssec.ReasonUnsupportedDigest,
		dnssec.ReasonDenialNotImplemented:
		return StatusUnsupported, reason
	}

	switch res.Status {
	case dnssec.StatusSecure:
		return StatusSecure, reason
	case dnssec.StatusInsecure:
		return StatusInsecure, reason
	case dnssec.StatusBogus:
		return StatusBogus, reason
	case dnssec.StatusIndeterminate:
		return StatusIndeterminate, reason
	default:
		// A status this package does not know about is an internal error
		// rather than a guess. Silently folding it into Indeterminate would
		// hide a version skew between the engine and its observer.
		return StatusInternalError, reason
	}
}
