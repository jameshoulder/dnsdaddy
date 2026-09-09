package dnssec

import (
	"strings"
	"time"
)

// ValidationResult is what a validation run produces: a status, the reason
// for it, and the ordered record of how it was reached.
//
// The result is a value, not a handle onto live state. Once returned it does
// not change, which is what makes it safe to store in a regression corpus and
// compare against a later run.
type ValidationResult struct {
	// Status is the verdict. Never assume it: the zero value is
	// Indeterminate precisely so that a partially built result reads as an
	// admission rather than a claim.
	Status ValidationStatus `json:"status"`

	// Reason is why. For StatusSecure it is ReasonVerified.
	Reason Reason `json:"reason"`

	// Name and RRType identify what was validated, in canonical form.
	Name   string `json:"name"`
	RRType uint16 `json:"rrType"`

	// Steps is the ordered trace. Order is deterministic for a given input:
	// nothing here iterates a map to produce a step, because a trace that
	// reorders between runs cannot be diffed and therefore cannot be used as
	// evidence.
	Steps []ValidationStep `json:"steps"`

	// At is the validator's notion of the current time for this run, taken
	// once at the start. Recorded because both signature-validity checks are
	// relative to it, so a disagreement about expiry is only meaningful
	// alongside the clock that produced it.
	At time.Time `json:"at"`
}

// Secure reports whether the result is a positive verdict.
//
// Provided so that callers write result.Secure() rather than comparing
// against a constant, which is one fewer place for an inverted condition to
// hide.
func (r ValidationResult) Secure() bool { return r.Status == StatusSecure }

// Insecure reports whether the data was proved to lie below an authenticated
// insecure delegation.
//
// Deliberately not folded into Secure(). The two are both "nothing is wrong
// here", and they are not the same claim: Secure means the data was signed
// and the signature verified, Insecure means the data was never supposed to
// be signed and that fact was proved. A caller that conflates them cannot
// tell an authenticated unsigned zone from an authenticated signed one, which
// is precisely the distinction DNSSEC exists to make.
func (r ValidationResult) Insecure() bool { return r.Status == StatusInsecure }

// Bogus reports whether validation actively failed, as opposed to being
// unable to reach a conclusion.
func (r ValidationResult) Bogus() bool { return r.Status == StatusBogus }

// Summary is a one-line description for humans.
func (r ValidationResult) Summary() string {
	name := r.Name
	if name == "" {
		name = "(unnamed)"
	}
	return name + " " + rrTypeName(r.RRType) + ": " + r.Status.String() + " — " + r.Reason.Explain()
}

// Trace renders the full step record, one step per line, with the summary
// last. Intended for a terminal and for test failure output; never parsed.
func (r ValidationResult) Trace() string {
	var b strings.Builder
	for _, s := range r.Steps {
		b.WriteString(s.String())
		b.WriteByte('\n')
	}
	b.WriteString("=> ")
	b.WriteString(r.Summary())
	return b.String()
}

// recorder accumulates steps during a run and produces the final result.
//
// It exists so that no code path can construct a result without also having
// recorded how it got there: the only ways out are the four terminal methods
// below, and each one takes the reason it is about to publish.
type recorder struct {
	name   string
	rrType uint16
	at     time.Time
	steps  []ValidationStep
}

func newRecorder(name string, rrType uint16, at time.Time) *recorder {
	return &recorder{name: name, rrType: rrType, at: at}
}

// step records an observation and returns its reason, so a caller can write
//
//	return r.bogus(r.step(...))
//
// without naming the reason twice and risking the two drifting apart.
func (r *recorder) step(s ValidationStep) Reason {
	r.steps = append(r.steps, s)
	return s.Reason
}

// ok records a successful step.
func (r *recorder) ok(s ValidationStep) {
	s.Outcome = OutcomeOK
	if s.Reason == ReasonNone {
		s.Reason = ReasonVerified
	}
	r.steps = append(r.steps, s)
}

// fail records a failed step and returns its reason.
func (r *recorder) fail(s ValidationStep, reason Reason) Reason {
	s.Outcome = OutcomeFailed
	s.Reason = reason
	return r.step(s)
}

// skip records a step that was not attempted and returns its reason.
func (r *recorder) skip(s ValidationStep, reason Reason) Reason {
	s.Outcome = OutcomeSkipped
	s.Reason = reason
	return r.step(s)
}

func (r *recorder) result(status ValidationStatus, reason Reason) ValidationResult {
	return ValidationResult{
		Status: status,
		Reason: reason,
		Name:   r.name,
		RRType: r.rrType,
		Steps:  r.steps,
		At:     r.at,
	}
}

// secure publishes a positive verdict.
func (r *recorder) secure() ValidationResult {
	return r.result(StatusSecure, ReasonVerified)
}

// bogus publishes a negative verdict. Only legitimate once a secure
// delegation has been established — see StatusBogus — which is the chain
// walk's responsibility to enforce, not this recorder's.
func (r *recorder) bogus(reason Reason) ValidationResult {
	return r.result(StatusBogus, reason)
}

// insecure publishes RFC 4033 §5's Insecure: an authenticated proof that no
// DS record exists at a delegation point, so the data below it is legitimately
// unsigned.
//
// It takes no reason argument because there is exactly one thing Insecure is
// allowed to mean. It is not "no signature was found", not "the algorithm is
// unsupported", not "validation failed", not "the DNSKEY was missing", not a
// timeout, not malformed DNSSEC records, and above all not "we could not prove
// Secure". Every one of those is Bogus or Indeterminate. A caller that wants
// Insecure has to have run a denial proof and had it succeed, and the only
// caller that can is the one that did.
func (r *recorder) insecure() ValidationResult {
	return r.result(StatusInsecure, ReasonVerified)
}

// indeterminate publishes "could not tell", which is the honest answer
// whenever Daddybound lacks either the data or the implemented capability to
// decide.
func (r *recorder) indeterminate(reason Reason) ValidationResult {
	return r.result(StatusIndeterminate, reason)
}

// verdict publishes the outcome for a failed check, choosing between Bogus
// and Indeterminate according to whether the reason is about the data or
// about this validator. Every failing path in the chain walk goes through
// here rather than calling bogus directly, so the choice is made once.
func (r *recorder) verdict(reason Reason) ValidationResult {
	if reason.aboutValidator() {
		return r.indeterminate(reason)
	}
	return r.bogus(reason)
}
