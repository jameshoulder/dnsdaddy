// Package differential compares Daddybound's verdicts against an independent
// reference validator.
//
// The point is not to make Daddybound agree with anything in particular. It
// is to find the cases where it disagrees, and to make one class of
// disagreement impossible to overlook: the reference says the data is forged
// and Daddybound says it is fine.
//
// A reference validator is an oracle, not an authority. When the two
// disagree, the investigation starts at the rule identifiers in
// docs/daddybound/standards.md — "the older implementation says so" is not a
// finding, and neither is "our implementation is newer". Where the standard
// is unambiguous, the standard decides.
package differential

import (
	"context"
	"fmt"
	"sort"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// Reference is an independent DNSSEC validator used as a test oracle.
//
// Implementations live behind build constraints so that nothing they link
// against reaches the shipped resolver. The interface is here, in ordinary
// Go, so that the comparison logic can be read, tested and reasoned about
// without a C toolchain.
type Reference interface {
	// Name identifies the oracle in reports, including its version where it
	// can be obtained. A comparison report without it cannot be reproduced.
	Name() string
	// Validate returns the reference's verdict for one question.
	Validate(ctx context.Context, qname string, qtype uint16) (ReferenceResult, error)
}

// ReferenceResult is an oracle's verdict.
type ReferenceResult struct {
	Status dnssec.ValidationStatus
	// Unresolved marks an oracle that reported neither "secure" nor "bogus"
	// and cannot say which of Insecure and Indeterminate it meant.
	//
	// libunbound is like this: its result carries a secure flag and a bogus
	// flag, and both clear covers RFC 4033's Insecure and its Indeterminate
	// at once. Status is set to Insecure in that case because it is the more
	// specific of the two, and this flag records that the oracle did not
	// actually choose. Classify then treats Daddybound's Indeterminate as
	// consistent with it, because it is: the oracle's answer does not
	// distinguish them, so calling it a disagreement would be inventing
	// evidence the oracle never gave.
	Unresolved bool

	// Detail is whatever the oracle says about its reasoning, verbatim.
	//
	// It is for a human reading a failure. Nothing in this package parses it,
	// branches on it, or lets it influence a classification — a validator
	// that decided anything by matching another implementation's error text
	// would be deriving its behaviour from that implementation, which is the
	// thing this project exists not to do.
	Detail string
}

// Class is the outcome of comparing one verdict against one oracle.
type Class string

const (
	// ClassMatch: both reached the same status.
	ClassMatch Class = "MATCH"

	// ClassFalseSecure: the reference says the data does not validate and
	// Daddybound says it does.
	//
	// This is the P0 failure of the whole project. Every other class is a
	// question about correctness; this one is a validator that would tell an
	// operator forged data is authentic. Nothing excuses it — a known gap
	// cannot reclassify it, and the release gate counts it.
	ClassFalseSecure Class = "FALSE_SECURE"

	// ClassFalseBogus: Daddybound says the data is forged and the reference
	// says it is fine.
	//
	// Wrong, and wrong in the direction that refuses good data rather than
	// accepting bad. It still needs fixing: a validator that cries wolf gets
	// turned off, and a validator that is turned off protects nobody.
	ClassFalseBogus Class = "FALSE_BOGUS"

	// ClassStatusDisagreement: the two differ in some other way — one says
	// Indeterminate where the other reached a verdict, most often.
	ClassStatusDisagreement Class = "STATUS_DISAGREEMENT"

	// ClassKnownGap: a disagreement a scenario predicted and explained, from
	// a capability v0.1 does not claim.
	//
	// Deliberately not a synonym for "ignore". A known gap is a documented
	// limitation with a written justification attached to the scenario, and
	// it can never absorb a FalseSecure: Classify checks for that first.
	ClassKnownGap Class = "KNOWN_GAP"

	// ClassReferenceError: the oracle could not answer. Says nothing about
	// Daddybound and must not be counted as agreement.
	ClassReferenceError Class = "REFERENCE_ERROR"

	// ClassDaddyboundError: Daddybound failed to produce a result at all.
	ClassDaddyboundError Class = "DADDYBOUND_ERROR"
)

// Comparison is one scenario run through both validators.
type Comparison struct {
	Scenario   string
	Class      Class
	Daddybound dnssec.ValidationResult
	Reference  ReferenceResult

	// ReferenceErr and DaddyboundErr are set for the two error classes.
	ReferenceErr  string
	DaddyboundErr string

	// KnownGap is the scenario's own explanation of a predicted
	// disagreement, empty when it predicted none.
	KnownGap string
}

// Classify decides the class of one comparison.
//
// The order of the checks is the safety property. FalseSecure is tested
// before the known-gap exemption and before anything else that could soften
// a disagreement, so no scenario annotation and no future special case can
// reclassify a false Secure into something quieter.
func Classify(db dnssec.ValidationResult, dbErr error, ref ReferenceResult, refErr error, knownGap string) Class {
	// A Daddybound failure is reported before the oracle is consulted: if
	// Daddybound did not produce a result, there is nothing to compare and
	// the oracle's verdict is not evidence about it either way.
	if dbErr != nil {
		return ClassDaddyboundError
	}

	// The P0 check, first and unconditional. The reference established that
	// the data does not validate, and Daddybound said it does.
	if ref.Status == dnssec.StatusBogus && db.Status == dnssec.StatusSecure {
		return ClassFalseSecure
	}

	if refErr != nil {
		return ClassReferenceError
	}
	if db.Status == ref.Status {
		return ClassMatch
	}
	// An oracle that could not separate Insecure from Indeterminate agrees
	// with either. Placed after the FalseSecure check so it can never soften
	// one: a bogus reference verdict is never Unresolved.
	if ref.Unresolved && (db.Status == dnssec.StatusIndeterminate || db.Status == dnssec.StatusInsecure) {
		return ClassMatch
	}
	// The known-gap annotation is consulted before FalseBogus and after
	// FalseSecure, which is the whole of its authority.
	//
	// Calling a disagreement a false Bogus presumes the oracle is right. A
	// scenario can rebut that presumption with a written justification — an
	// RFC citation, or a limitation of how the oracle is configured — and
	// the foreign-zone-signature scenario does exactly that. It can never
	// rebut a false Secure, because Classify has already returned by then:
	// no annotation, and no future special case added below this line, can
	// quiet the one class that matters.
	if knownGap != "" {
		return ClassKnownGap
	}
	if ref.Status == dnssec.StatusSecure && db.Status == dnssec.StatusBogus {
		return ClassFalseBogus
	}
	return ClassStatusDisagreement
}

// Report is a set of comparisons and the counts that matter.
type Report struct {
	Oracle      string
	Comparisons []Comparison
}

// Counts returns how many comparisons fell into each class, in a fixed class
// order so two reports can be diffed.
func (r Report) Counts() []struct {
	Class Class
	N     int
} {
	byClass := map[Class]int{}
	for _, c := range r.Comparisons {
		byClass[c.Class]++
	}
	order := []Class{
		ClassFalseSecure, ClassFalseBogus, ClassStatusDisagreement,
		ClassKnownGap, ClassMatch, ClassReferenceError, ClassDaddyboundError,
	}
	out := make([]struct {
		Class Class
		N     int
	}, 0, len(order))
	for _, c := range order {
		out = append(out, struct {
			Class Class
			N     int
		}{c, byClass[c]})
	}
	return out
}

// FalseSecure returns the comparisons where Daddybound accepted data the
// reference rejected.
func (r Report) FalseSecure() []Comparison {
	var out []Comparison
	for _, c := range r.Comparisons {
		if c.Class == ClassFalseSecure {
			out = append(out, c)
		}
	}
	return out
}

// FalseSecureRate is the proportion of comparable runs that were false
// Secures.
//
// The denominator excludes runs where either side failed to produce a
// verdict, because those are not evidence about agreement. Counting them
// would let a broken oracle flatter the rate, which is the wrong direction
// for this particular number to be wrong in.
func (r Report) FalseSecureRate() float64 {
	comparable, false_ := 0, 0
	for _, c := range r.Comparisons {
		switch c.Class {
		case ClassReferenceError, ClassDaddyboundError:
			continue
		case ClassFalseSecure:
			false_++
		}
		comparable++
	}
	if comparable == 0 {
		return 0
	}
	return float64(false_) / float64(comparable)
}

// Summary renders the report for a human or a CI log.
func (r Report) Summary() string {
	out := fmt.Sprintf("differential report against %s\n", r.Oracle)
	for _, c := range r.Counts() {
		out += fmt.Sprintf("  %-20s %d\n", c.Class, c.N)
	}
	out += fmt.Sprintf("  %-20s %.4f\n", "false secure rate", r.FalseSecureRate())

	// Failures are listed in a stable order so a CI log can be diffed
	// between runs.
	var notable []Comparison
	for _, c := range r.Comparisons {
		switch c.Class {
		case ClassMatch, ClassKnownGap:
		default:
			notable = append(notable, c)
		}
	}
	sort.Slice(notable, func(i, j int) bool {
		if notable[i].Class != notable[j].Class {
			return notable[i].Class < notable[j].Class
		}
		return notable[i].Scenario < notable[j].Scenario
	})
	for _, c := range notable {
		out += fmt.Sprintf("\n%s [%s]\n  daddybound: %s (%s)\n  reference:  %s",
			c.Scenario, c.Class, c.Daddybound.Status, c.Daddybound.Reason, c.Reference.Status)
		if c.Reference.Detail != "" {
			out += fmt.Sprintf(" — %s", c.Reference.Detail)
		}
		if c.ReferenceErr != "" {
			out += fmt.Sprintf("\n  reference error: %s", c.ReferenceErr)
		}
		if c.DaddyboundErr != "" {
			out += fmt.Sprintf("\n  daddybound error: %s", c.DaddyboundErr)
		}
		out += "\n"
	}
	return out
}
