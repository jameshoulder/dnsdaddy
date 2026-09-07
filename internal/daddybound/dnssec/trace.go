package dnssec

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// StepKind says which question a validation step answered.
//
// The kinds are the joints of the trust chain, so a trace can be read as a
// sequence of claims: this anchor was configured, this key matched it, this
// delegation authenticated that key, this signature covered that data.
type StepKind string

const (
	// StepTrustAnchor: a configured anchor was matched against a DNSKEY.
	StepTrustAnchor StepKind = "trust_anchor"
	// StepDS: a delegation record was matched against a child DNSKEY.
	StepDS StepKind = "ds"
	// StepDNSKEY: a key was examined for eligibility to sign.
	StepDNSKEY StepKind = "dnskey"
	// StepRRSIG: one signature was considered for one RRset.
	StepRRSIG StepKind = "rrsig"
	// StepRRset: the verdict for one RRset, after every signature on it was
	// considered.
	StepRRset StepKind = "rrset"
	// StepPolicy: an algorithm or digest was allowed or refused.
	StepPolicy StepKind = "policy"
	// StepLimit: validation stopped at a bound, or was cancelled.
	StepLimit StepKind = "limit"
)

// StepOutcome is the three-way result of a step. Skipped is a real outcome
// and not a synonym for failure: a signature that was never eligible to be
// tried says something different about the zone than one that was tried and
// rejected, and a trace that blurs the two cannot be used to argue about a
// disagreement with a reference validator.
type StepOutcome string

const (
	OutcomeOK      StepOutcome = "ok"
	OutcomeFailed  StepOutcome = "failed"
	OutcomeSkipped StepOutcome = "skipped"
)

// ValidationStep is one recorded observation.
//
// Every field is a typed value rather than a formatted string, so that the
// differential comparator and the regression corpus can compare steps
// structurally. Note is the only free text and nothing ever branches on it.
//
// Zero-valued optional fields mean "not applicable to this step", and both
// the JSON encoding and the human-readable line omit them. That is imprecise
// for two legal values — algorithm 0 is DELETE and key tag 0 occurs about
// once in 65536 keys — so a step carrying either renders as though the field
// were absent.
//
// The imprecision is confined to presentation. Nothing reads a step back out
// of its rendered form to make a decision: comparisons in the differential
// harness and the regression corpus use the struct fields, which are exact.
// The alternative, a presence flag beside every optional field, would put
// four more booleans into a type whose whole job is to be easy to read.
type ValidationStep struct {
	Kind    StepKind    `json:"kind"`
	Outcome StepOutcome `json:"outcome"`
	Reason  Reason      `json:"reason,omitempty"`

	// Zone is the owner name this step concerns, in canonical form.
	Zone string `json:"zone,omitempty"`
	// Name is the RRset owner name, when it differs from Zone.
	Name string `json:"name,omitempty"`
	// RRType is the record type under consideration.
	RRType uint16 `json:"rrType,omitempty"`

	// Algorithm is the DNSSEC algorithm number (IANA registry).
	Algorithm uint8 `json:"algorithm,omitempty"`
	// DigestType is the DS digest type (IANA registry).
	DigestType uint8 `json:"digestType,omitempty"`
	// KeyTag is the DNSKEY key tag, which is a checksum and not an
	// identifier: two keys in one RRset may share it.
	KeyTag uint16 `json:"keyTag,omitempty"`

	// Note is for humans. Never parsed, never compared, never used to decide
	// anything.
	Note string `json:"note,omitempty"`
}

// String renders one step as a line of a trace.
func (s ValidationStep) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-13s %-7s", s.Kind, s.Outcome)

	if s.Zone != "" {
		fmt.Fprintf(&b, " zone=%s", s.Zone)
	}
	if s.Name != "" && s.Name != s.Zone {
		fmt.Fprintf(&b, " name=%s", s.Name)
	}
	if s.RRType != 0 {
		fmt.Fprintf(&b, " type=%s", rrTypeName(s.RRType))
	}
	if s.DigestType != 0 {
		fmt.Fprintf(&b, " digest=%d", s.DigestType)
	}
	if s.Algorithm != 0 {
		fmt.Fprintf(&b, " alg=%d", s.Algorithm)
	}
	if s.KeyTag != 0 {
		fmt.Fprintf(&b, " keytag=%d", s.KeyTag)
	}
	if s.Reason != ReasonNone {
		fmt.Fprintf(&b, " reason=%s", s.Reason)
	}
	if s.Note != "" {
		fmt.Fprintf(&b, " (%s)", s.Note)
	}
	return b.String()
}

// rrTypeName renders a type number as its mnemonic, falling back to TYPEnnn
// for types this build has no name for — which is the RFC 3597 convention and
// keeps an unknown type readable rather than blank.
func rrTypeName(t uint16) string {
	if name, ok := dns.TypeToString[t]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}
