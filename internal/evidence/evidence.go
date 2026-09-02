// Package evidence is the common shape for everything DNS Daddy thinks it
// knows about a domain, an address or a device.
//
// # Why this exists
//
// Before this package there were three kinds of evidence in the codebase and
// no way to put them side by side. A blocklist entry knew its feed. A finding
// knew its detector and its signals. A provider verdict knew its score. All
// three answered "is this bad and why", none of them in the same words, and
// nothing could say "two independent sources agree" because there was no shape
// in which two sources could be compared.
//
// This package is that shape. It is deliberately small: five identifying
// fields, a claim, a confidence and a time. Anything a particular source
// wants to say beyond that goes in Detail, attributed to that source, and is
// displayed as that source's own words rather than folded into a number of
// ours.
//
// # What it is not
//
// It is not a scoring system. Confidence is a three-value enum precisely so
// that nobody can average it. Two sources at "high" do not make a "very high";
// they make two sources at high, which is what an operator is shown and what
// an assessment says. The moment evidence becomes arithmetic, the explanation
// stops being reproducible by the person reading it, and that is the one
// property this release exists to provide.
//
// It is also not the enforcement path. Evidence records what was observed;
// policy decides what to do about it. A detector producing "suspicious" is
// evidence, not a block. See docs/detection/README.md, which states that
// position at more length.
package evidence

import (
	"strings"
	"time"
)

// SchemaVersion is carried on exported evidence so that a consumer — a SIEM
// rule, a generated client — can tell whether it is reading a shape it
// understands. It moves when a field changes meaning, not when one is added.
const SchemaVersion = "1.0"

// Kind is where a piece of evidence came from, at the coarsest useful
// granularity: not which feed, but what sort of thing a feed is.
//
// It exists because the answer to "how much should I trust this" differs by
// kind in a way it does not differ within a kind. A feed match means a human
// somewhere curated an indicator. A detector result means a heuristic inferred
// intent from traffic shape. Those are different epistemic claims and an
// operator reading an explanation needs to be able to tell them apart at a
// glance.
type Kind string

const (
	// KindFeed is a match against a downloaded threat-intelligence list.
	KindFeed Kind = "feed"
	// KindProvider is an answer from an external API the operator configured.
	KindProvider Kind = "provider"
	// KindDetector is a behavioural heuristic's finding. Inference, not fact.
	KindDetector Kind = "detector"
	// KindLocal is something this resolver observed itself — first-seen, query
	// volume, which clients asked. No third party involved.
	KindLocal Kind = "local"
	// KindOperator is a human decision recorded as evidence: an allow-list
	// entry, a manual block. The most trustworthy kind, and the only one that
	// can be argued with.
	KindOperator Kind = "operator"
)

// Valid reports whether k is a kind this build understands.
func (k Kind) Valid() bool {
	switch k {
	case KindFeed, KindProvider, KindDetector, KindLocal, KindOperator:
		return true
	}
	return false
}

// Confidence is how strongly a source stands behind its own claim.
//
// Three values, not a float, and this is the most consequential decision in
// the package.
//
// A float invites arithmetic across sources whose numbers have no common
// scale: VirusTotal's engine ratio, a detector's weighted signal total and a
// feed's binary membership are not commensurable, and averaging them produces
// a number that looks precise and means nothing. That number then appears in
// the interface, an operator acts on it, and nobody — including us — can say
// how it was reached.
//
// Where a source has a number of its own it goes in Detail and is shown as
// that source's number, with that source's name next to it.
type Confidence string

const (
	// ConfidenceLow is "this is worth knowing", not "this is probably true".
	ConfidenceLow Confidence = "low"
	// ConfidenceMedium is the default for an inference with real support.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceHigh is reserved for a source that would stake its reputation
	// on the claim: a curated feed listing, or an operator's own decision.
	ConfidenceHigh Confidence = "high"
)

// Valid reports whether c is a confidence this build understands.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	}
	return false
}

// Rank orders confidence for display and for "the strongest thing we have"
// queries. It is deliberately not exposed as arithmetic on Confidence itself.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceMedium:
		return 1
	case ConfidenceHigh:
		return 2
	default:
		return 0
	}
}

// SubjectType is what a piece of evidence is about.
type SubjectType string

const (
	SubjectDomain SubjectType = "domain"
	SubjectIP     SubjectType = "ip"
	SubjectDevice SubjectType = "device"
)

// Valid reports whether t is a subject type this build understands.
func (t SubjectType) Valid() bool {
	switch t {
	case SubjectDomain, SubjectIP, SubjectDevice:
		return true
	}
	return false
}

// Subject is what evidence is about: a domain, an address, or a device.
type Subject struct {
	Type  SubjectType `json:"type"`
	Value string      `json:"value"`
}

// Key is the storage key for a subject. Type is included because "1.2.3.4" as
// a domain and as an address are different subjects, and a bare value would
// silently merge them.
func (s Subject) Key() string { return string(s.Type) + ":" + s.Value }

// Domain returns a subject for a domain name, lower-cased and stripped of a
// trailing dot so that "Evil.Example." and "evil.example" are one subject
// rather than three.
func Domain(name string) Subject {
	return Subject{Type: SubjectDomain, Value: normaliseDomain(name)}
}

// IP returns a subject for an address.
func IP(addr string) Subject {
	return Subject{Type: SubjectIP, Value: strings.TrimSpace(addr)}
}

// Device returns a subject for a device identity.
func Device(id string) Subject {
	return Subject{Type: SubjectDevice, Value: strings.TrimSpace(id)}
}

// normaliseDomain lower-cases and strips the root label.
//
// Deliberately not internal/domainutil.Normalize: that function is on the DNS
// hot path and does more (IDNA, validity). This is a storage key normaliser
// and needs only to stop the same name producing two rows.
func normaliseDomain(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	for strings.HasSuffix(n, ".") {
		n = strings.TrimSuffix(n, ".")
	}
	return n
}

// Evidence is one source's claim about one subject at one time.
type Evidence struct {
	ID      string  `json:"id"`
	Subject Subject `json:"subject"`

	Kind Kind `json:"kind"`
	// Source is the stable identifier of what produced this: a feed ID, a
	// provider ID, a detector name, or "operator".
	Source string `json:"source"`
	// SourceName is the display name as it was at the time of recording.
	//
	// Denormalised on purpose. A feed renamed or deleted next month must not
	// change or blank the explanation of a block that happened today — an
	// audit trail that rewrites itself is not one.
	SourceName string `json:"sourceName"`

	// Claim is what the source asserts, in words an operator can read:
	// "listed as malware infrastructure", "behaviour consistent with DNS
	// tunnelling", "first seen four minutes ago".
	Claim string `json:"claim"`
	// Category is the security category this bears on, where the source names
	// one: malware, phishing, c2, cryptomining. Empty is valid and common —
	// local observations and most enrichment have no category.
	Category string `json:"category,omitempty"`

	Confidence Confidence `json:"confidence"`

	ObservedAt time.Time `json:"observedAt"`
	// ExpiresAt is when this claim should stop being treated as current. Nil
	// means it does not expire on its own — an operator decision, or a local
	// observation of something that did happen and always will have.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`

	// Detail is the source's own supporting data, in the source's own terms:
	// a detector's signals, a provider's score, a feed's category string.
	//
	// Untrusted by construction. Provider values come from a third party and
	// domain names come from clients, so nothing here may be rendered without
	// escaping or exported without bounding. The store enforces a size cap.
	Detail map[string]any `json:"detail,omitempty"`
}

// Expired reports whether this evidence has passed its expiry at the given
// time. Evidence with no expiry never expires.
func (e Evidence) Expired(now time.Time) bool {
	return e.ExpiresAt != nil && !e.ExpiresAt.After(now)
}

// Inference reports whether this evidence is something inferred rather than
// asserted by a curator or a human.
//
// Used to word explanations honestly. A block supported only by inference must
// not be described the same way as one supported by a curated listing, and
// this is the distinction that decides which wording is used.
func (e Evidence) Inference() bool {
	return e.Kind == KindDetector
}

// Validate reports why this evidence cannot be stored, or nil.
func (e Evidence) Validate() error {
	switch {
	case !e.Subject.Type.Valid():
		return errInvalid("subject type", string(e.Subject.Type))
	case strings.TrimSpace(e.Subject.Value) == "":
		return errEmpty("subject value")
	case !e.Kind.Valid():
		return errInvalid("kind", string(e.Kind))
	case strings.TrimSpace(e.Source) == "":
		return errEmpty("source")
	case strings.TrimSpace(e.Claim) == "":
		return errEmpty("claim")
	case !e.Confidence.Valid():
		return errInvalid("confidence", string(e.Confidence))
	case e.ObservedAt.IsZero():
		return errEmpty("observedAt")
	}
	return nil
}
