package detect

import (
	"fmt"
	"sort"
	"strings"
)

// Name assessment: what a single DNS name looks like, on its own.
//
// This is the weakest evidence DNS Daddy produces and is deliberately built to
// say so. It reads one name, allocates nothing that outlives the call, and
// keeps no state — no per-domain table, no cache, no growth. That property is
// why it can run on demand for any name at any time on a small box, and it is
// worth preserving.
//
// What it cannot do is more important than what it can. It has never seen the
// domain resolve, does not know who registered it or when, and has no
// behavioural context. A random-looking name is a *lead*: legitimate CDN,
// telemetry and cloud-storage hostnames are random-looking by design, and they
// vastly outnumber malicious ones on a real network. Nothing here is
// sufficient to block, and NameAssessment carries no severity for that reason.

// NameSignalWeights are each signal's share of the assessment.
//
// They sum to 1 and are held small in aggregate on purpose: see MaxScore. The
// randomness index carries the most because it is the only signal that
// combines several independent properties, and the single-property signals
// carry least because each is individually easy to trip by accident.
var NameSignalWeights = map[string]float64{
	"dga_like_characteristics": 0.40,
	"label_entropy":            0.20,
	"digit_ratio":              0.15,
	"name_length":              0.10,
	"encoded_label":            0.10,
	"hyphen_density":           0.05,
}

// MaxNameScore bounds what a name's own appearance can contribute to any
// overall risk assessment.
//
// Capped well below 100 deliberately. Appearance alone should never reach a
// blocking threshold on its own, whatever combination of lexical properties a
// name manages to trip, because the benign population that shares those
// properties is large. Corroborated threat intelligence is what earns a high
// score; this is a modifier on top of it.
const MaxNameScore = 25.0

// NameAssessment is the result of looking at one name.
type NameAssessment struct {
	// Name is the name assessed, normalised.
	Name string `json:"name"`
	// AssessedLabel is the label the lexical signals were measured on: the
	// highest-scoring label, named so a reader can see what was judged rather
	// than having to guess.
	AssessedLabel string `json:"assessedLabel,omitempty"`
	// RegisteredDomain is the eTLD+1, when the name has one.
	RegisteredDomain string `json:"registeredDomain,omitempty"`
	// Signals are the measurements that contributed, strongest first. Each
	// carries its own floor, ceiling and weight so the arithmetic can be
	// checked by hand.
	Signals []Signal `json:"signals"`
	// NotObserved names the lexical properties that were looked for and not
	// found. Reported explicitly because "we checked and it was ordinary" and
	// "we did not check" are different statements, and collapsing them is how
	// an absence of evidence turns into a clean bill of health.
	NotObserved []string `json:"notObserved"`
	// Unavailable names properties that could not be measured on this name,
	// with the reason. Never treated as evidence of safety.
	Unavailable []string `json:"unavailable,omitempty"`
	// Score is this name's contribution to an overall risk assessment, 0 to
	// MaxNameScore.
	Score float64 `json:"score"`
	// Confidence is how much weight to place on this assessment, 0..1. It is
	// low by construction: see the package comment.
	Confidence float64 `json:"confidence"`
	// Summary states the finding in the cautious register the evidence
	// supports.
	Summary string `json:"summary"`
	// Limitations is what this assessment cannot tell you. Always populated.
	Limitations []string `json:"limitations"`
}

// AssessName measures the lexical properties of a single DNS name.
//
// name must already be normalised (lowercase, no trailing dot), as it is
// everywhere else in this package.
func AssessName(name string) NameAssessment {
	a := NameAssessment{
		Name:        name,
		Signals:     []Signal{},
		NotObserved: []string{},
		Limitations: nameLimitations,
	}
	if name == "" {
		a.Summary = "No name to assess."
		return a
	}

	parent, _, hasParent := split(name)
	if hasParent {
		a.RegisteredDomain = parent
	} else {
		a.Unavailable = append(a.Unavailable,
			"registered domain: the name is a single label, is itself a public "+
				"suffix, or sits under a private-namespace TLD, so it cannot be "+
				"attributed to a registrable domain")
	}

	label, skipped := assessableLabel(name)
	if label == "" {
		if skipped != "" {
			a.Unavailable = append(a.Unavailable, skipped)
		}
		a.Summary = "This name has no label that lexical analysis can meaningfully judge."
		a.Confidence = 0
		return a
	}
	a.AssessedLabel = label

	add := func(s Signal) {
		s.Weight = NameSignalWeights[s.Name]
		s.Normalised = clamp01(s.Normalised)
		s.Contribution = s.Normalised * s.Weight
		if s.Normalised > 0 {
			a.Signals = append(a.Signals, s)
		} else {
			a.NotObserved = append(a.NotObserved, s.Description)
		}
	}

	add(randomnessSignal(label))
	add(entropySignal(label, &a))
	add(digitSignal(label))
	add(lengthSignal(name))
	add(encodedSignal(label))
	add(hyphenSignal(label))

	var total float64
	for _, s := range a.Signals {
		total += s.Contribution
	}
	sort.SliceStable(a.Signals, func(i, j int) bool {
		return a.Signals[i].Contribution > a.Signals[j].Contribution
	})

	a.Score = clamp01(total) * MaxNameScore
	a.Confidence = nameConfidence(len(a.Signals), len(label))
	a.Summary = nameSummary(a)
	return a
}

var nameLimitations = []string{
	"This describes how the name looks, nothing more. It has not been resolved, " +
		"and its registration date, owner and hosting are not known here.",
	"Random-looking names are normal. CDN, cloud-storage, telemetry and " +
		"load-balancer hostnames are generated by machines and routinely score " +
		"as highly as malicious ones.",
	"A name chosen to look ordinary scores nothing here. A low score is not " +
		"evidence that a domain is safe.",
}

// assessableLabel picks the label to measure: the highest-scoring label that
// is long enough to judge, excluding public-suffix components and the
// structural prefixes that carry no signal.
//
// Choosing the strongest label rather than averaging is deliberate. A tunnel
// or a generated hostname puts its payload in one label and leaves the rest
// ordinary, and an average over "www", "example" and a 50-character random
// string reports the ordinary labels' calm rather than the interesting one.
func assessableLabel(name string) (label, unavailable string) {
	labels := labelsOf(name)
	if len(labels) == 0 {
		return "", ""
	}
	parent, _, hasParent := split(name)

	// Everything at or below the registrable boundary is the owner's choice;
	// the public suffix above it is not, and scoring "co.uk" would be noise.
	candidates := labels
	if hasParent {
		suffixLabels := len(labelsOf(parent)) - 1
		if n := len(labels) - suffixLabels; n > 0 && n <= len(labels) {
			candidates = labels[:n]
		}
	}

	var (
		best      string
		bestScore float64
		punycode  bool
		tooShort  bool
	)
	for _, l := range candidates {
		if structuralLabels[l] {
			continue
		}
		if isInternationalised(l) {
			punycode = true
			continue
		}
		if len(l) < 8 {
			tooShort = true
			continue
		}
		if s := randomnessIndex(l); s >= bestScore || best == "" {
			best, bestScore = l, s
		}
	}
	switch {
	case best != "":
		return best, ""
	case punycode:
		return "", "lexical analysis: every candidate label is punycode (xn--), " +
			"which is machine-generated by definition and would score as random " +
			"whatever it spells"
	case tooShort:
		return "", "lexical analysis: no label is long enough to measure — below " +
			"about eight characters, entropy and character-distribution tests " +
			"measure length rather than randomness"
	}
	return "", ""
}

// structuralLabels carry no signal about who chose the name: they are
// conventions, present on ordinary and malicious names alike.
var structuralLabels = map[string]bool{
	"www": true, "mail": true, "smtp": true, "imap": true, "pop": true,
	"ns1": true, "ns2": true, "mx": true, "cdn": true, "api": true,
	"_dmarc": true, "_domainkey": true,
}

func randomnessSignal(label string) Signal {
	v := randomnessIndex(label)
	return Signal{
		Name: "dga_like_characteristics",
		Description: "Combined vowel distribution, consonant runs, digit fraction and " +
			"entropy, on 0..1 — the surface statistics an algorithmically generated " +
			"name tends to trip together.",
		Value: v, Floor: 0.35, Ceiling: 0.75,
		Normalised: ramp(v, 0.35, 0.75),
	}
}

func entropySignal(label string, a *NameAssessment) Signal {
	s := Signal{
		Name: "label_entropy",
		Description: "Shannon entropy of the assessed label in bits per character. " +
			"High entropy means the characters are evenly spread, which random " +
			"strings are and words are not.",
		Floor: 3.2, Ceiling: 4.2,
	}
	if len(label) < minEntropyLabelLen {
		// Entropy per character is bounded by log2(length), so a short label
		// cannot score highly however random it is. Reporting zero here would
		// read as "measured, and ordinary".
		a.Unavailable = append(a.Unavailable, fmt.Sprintf(
			"label entropy: %q is %d characters, below the %d needed for entropy "+
				"per character to measure randomness rather than length",
			label, len(label), minEntropyLabelLen))
		return s
	}
	s.Value = shannonEntropy(label)
	s.Normalised = ramp(s.Value, s.Floor, s.Ceiling)
	return s
}

func digitSignal(label string) Signal {
	var digits int
	for i := 0; i < len(label); i++ {
		if label[i] >= '0' && label[i] <= '9' {
			digits++
		}
	}
	v := float64(digits) / float64(len(label))
	return Signal{
		Name: "digit_ratio",
		Description: "Fraction of the assessed label that is digits. Generated names " +
			"carry more digits than chosen ones — though so do version numbers, " +
			"shard identifiers and datestamps.",
		Value: v, Floor: 0.20, Ceiling: 0.50,
		Normalised: ramp(v, 0.20, 0.50),
	}
}

func lengthSignal(name string) Signal {
	v := float64(len(name))
	return Signal{
		Name: "name_length",
		Description: "Total length of the name in characters. Unusually long names " +
			"carry data as often as they carry meaning.",
		Value: v, Floor: 60, Ceiling: 150,
		Normalised: ramp(v, 60, 150),
	}
}

func encodedSignal(label string) Signal {
	v := 0.0
	if looksEncoded(label) {
		v = 1
	}
	return Signal{
		Name: "encoded_label",
		Description: "Whether the assessed label conforms to a base32/base64/hex " +
			"character set with a mix consistent with encoded binary rather than text.",
		Value: v, Floor: 0, Ceiling: 1,
		Normalised: v,
	}
}

func hyphenSignal(label string) Signal {
	var hyphens int
	for i := 0; i < len(label); i++ {
		if label[i] == '-' {
			hyphens++
		}
	}
	v := float64(hyphens)
	return Signal{
		Name: "hyphen_density",
		Description: "Hyphens in the assessed label. Long hyphenated strings are a " +
			"staple of brand-impersonation names — and of ordinary descriptive ones.",
		Value: v, Floor: 3, Ceiling: 7,
		Normalised: ramp(v, 3, 7),
	}
}

// nameConfidence reports how much weight to place on the assessment.
//
// It rises with the number of independent signals that fired, because one
// property tripping is ordinary and several tripping together is not. It is
// capped below 1: this measure cannot be certain about anything, and a
// confidence of 1 on a lexical heuristic would be a lie.
func nameConfidence(signals, labelLen int) float64 {
	if signals == 0 {
		return 0
	}
	c := 0.25 + 0.15*float64(signals-1)
	if labelLen < minEntropyLabelLen {
		c *= 0.6
	}
	if c > 0.75 {
		c = 0.75
	}
	return c
}

// nameSummary states the result in language the evidence supports. The
// register is the point: "DGA-like characteristics observed" is a description
// of a measurement, "a DGA domain" is a claim about malware that this cannot
// establish.
func nameSummary(a NameAssessment) string {
	if len(a.Signals) == 0 {
		return "Nothing unusual about how this name is constructed. That is not " +
			"evidence that the domain is safe — a name chosen to look ordinary " +
			"scores exactly this way."
	}
	names := make([]string, 0, len(a.Signals))
	for _, s := range a.Signals {
		names = append(names, humanSignal[s.Name])
	}
	lead := "Possible DGA-like characteristics observed"
	if len(a.Signals) == 1 {
		lead = "One unusual property observed"
	} else if len(a.Signals) >= 3 {
		lead = "Several DGA-like characteristics observed together"
	}
	return fmt.Sprintf("%s in %q: %s. Lexical evidence only — this describes the "+
		"name's appearance, not its behaviour, and legitimate machine-generated "+
		"hostnames look much the same.",
		lead, a.AssessedLabel, strings.Join(names, ", "))
}

var humanSignal = map[string]string{
	"dga_like_characteristics": "algorithmic-looking character statistics",
	"label_entropy":            "high character entropy",
	"digit_ratio":              "a high proportion of digits",
	"name_length":              "unusual length",
	"encoded_label":            "an encoded-looking label",
	"hyphen_density":           "heavy hyphenation",
}
