package evidence

import (
	"sort"
	"strings"
	"time"
)

// Verdict is what a set of evidence adds up to, in the coarsest terms that are
// still honest.
type Verdict string

const (
	// VerdictUnknown means nothing is on file. It is the default and it is a
	// real answer, not a failure — most domains are unknown to most sources.
	VerdictUnknown Verdict = "unknown"
	// VerdictBenign means a source positively asserted the subject is fine.
	// Rarer than it sounds: an absence of evidence is Unknown, not Benign.
	VerdictBenign Verdict = "benign"
	// VerdictSuspicious means something inferred a concern. Inference only.
	VerdictSuspicious Verdict = "suspicious"
	// VerdictMalicious means at least one curated source listed the subject.
	VerdictMalicious Verdict = "malicious"
)

// Assessment is what DNS Daddy currently thinks about a subject, and — more
// importantly — the reasons, kept separate rather than combined.
//
// The design rule is that everything in here can be re-derived by hand from
// the Evidence slice by a person who has never read this file. There is no
// score, no weighting between sources, and no field whose value cannot be
// pointed at in the evidence below it. §14 of the v0.3 brief asks for
// corroboration without "two feeds = definitely malicious"; this is how: the
// count of agreeing sources is reported, and it is reported as a count, next
// to the sources themselves.
type Assessment struct {
	Subject Subject `json:"subject"`
	Verdict Verdict `json:"verdict"`
	// Confidence is the highest confidence among the evidence that supports
	// the verdict — not an average, and not raised by corroboration. Two
	// medium-confidence sources agreeing is two medium-confidence sources
	// agreeing; saying "high" there would be inventing certainty.
	Confidence Confidence `json:"confidence"`
	// Summary is one sentence stating what is believed and on what basis.
	Summary string `json:"summary"`
	// Categories are those named by supporting evidence, most-cited first.
	Categories []string `json:"categories,omitempty"`
	// Sources names the distinct sources that support the verdict, so
	// "corroborated" can be shown as the specific sources that corroborate.
	Sources []string `json:"sources,omitempty"`
	// Corroborated reports whether more than one independent source supports
	// the verdict. Independent means a different Source, not a different row:
	// one feed listing a domain twice is one source.
	Corroborated bool `json:"corroborated"`
	// InferenceOnly reports that nothing but behavioural inference supports
	// this. It exists so the interface can word such a verdict differently,
	// because "a heuristic thinks so" and "a curator listed it" are not the
	// same claim and must not read as though they were.
	InferenceOnly bool `json:"inferenceOnly"`
	// Evidence is everything considered, expired entries excluded, strongest
	// first. The assessment is a reading of this and nothing else.
	Evidence []Evidence `json:"evidence"`
}

// Assess reads a set of evidence and states what it supports.
//
// Expired evidence is excluded rather than discounted: a claim past its own
// stated expiry is not weak evidence, it is evidence the source no longer
// stands behind, and treating it as a faint signal would be the "malicious
// forever because it appeared once" failure §13 warns about.
func Assess(subject Subject, all []Evidence, now time.Time) Assessment {
	a := Assessment{Subject: subject, Verdict: VerdictUnknown, Confidence: ConfidenceLow}

	live := make([]Evidence, 0, len(all))
	for _, e := range all {
		if !e.Expired(now) {
			live = append(live, e)
		}
	}
	sortEvidence(live)
	a.Evidence = live
	if len(live) == 0 {
		a.Summary = "Nothing on file for this subject."
		return a
	}

	// The verdict is decided by the strongest kind of claim present, not by
	// counting. A curated listing outranks an inference however many
	// inferences there are, because they are different kinds of claim.
	var (
		curated    []Evidence // feed or operator: somebody decided
		provider   []Evidence
		inferences []Evidence
		benign     []Evidence
	)
	for _, e := range live {
		switch {
		case e.Category == "" && e.Kind == KindLocal:
			// Local context — first-seen, volume. Never decides a verdict.
		case e.Kind == KindOperator && e.Category == categoryAllowed:
			benign = append(benign, e)
		case e.Kind == KindFeed || e.Kind == KindOperator:
			curated = append(curated, e)
		case e.Kind == KindProvider:
			provider = append(provider, e)
		case e.Kind == KindDetector:
			inferences = append(inferences, e)
		}
	}

	var supporting []Evidence
	switch {
	case len(benign) > 0:
		a.Verdict, supporting = VerdictBenign, benign
	case len(curated) > 0:
		a.Verdict, supporting = VerdictMalicious, curated
		supporting = append(supporting, provider...)
	case len(provider) > 0:
		a.Verdict, supporting = VerdictMalicious, provider
	case len(inferences) > 0:
		a.Verdict, supporting = VerdictSuspicious, inferences
		a.InferenceOnly = true
	default:
		a.Summary = "Seen locally, but no source has anything to say about it."
		return a
	}

	a.Confidence = strongest(supporting)
	a.Sources = distinctSources(supporting)
	a.Corroborated = len(a.Sources) > 1
	a.Categories = categoriesByCitation(supporting)
	a.Summary = summarise(a)
	return a
}

// categoryAllowed marks an operator's allow-list entry.
const categoryAllowed = "allowed"

// strongest returns the highest confidence present. Not an average: see the
// note on Assessment.Confidence.
func strongest(es []Evidence) Confidence {
	best := ConfidenceLow
	for _, e := range es {
		if e.Confidence.Rank() > best.Rank() {
			best = e.Confidence
		}
	}
	return best
}

// distinctSources lists the distinct sources, in first-seen order so the
// output is stable for a given input.
func distinctSources(es []Evidence) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(es))
	for _, e := range es {
		name := e.SourceName
		if name == "" {
			name = e.Source
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// categoriesByCitation orders categories by how many sources named them, then
// alphabetically so equal counts do not reorder between calls.
func categoriesByCitation(es []Evidence) []string {
	counts := map[string]int{}
	for _, e := range es {
		if e.Category != "" {
			counts[e.Category]++
		}
	}
	out := make([]string, 0, len(counts))
	for c := range counts {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if counts[out[i]] != counts[out[j]] {
			return counts[out[i]] > counts[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// sortEvidence orders strongest-and-most-recent first, so a reader sees the
// load-bearing rows without scrolling.
func sortEvidence(es []Evidence) {
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].Confidence.Rank() != es[j].Confidence.Rank() {
			return es[i].Confidence.Rank() > es[j].Confidence.Rank()
		}
		return es[i].ObservedAt.After(es[j].ObservedAt)
	})
}

// summarise writes the one-sentence conclusion.
//
// The wording is load-bearing. An inference-only verdict says "behaviour
// consistent with", never "is": the difference between those two phrasings is
// the difference between a defensible statement and a claim the evidence does
// not support.
func summarise(a Assessment) string {
	var b strings.Builder
	switch a.Verdict {
	case VerdictBenign:
		b.WriteString("Explicitly allowed by an operator decision")
	case VerdictMalicious:
		if len(a.Categories) > 0 {
			b.WriteString("Listed as " + a.Categories[0])
		} else {
			b.WriteString("Listed as malicious")
		}
	case VerdictSuspicious:
		b.WriteString("Behaviour consistent with a concern")
		if len(a.Categories) > 0 {
			b.Reset()
			b.WriteString("Behaviour consistent with " + a.Categories[0])
		}
	default:
		return "Nothing on file for this subject."
	}

	switch {
	case a.Corroborated:
		b.WriteString(" by " + plural(len(a.Sources), "independent source", "independent sources"))
	case len(a.Sources) == 1:
		b.WriteString(" by " + a.Sources[0])
	}

	if a.InferenceOnly {
		b.WriteString(". This is inferred from traffic, not a curated listing")
	}
	b.WriteString(".")
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

// itoa avoids pulling strconv in for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
