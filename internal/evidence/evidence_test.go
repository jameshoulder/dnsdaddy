package evidence

import (
	"strings"
	"testing"
	"time"
)

func at(mins int) time.Time {
	return time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC).Add(time.Duration(mins) * time.Minute)
}

func ev(kind Kind, source, claim, category string, conf Confidence, observed int) Evidence {
	return Evidence{
		ID: source + ":" + claim, Subject: Domain("evil.example"),
		Kind: kind, Source: source, SourceName: source, Claim: claim,
		Category: category, Confidence: conf, ObservedAt: at(observed),
	}
}

// A domain is one subject however it was spelled. Without this the same name
// produces separate rows and an investigation view shows half the evidence.
func TestDomainSubjectsAreNormalised(t *testing.T) {
	for _, in := range []string{"Evil.Example", "evil.example.", "  EVIL.EXAMPLE.  ", "evil.example"} {
		if got := Domain(in).Value; got != "evil.example" {
			t.Errorf("Domain(%q) = %q", in, got)
		}
	}
	// The subject key separates types, so an address and a domain that happen
	// to spell the same never merge.
	if Domain("1.2.3.4").Key() == IP("1.2.3.4").Key() {
		t.Error("a domain and an address with the same value share a key")
	}
}

// Confidence must not be arithmetic. This is the design decision the whole
// package rests on, so it is pinned rather than left to convention.
func TestConfidenceIsOrderedButNotNumeric(t *testing.T) {
	if ConfidenceLow.Rank() >= ConfidenceMedium.Rank() ||
		ConfidenceMedium.Rank() >= ConfidenceHigh.Rank() {
		t.Fatal("confidence does not order low < medium < high")
	}
	if Confidence("very-high").Valid() {
		t.Error("an invented confidence was accepted")
	}
}

func TestValidationRejectsUnusableEvidence(t *testing.T) {
	good := ev(KindFeed, "f_urlhaus", "listed as a malicious host", "malware", ConfidenceHigh, 0)
	if err := good.Validate(); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Evidence){
		"no subject value": func(e *Evidence) { e.Subject.Value = "" },
		"bad subject type": func(e *Evidence) { e.Subject.Type = "planet" },
		"bad kind":         func(e *Evidence) { e.Kind = "rumour" },
		"no source":        func(e *Evidence) { e.Source = "" },
		"no claim":         func(e *Evidence) { e.Claim = "" },
		"bad confidence":   func(e *Evidence) { e.Confidence = "certain" },
		"no observed time": func(e *Evidence) { e.ObservedAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			e := good
			mutate(&e)
			if err := e.Validate(); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestExpiry(t *testing.T) {
	e := ev(KindFeed, "f", "listed", "malware", ConfidenceHigh, 0)
	if e.Expired(at(9999)) {
		t.Error("evidence with no expiry expired")
	}
	exp := at(10)
	e.ExpiresAt = &exp
	if e.Expired(at(9)) {
		t.Error("expired early")
	}
	if !e.Expired(at(10)) {
		t.Error("did not expire at its expiry")
	}
}

/* ---------- assessment --------------------------------------------------- */

// Nothing on file is a real answer, and it must not read as "clean".
func TestNoEvidenceIsUnknownNotBenign(t *testing.T) {
	a := Assess(Domain("nothing.example"), nil, at(0))
	if a.Verdict != VerdictUnknown {
		t.Errorf("verdict = %q, want unknown", a.Verdict)
	}
	if strings.Contains(strings.ToLower(a.Summary), "safe") ||
		strings.Contains(strings.ToLower(a.Summary), "benign") {
		t.Errorf("an absence of evidence reads as an assurance: %q", a.Summary)
	}
}

// The corroboration rule from the brief's §14: two sources agreeing is
// reported as two sources agreeing, never as a higher confidence.
func TestCorroborationDoesNotRaiseConfidence(t *testing.T) {
	one := Assess(Domain("evil.example"), []Evidence{
		ev(KindFeed, "f_a", "listed as malware infrastructure", "malware", ConfidenceMedium, 0),
	}, at(1))
	two := Assess(Domain("evil.example"), []Evidence{
		ev(KindFeed, "f_a", "listed as malware infrastructure", "malware", ConfidenceMedium, 0),
		ev(KindFeed, "f_b", "known malicious host", "malware", ConfidenceMedium, 0),
	}, at(1))

	if one.Confidence != ConfidenceMedium || two.Confidence != ConfidenceMedium {
		t.Fatalf("confidence changed with corroboration: %q then %q", one.Confidence, two.Confidence)
	}
	if one.Corroborated {
		t.Error("a single source reported itself as corroborated")
	}
	if !two.Corroborated {
		t.Error("two independent sources were not reported as corroborating")
	}
	if len(two.Sources) != 2 {
		t.Errorf("sources = %v, want both named", two.Sources)
	}
	if !strings.Contains(two.Summary, "2 independent sources") {
		t.Errorf("the summary does not say how many sources agree: %q", two.Summary)
	}
}

// One source listing a domain twice is one source, not corroboration. This is
// the specific way a naive count is wrong.
func TestRepeatedClaimsFromOneSourceAreNotCorroboration(t *testing.T) {
	a := Assess(Domain("evil.example"), []Evidence{
		ev(KindFeed, "f_a", "listed as malware infrastructure", "malware", ConfidenceHigh, 0),
		ev(KindFeed, "f_a", "listed again under another category", "phishing", ConfidenceHigh, 1),
	}, at(2))
	if a.Corroborated {
		t.Error("one source citing itself twice was reported as corroboration")
	}
	if len(a.Sources) != 1 {
		t.Errorf("sources = %v, want one", a.Sources)
	}
}

// A curated listing and a heuristic are different kinds of claim and must not
// produce the same wording.
func TestInferenceOnlyIsWordedAsInference(t *testing.T) {
	inferred := Assess(Domain("odd.example"), []Evidence{
		ev(KindDetector, "dga_like", "behaviour consistent with algorithmically generated domains", "dga", ConfidenceMedium, 0),
	}, at(1))
	if inferred.Verdict != VerdictSuspicious {
		t.Errorf("verdict = %q, want suspicious", inferred.Verdict)
	}
	if !inferred.InferenceOnly {
		t.Error("a detector-only assessment did not flag itself as inference")
	}
	if !strings.Contains(inferred.Summary, "inferred from traffic") {
		t.Errorf("summary does not say it is inferred: %q", inferred.Summary)
	}
	if strings.Contains(inferred.Summary, "Listed as") {
		t.Errorf("an inference is worded as a listing: %q", inferred.Summary)
	}

	// A curated listing outranks any number of inferences.
	curated := Assess(Domain("odd.example"), []Evidence{
		ev(KindDetector, "dga_like", "behaviour consistent with DGA", "dga", ConfidenceMedium, 0),
		ev(KindDetector, "nxdomain_anomaly", "unusual failure rate", "", ConfidenceMedium, 1),
		ev(KindFeed, "f_urlhaus", "listed as a malicious host", "malware", ConfidenceHigh, 2),
	}, at(3))
	if curated.Verdict != VerdictMalicious {
		t.Errorf("verdict = %q, want malicious", curated.Verdict)
	}
	if curated.InferenceOnly {
		t.Error("an assessment backed by a curated listing claimed to be inference-only")
	}
}

// An operator's allow decision beats every source. It is the one claim a human
// made deliberately about this network.
func TestAnOperatorAllowBeatsEverything(t *testing.T) {
	a := Assess(Domain("internal.corp"), []Evidence{
		ev(KindFeed, "f_a", "listed as malware infrastructure", "malware", ConfidenceHigh, 0),
		ev(KindOperator, "operator", "allow-listed by an operator", "allowed", ConfidenceHigh, 1),
	}, at(2))
	if a.Verdict != VerdictBenign {
		t.Errorf("verdict = %q, want benign", a.Verdict)
	}
}

// Expired evidence is excluded, not discounted. A claim past its own expiry is
// one the source no longer stands behind.
func TestExpiredEvidenceIsExcludedFromTheAssessment(t *testing.T) {
	exp := at(5)
	stale := ev(KindFeed, "f_a", "listed as malware infrastructure", "malware", ConfidenceHigh, 0)
	stale.ExpiresAt = &exp

	a := Assess(Domain("was-bad.example"), []Evidence{stale}, at(6))
	if a.Verdict != VerdictUnknown {
		t.Errorf("verdict = %q, want unknown once the listing expired", a.Verdict)
	}
	if len(a.Evidence) != 0 {
		t.Errorf("expired evidence was carried into the assessment: %+v", a.Evidence)
	}

	// And before expiry it counts.
	if b := Assess(Domain("was-bad.example"), []Evidence{stale}, at(4)); b.Verdict != VerdictMalicious {
		t.Errorf("verdict before expiry = %q, want malicious", b.Verdict)
	}
}

// Local observations are context, never a verdict. "First seen four minutes
// ago" must not make a domain suspicious on its own.
func TestLocalObservationsDoNotProduceAVerdict(t *testing.T) {
	a := Assess(Domain("new.example"), []Evidence{
		ev(KindLocal, "first_seen", "first seen on this network 4 minutes ago", "", ConfidenceHigh, 0),
	}, at(1))
	if a.Verdict != VerdictUnknown {
		t.Errorf("verdict = %q, want unknown — a new domain is not a suspicious one", a.Verdict)
	}
	// It is still shown, because it is useful context.
	if len(a.Evidence) != 1 {
		t.Error("the local observation was dropped rather than shown as context")
	}
}

// The assessment must be reproducible: the same input yields the same output,
// including the order of everything a reader would compare between two runs.
func TestAssessmentIsDeterministic(t *testing.T) {
	in := []Evidence{
		ev(KindFeed, "f_b", "known malicious host", "phishing", ConfidenceHigh, 1),
		ev(KindFeed, "f_a", "listed as malware infrastructure", "malware", ConfidenceHigh, 0),
		ev(KindProvider, "p_vt", "flagged by 9 engines", "malware", ConfidenceMedium, 2),
	}
	first := Assess(Domain("evil.example"), in, at(3))
	for i := 0; i < 20; i++ {
		got := Assess(Domain("evil.example"), in, at(3))
		if got.Summary != first.Summary ||
			strings.Join(got.Categories, ",") != strings.Join(first.Categories, ",") ||
			strings.Join(got.Sources, ",") != strings.Join(first.Sources, ",") {
			t.Fatalf("assessment differs between runs:\n %+v\n %+v", first, got)
		}
	}
	// malware is cited twice, phishing once, so malware leads.
	if len(first.Categories) == 0 || first.Categories[0] != "malware" {
		t.Errorf("categories = %v, want the most-cited first", first.Categories)
	}
}
