package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func getIntelligence(t *testing.T, h *harness, domain string) (int, intelligenceResponse) {
	t.Helper()
	resp, body := h.do(http.MethodGet, "/api/v1/intelligence?domain="+domain, nil)
	var out intelligenceResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decoding response: %v (body %s)", err, body)
		}
	}
	return resp.StatusCode, out
}

func TestIntelligenceReportsCorroboratingSources(t *testing.T) {
	h := newHarness(t)
	h.login()

	status, got := getIntelligence(t, h, "corroborated.example")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !got.Listed {
		t.Fatal("listed = false, want true")
	}
	if got.IndependentSources != 2 {
		t.Errorf("independentSources = %d, want 2", got.IndependentSources)
	}
	if len(got.Sources) != 2 {
		t.Fatalf("returned %d sources, want 2: %+v", len(got.Sources), got.Sources)
	}

	// Exactly one source decides the block reason, and it is the first claim.
	deciding := 0
	for _, s := range got.Sources {
		if s.Deciding {
			deciding++
		}
	}
	if deciding != 1 {
		t.Errorf("%d sources marked deciding, want exactly 1", deciding)
	}
	if !got.Sources[0].Deciding {
		t.Error("the deciding source is not listed first")
	}
	if got.Category != "malware" {
		t.Errorf("category = %q, want malware (the first claim)", got.Category)
	}
	if !strings.Contains(got.Assessment, "Two independent") {
		t.Errorf("assessment did not report corroboration: %q", got.Assessment)
	}
}

func TestIntelligenceReportsASingleSourceAsALead(t *testing.T) {
	h := newHarness(t)
	h.login()

	status, got := getIntelligence(t, h, "evil.com")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.IndependentSources != 1 {
		t.Errorf("independentSources = %d, want 1", got.IndependentSources)
	}
	// The wording matters as much as the count: one list is a lead, and
	// stating it as more than that is the overclaim this product avoids.
	if !strings.Contains(got.Assessment, "lead") {
		t.Errorf("a single source was not framed as a lead: %q", got.Assessment)
	}
}

// Blocking a child because its parent is listed is correct; reporting the
// child as though it were itself on a feed is not.
func TestIntelligenceAttributesAListingToTheParent(t *testing.T) {
	h := newHarness(t)
	h.login()

	status, got := getIntelligence(t, h, "login.evil.com")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !got.Listed {
		t.Fatal("listed = false, want true — a child of a listed parent is covered")
	}
	if got.MatchedName != "evil.com" {
		t.Errorf("matchedName = %q, want evil.com", got.MatchedName)
	}
	if !strings.Contains(got.Assessment, "parent name evil.com") {
		t.Errorf("assessment did not explain the parent match: %q", got.Assessment)
	}
}

// An unlisted name must not be reported as safe. DNS Daddy knows only what the
// enabled feeds contain, and saying otherwise is the overclaim that turns a
// blocklist into a false guarantee.
func TestIntelligenceDoesNotCallAnUnlistedDomainSafe(t *testing.T) {
	h := newHarness(t)
	h.login()

	status, got := getIntelligence(t, h, "harmless.example")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Listed {
		t.Error("listed = true for an unindexed domain")
	}
	if got.IndependentSources != 0 || len(got.Sources) != 0 {
		t.Errorf("unlisted domain reported sources: %+v", got.Sources)
	}
	if !strings.Contains(got.Assessment, "absence of evidence") {
		t.Errorf("assessment implied safety rather than ignorance: %q", got.Assessment)
	}
}

func TestIntelligenceRejectsBadInput(t *testing.T) {
	h := newHarness(t)
	h.login()

	for _, tc := range []struct{ name, domain string }{
		{"empty", ""},
		{"not a name", "not%20a%20domain!!"},
		{"overlong", strings.Repeat("a", 600)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := h.do(http.MethodGet, "/api/v1/intelligence?domain="+tc.domain, nil)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestIntelligenceRequiresAuthentication(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(http.MethodGet, "/api/v1/intelligence?domain=evil.com", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// Name analysis is reported for every name, listed or not. An unlisted name is
// precisely the case where how the name looks is the only evidence there is.
func TestIntelligenceIncludesNameAnalysisForUnlistedNames(t *testing.T) {
	h := newHarness(t)
	h.login()

	status, got := getIntelligence(t, h, "kq3v9z7x2m1p8w4t.example")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Listed {
		t.Fatal("listed = true, want false")
	}
	if got.NameAnalysis.Score <= 0 {
		t.Errorf("nameAnalysis.score = %.1f, want a positive score for a "+
			"random-looking name", got.NameAnalysis.Score)
	}
	if len(got.NameAnalysis.Signals) == 0 {
		t.Error("nameAnalysis returned no signals")
	}
	// The arithmetic has to be checkable by hand from what is returned.
	for _, s := range got.NameAnalysis.Signals {
		if s.Weight == 0 {
			t.Errorf("signal %q published no weight", s.Name)
		}
		want := s.Normalised * s.Weight
		if diff := s.Contribution - want; diff > 1e-9 || diff < -1e-9 {
			t.Errorf("signal %q: contribution %.6f != normalised %.6f x weight %.6f",
				s.Name, s.Contribution, s.Normalised, s.Weight)
		}
	}
	if len(got.NameAnalysis.Limitations) == 0 {
		t.Error("nameAnalysis stated no limitations")
	}
}

func TestIntelligenceNameAnalysisStaysQuietOnOrdinaryNames(t *testing.T) {
	h := newHarness(t)
	h.login()

	status, got := getIntelligence(t, h, "www.microsoft.com")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.NameAnalysis.Score != 0 {
		t.Errorf("nameAnalysis.score = %.1f for ordinary traffic, want 0",
			got.NameAnalysis.Score)
	}
	if !strings.Contains(got.NameAnalysis.Summary, "not evidence that the domain is safe") {
		t.Errorf("a quiet result implied safety: %q", got.NameAnalysis.Summary)
	}
}
