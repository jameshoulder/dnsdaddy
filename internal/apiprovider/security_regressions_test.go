package apiprovider

import (
	"strings"
	"testing"
)

// TestSecurityMaliciousVerdictBeatsHigherScoredSuspicious verifies explicit malicious dispositions outrank incomparable provider scores.
func TestSecurityMaliciousVerdictBeatsHigherScoredSuspicious(t *testing.T) {
	malicious := Verdict{Disposition: DispositionMalicious, Score: 0.1}
	suspicious := Verdict{Disposition: DispositionSuspicious, Score: 0.99}
	if !preferCachedVerdict(malicious, suspicious) {
		t.Fatal("explicit malicious verdict must override a higher scored suspicious one")
	}
	if preferCachedVerdict(suspicious, malicious) {
		t.Fatal("higher scored suspicious result must not replace a malicious verdict")
	}
}

// TestSecurityExcerptRedactsAcrossTruncationBoundary ensures partial credentials cannot leak at evidence truncation boundaries.
func TestSecurityExcerptRedactsAcrossTruncationBoundary(t *testing.T) {
	secret := "secret-crosses-excerpt-boundary"
	cfg := InstanceConfig{Secret: secret}
	response := &Response{Body: []byte(strings.Repeat("x", 1018) + secret + " tail")}
	text := cfg.SafeExcerpt(response, 1024)
	if strings.Contains(text, "secre") {
		t.Fatalf("excerpt leaked part of secret near byte 1024: %q", text)
	}
}
