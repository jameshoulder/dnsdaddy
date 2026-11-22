package main

import (
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/diag"
)

func TestSanitizeDoctorChecksOmitsFreeFormFields(t *testing.T) {
	checks := []diag.Check{{
		Section:  diag.SectionUpstream,
		Name:     "https://dns.example/dns-query?token=secret",
		Status:   diag.StatusFail,
		Summary:  "Upstream https://dns.example/dns-query?token=secret failed",
		Evidence: []string{"spec: https://dns.example/dns-query?token=secret"},
		Action:   "check token",
	}}
	out := sanitizeDoctorChecks(checks)
	if len(out) != 1 {
		t.Fatalf("len=%d", len(out))
	}
	raw := out[0].Section + out[0].CheckID + out[0].Status
	if strings.Contains(raw, "token") || strings.Contains(raw, "https://") {
		t.Fatalf("leaked free-form content: %+v", out[0])
	}
	if out[0].Status != string(diag.StatusFail) || out[0].Section != diag.SectionUpstream {
		t.Fatalf("unexpected row: %+v", out[0])
	}
	if len(out[0].CheckID) != 16 {
		t.Fatalf("checkId=%q", out[0].CheckID)
	}
}
