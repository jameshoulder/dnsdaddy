package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestBuildAgreesWithLaboratory(t *testing.T) {
	doc, err := Build(Options{Revision: "test", Now: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if doc.Summary.Scenarios == 0 {
		t.Fatal("expected scenarios")
	}
	if doc.Summary.Disagreed != 0 {
		t.Fatalf("laboratory disagreed on %d scenarios", doc.Summary.Disagreed)
	}
	if doc.Summary.Agreed != doc.Summary.Scenarios {
		t.Fatalf("agreed %d != scenarios %d", doc.Summary.Agreed, doc.Summary.Scenarios)
	}
	if !doc.Experimental {
		t.Fatal("report must mark experimental")
	}
	if len(doc.Milestone.Items) == 0 {
		t.Fatal("expected milestone checklist")
	}
	if doc.Summary.ByFamily["positive"] == 0 {
		t.Fatal("expected positive family coverage")
	}
}

func TestWriteMarkdownContainsGates(t *testing.T) {
	doc, err := Build(Options{Revision: "test", Now: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, doc); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# Daddybound laboratory conformance",
		"What this report does not claim",
		"Laboratory summary",
		"Milestone: DNS Daddy: Verified Trust",
		"VT-1.5",
		"make test-daddybound",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestWriteJSONRoundTripShape(t *testing.T) {
	doc, err := Build(Options{Revision: "test", Now: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, doc); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	s := buf.String()
	if !strings.Contains(s, `"experimental": true`) {
		t.Fatal("json missing experimental true")
	}
	if !strings.Contains(s, `"title": "Daddybound laboratory conformance"`) {
		t.Fatal("json missing title")
	}
}
