package evidence

import (
	"reflect"
	"testing"
)

// TestSecurityDistinctSourcesDisambiguatesSameDisplayName checks that
// different stable source IDs stay independently identifiable in the UI.
func TestSecurityDistinctSourcesDisambiguatesSameDisplayName(t *testing.T) {
	evidence := []Evidence{
		{Source: "feed_a", SourceName: "Shared feed"},
		{Source: "feed_b", SourceName: "Shared feed"},
	}
	want := []string{"Shared feed (feed_a)", "Shared feed (feed_b)"}
	if got := distinctSources(evidence); !reflect.DeepEqual(got, want) {
		t.Fatalf("distinctSources = %v, want %v", got, want)
	}
}

// TestSecurityDistinctSourcesKeepsUniqueNames checks that unambiguous names
// are displayed without unnecessary identifiers.
func TestSecurityDistinctSourcesKeepsUniqueNames(t *testing.T) {
	evidence := []Evidence{
		{Source: "feed_a", SourceName: "First feed"},
		{Source: "feed_b", SourceName: "Second feed"},
	}
	want := []string{"First feed", "Second feed"}
	if got := distinctSources(evidence); !reflect.DeepEqual(got, want) {
		t.Fatalf("distinctSources = %v, want %v", got, want)
	}
}

// TestSecurityDistinctSourcesDeduplicatesRenamedFeed verifies that historical
// display-name changes do not increase independent-source counts.
func TestSecurityDistinctSourcesDeduplicatesRenamedFeed(t *testing.T) {
	evidence := []Evidence{
		{Source: "feed_a", SourceName: "Old name"},
		{Source: "feed_a", SourceName: "New name"},
	}
	want := []string{"Old name"}
	if got := distinctSources(evidence); !reflect.DeepEqual(got, want) {
		t.Fatalf("distinctSources = %v, want %v", got, want)
	}
}
