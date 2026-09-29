package config

import "testing"

func TestOriginalDecisionEvidenceDefaultsOnWithAnExplicitOptOut(t *testing.T) {
	cfg := Default()
	if !cfg.Log.DecisionRecords {
		t.Fatal("a default installation cannot retain original decision evidence")
	}
	if err := unmarshalYAML([]byte("log:\n  decision_records: false\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Log.DecisionRecords {
		t.Fatal("an explicit privacy opt-out was overwritten by the default")
	}
}
