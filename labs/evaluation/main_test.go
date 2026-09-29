package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckedInEvaluationIsChronologicalAndPreservesItsLimitations(t *testing.T) {
	var manifest struct {
		Checksums map[string]string `json:"checksumsSha256"`
	}
	data, err := os.ReadFile("data/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Mkdir(filepath.Join(dir, "data"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"training.ndjson", "heldout.ndjson"} {
		data, err = os.ReadFile(filepath.Join("data", name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != manifest.Checksums[name] {
			t.Fatalf("%s differs from its dataset manifest", name)
		}
		if err = os.WriteFile(filepath.Join(dir, "data", name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err = run(dir, false); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r report
	if err = json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if r.TrainingWindows != 96 || r.TrainingQueries != 5760 || r.Learned.Windows != 64 || r.HeldOutQueries != 3840 || r.HeldOutStart.Before(r.TrainingEnd) {
		t.Fatalf("population or chronology changed: %+v", r)
	}
	if r.ColdStart.Scored != 0 || r.ColdStart.RecallScored != nil {
		t.Fatal("cold start fabricated predictions")
	}
	if r.Learned.Windows != r.Learned.TP+r.Learned.FP+r.Learned.TN+r.Learned.FN+r.Learned.AbstainedBenign+r.Learned.AbstainedMalicious {
		t.Fatal("outcome denominators do not reconcile")
	}
	// Preserve the adversarial/benign overlap cases instead of quietly
	// dropping inconvenient windows to improve a headline accuracy figure.
	if r.Learned.FP == 0 || r.Learned.FN == 0 || r.Learned.AbstainedMalicious == 0 {
		t.Fatal("the deliberately difficult coverage cases disappeared")
	}
}
