package detect

import "testing"

func TestBehaviouralMappingCatalogueDoesNotClaimConfirmedAttack(t *testing.T) {
	for _, detector := range defaultDetectorsForTest() {
		for _, technique := range detector.Info().MITRE {
			if !technique.Hypothesis {
				t.Errorf("%s: %s must be an investigation hypothesis", detector.Name(), technique.ID)
			}
			if technique.Rationale == "" {
				t.Errorf("%s: missing rationale", technique.ID)
			}
		}
	}
}

func TestProducedFindingsDoNotClaimConfirmedAttack(t *testing.T) {
	for _, corpus := range allDetectorCorpora() {
		t.Run(corpus.name, func(t *testing.T) {
			findings := feed(corpus.detector, NewExclusions(nil, false), corpus.corpus, windowEnd(corpus.window))
			if len(findings) == 0 {
				t.Fatal("test corpus produced no findings")
			}
			for _, finding := range findings {
				for _, technique := range finding.MITRE {
					if !technique.Hypothesis {
						t.Errorf("%s: inferred behaviour must not be reported as established", technique.ID)
					}
				}
			}
		})
	}
}

func TestHypothesisDoesNotMutateTechniqueCatalogue(t *testing.T) {
	original := techAppLayerDNS
	copy := asHypothesis(original, "test rationale")
	if !copy.Hypothesis || copy.Rationale != "test rationale" {
		t.Fatal("hypothesis copy is incomplete")
	}
	if original.Hypothesis || original.Rationale != "" || techAppLayerDNS.Hypothesis || techAppLayerDNS.Rationale != "" {
		t.Fatal("catalogue was mutated")
	}
}
