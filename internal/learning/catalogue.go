package learning

import "github.com/jameshoulder/dnsdaddy/internal/detect"

// CatalogueInfo lets the existing findings catalogue describe the separate
// fitted runtime without pretending it is one of the six fixed heuristics.
func CatalogueInfo() detect.DetectorInfo {
	return detect.DetectorInfo{
		Name: Algorithm, EventType: EventType, Title: "Local learned baseline",
		Description: "Fits per-client window means and variances from permitted local DNS traffic, then reports changes from that prior baseline. Scores describe unusualness, not maliciousness probability.",
		Maturity:    detect.MaturityExperimental, MaxSeverity: detect.SeverityLow, Window: "5 minutes by default; at least 12 eligible windows and one hour of history before scoring",
		MITRE: []detect.Technique{}, SignalNames: append([]string{}, featureNames[:]...),
		FalsePositives: []string{"New applications or legitimate nonce services", "CDN and endpoint-security telemetry", "Address reassignment or aggregated clients behind NAT"}, Enforces: false,
	}
}
