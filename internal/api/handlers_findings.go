package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// findingResponse is one finding as the API returns it.
//
// Detail is the complete finding document, passed through as raw JSON rather
// than decoded and re-encoded. That keeps one thing true that matters for
// integrations: what a consumer reads here is byte-for-byte what the detection
// engine produced, including any field this binary does not know about.
type findingResponse struct {
	ID         string          `json:"id"`
	Time       time.Time       `json:"time"`
	EventType  string          `json:"eventType"`
	Severity   string          `json:"severity"`
	Confidence float64         `json:"confidence"`
	Score      float64         `json:"score"`
	ClientIP   string          `json:"clientIp,omitempty"`
	ClientName string          `json:"clientName,omitempty"`
	NetworkID  string          `json:"networkId,omitempty"`
	Domain     string          `json:"domain,omitempty"`
	QType      string          `json:"qtype,omitempty"`
	Detector   string          `json:"detector"`
	Title      string          `json:"title"`
	Summary    string          `json:"summary"`
	Detail     json.RawMessage `json:"detail,omitempty"`
}

func toFindingResponse(f store.Finding, includeDetail bool) findingResponse {
	r := findingResponse{
		ID:         f.ID,
		Time:       f.Time,
		EventType:  f.EventType,
		Severity:   f.Severity,
		Confidence: f.Confidence,
		Score:      f.Score,
		ClientIP:   f.ClientIP,
		ClientName: f.ClientName,
		NetworkID:  f.NetworkID,
		Domain:     f.Domain,
		QType:      f.QType,
		Detector:   f.Detector,
		Title:      f.Title,
		Summary:    f.Summary,
	}
	if includeDetail && json.Valid([]byte(f.Detail)) {
		r.Detail = json.RawMessage(f.Detail)
	}
	return r
}

// handleListFindings returns recent behavioural findings.
//
// GET /api/v1/findings?severity=&type=&client=&domain=&hours=&limit=&detail=
func (a *API) handleListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := store.FindingFilter{
		Severity:  strings.ToLower(strings.TrimSpace(q.Get("severity"))),
		EventType: strings.TrimSpace(q.Get("type")),
		ClientIP:  strings.TrimSpace(q.Get("client")),
		Domain:    strings.TrimSpace(q.Get("domain")),
		Limit:     boundedParam(q.Get("limit"), 100, 1, 1000),
	}
	if filter.Severity != "" {
		if _, ok := detect.ParseSeverity(filter.Severity); !ok {
			writeError(w, http.StatusBadRequest, "severity must be info, low, medium, or high")
			return
		}
	}
	if hours := boundedParam(q.Get("hours"), 0, 1, 24*365); hours > 0 {
		filter.Since = time.Now().Add(-time.Duration(hours) * time.Hour)
	}

	findings, err := a.Store.ListFindings(r.Context(), filter)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	// Detail is opt-in: a finding document is a few kilobytes, and a list of
	// a hundred of them is not what a dashboard table needs.
	includeDetail := q.Get("detail") == "true"

	out := make([]findingResponse, 0, len(findings))
	for _, f := range findings {
		out = append(out, toFindingResponse(f, includeDetail))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"findings": out,
		"count":    len(out),
		// Restated on every response so a consumer never has to infer it:
		// nothing in this list caused anything to be blocked.
		"enforcement": "none",
	})
}

// handleGetFinding returns one finding with its full detail.
//
// GET /api/v1/findings/{id}
func (a *API) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	f, err := a.Store.GetFinding(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toFindingResponse(f, true))
}

// handleExportFindings streams findings as newline-delimited JSON.
//
// GET /api/v1/findings/export?hours=&severity=&limit=
//
// NDJSON rather than a JSON array, because that is what every log shipper and
// SIEM ingest pipeline already understands, and because a consumer can process
// it a record at a time instead of buffering the whole response. See
// docs/siem.md.
func (a *API) handleExportFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := store.FindingFilter{
		Severity:  strings.ToLower(strings.TrimSpace(q.Get("severity"))),
		EventType: strings.TrimSpace(q.Get("type")),
		Limit:     boundedParam(q.Get("limit"), 1000, 1, 1000),
	}
	if filter.Severity != "" {
		if _, ok := detect.ParseSeverity(filter.Severity); !ok {
			writeError(w, http.StatusBadRequest, "severity must be info, low, medium, or high")
			return
		}
	}
	if hours := boundedParam(q.Get("hours"), 24, 1, 24*365); hours > 0 {
		filter.Since = time.Now().Add(-time.Duration(hours) * time.Hour)
	}

	findings, err := a.Store.ListFindings(r.Context(), filter)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	// Oldest first, so a consumer appending to its own store keeps time order.
	for i := len(findings) - 1; i >= 0; i-- {
		f := findings[i]
		line := f.Detail
		if !json.Valid([]byte(line)) {
			// Should not happen — detail is written by the engine — but a
			// malformed row must not corrupt the whole stream for a consumer
			// parsing line by line.
			continue
		}
		if _, err := w.Write([]byte(line)); err != nil {
			return
		}
		if _, err := w.Write([]byte("\n")); err != nil {
			return
		}
	}
}

// handleDetectors returns the detector catalogue.
//
// GET /api/v1/detectors
//
// This endpoint exists so that what the software claims about its own
// detection capability comes from the running code rather than from a
// document somebody remembered to update. Each entry states its maturity, its
// signals, its known false positives, its ATT&CK mappings, and whether it can
// enforce anything — which, for every behavioural detector, is no.
func (a *API) handleDetectors(w http.ResponseWriter, r *http.Request) {
	enabled := a.Detector != nil

	resp := map[string]any{
		"enabled":     enabled,
		"enforcement": "none",
		"description": "Behavioural detectors observe, score and explain. They never block. " +
			"Blocking is done by the reputation and policy engine, which is driven by curated " +
			"threat intelligence rather than inference.",
		"schemaVersion": detect.SchemaVersion,
		"detectors":     a.Detector.Catalogue(),
	}
	if !enabled {
		resp["detectors"] = []detect.DetectorInfo{}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleFindingsSummary returns finding counts by type and severity.
//
// GET /api/v1/findings/summary?days=
func (a *API) handleFindingsSummary(w http.ResponseWriter, r *http.Request) {
	days := boundedParam(r.URL.Query().Get("days"), 7, 1, 365)
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	summary, err := a.Store.SummariseFindings(r.Context(), since)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if summary == nil {
		summary = []store.FindingSummary{}
	}

	var total int64
	for _, s := range summary {
		total += s.Count
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"days":    days,
		"total":   total,
		"byType":  summary,
		"enabled": a.Detector != nil,
	})
}

// boundedParam parses an integer query parameter and clamps it into a range.
//
// Clamping rather than rejecting: an operator who asks for 10,000 findings
// wants as many as they can have, and a 400 in the middle of an investigation
// helps nobody. Bounds still matter — an unbounded limit is a way to make the
// server allocate a great deal of memory from one request.
func boundedParam(raw string, def, min, max int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// detectionStatsLines renders detection engine counters for /metrics.
func detectionStatsLines(e *detect.Engine) []string {
	if e == nil {
		return nil
	}
	s := e.Stats()
	lines := []string{
		fmt.Sprintf("dnsdaddy_detection_observations_total %d", s.Observed),
		fmt.Sprintf("dnsdaddy_detection_dropped_total %d", s.Dropped),
		fmt.Sprintf("dnsdaddy_detection_excluded_total %d", s.Excluded),
		fmt.Sprintf("dnsdaddy_detection_suppressed_total %d", s.Suppressed),
		fmt.Sprintf("dnsdaddy_detection_findings_total %d", s.Emitted),
		fmt.Sprintf("dnsdaddy_detection_tracked_keys %d", s.Tracked),
	}
	return lines
}
