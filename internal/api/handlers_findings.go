package api

import (
	"context"
	"encoding/json"
	"errors"
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
	// Review is the operator's disposition, kept beside the detection rather
	// than inside it. Present on every row: an unreviewed finding carries
	// state "new" at version 0, which is what a writer passes back to claim
	// the first review.
	Review *store.FindingReview `json:"review,omitempty"`
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

// withReviews attaches each finding's review, or the implicit new one.
//
// One query for the page rather than one per row, and a read failure fails
// the request: a list that silently showed every finding as unreviewed would
// tell an operator their work was lost.
func (a *API) withReviews(ctx context.Context, rows []findingResponse) ([]findingResponse, error) {
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	reviews, err := a.Store.FindingReviews(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if r, ok := reviews[rows[i].ID]; ok {
			rv := r
			rows[i].Review = &rv
			continue
		}
		rows[i].Review = &store.FindingReview{FindingID: rows[i].ID, State: store.ReviewNew, Version: 0}
	}
	return rows, nil
}

// handleListFindings returns one page of behavioural findings.
//
// GET /api/v1/findings?severity=&type=&client=&domain=&hours=&limit=&detail=&cursor=
//
// Newest first. `nextCursor` in the response continues from the row after
// the last one returned; it is empty on the final page. The cursor is a
// keyset position rather than an offset, so a finding written while a
// consumer is paging neither repeats nor skips a row.
func (a *API) handleListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := store.FindingFilter{
		Severity:  strings.ToLower(strings.TrimSpace(q.Get("severity"))),
		EventType: strings.TrimSpace(q.Get("type")),
		ClientIP:  strings.TrimSpace(q.Get("client")),
		Domain:    strings.TrimSpace(q.Get("domain")),
		State:     strings.ToLower(strings.TrimSpace(q.Get("state"))),
		Limit:     boundedParam(q.Get("limit"), 100, 1, 1000),
		Cursor:    strings.TrimSpace(q.Get("cursor")),
	}
	if filter.Severity != "" {
		if _, ok := detect.ParseSeverity(filter.Severity); !ok {
			writeError(w, http.StatusBadRequest, "severity must be info, low, medium, or high")
			return
		}
	}
	if filter.State != "" && !store.ValidReviewState(filter.State) {
		writeError(w, http.StatusBadRequest, "state must be one of "+strings.Join(store.ReviewStates(), ", "))
		return
	}
	if hours := boundedParam(q.Get("hours"), 0, 1, 24*365); hours > 0 {
		filter.Since = time.Now().Add(-time.Duration(hours) * time.Hour)
	}

	findings, next, err := a.Store.ListFindings(r.Context(), filter)
	if err != nil {
		writeFindingsError(w, err)
		return
	}

	// Detail is opt-in: a finding document is a few kilobytes, and a list of
	// a hundred of them is not what a dashboard table needs.
	includeDetail := q.Get("detail") == "true"

	out := make([]findingResponse, 0, len(findings))
	for _, f := range findings {
		out = append(out, toFindingResponse(f, includeDetail))
	}
	if out, err = a.withReviews(r.Context(), out); err != nil {
		writeStoreError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"findings": out,
		"count":    len(out),
		"limit":    filter.Limit,
		// Empty when this was the last page. A consumer that stops on an
		// empty cursor has seen every matching finding; one that stops on a
		// short page has not necessarily, because a page is short whenever
		// the filter matched fewer rows than the limit.
		"nextCursor": next,
		// Restated on every response so a consumer never has to infer it:
		// nothing in this list caused anything to be blocked.
		"enforcement": "none",
	})
}

// writeFindingsError maps a findings-store error onto a status code.
//
// An unparseable cursor is the caller's error and is answered 400 with the
// reason, rather than as a silent restart from the top: a consumer that did
// not notice it had restarted would re-ingest every finding it already held.
func writeFindingsError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrInvalidCursor) {
		writeError(w, http.StatusBadRequest, "cursor is not one this server issued; omit it to start from the beginning")
		return
	}
	writeStoreError(w, err)
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
	rows, err := a.withReviews(r.Context(), []findingResponse{toFindingResponse(f, true)})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rows[0])
}

// reviewBody is the review write.
type reviewBody struct {
	State   string `json:"state"`
	Note    string `json:"note"`
	Version int64  `json:"version"`
}

// handleReviewFinding records an operator's disposition of a finding.
//
// PUT /api/v1/findings/{id}/review
//
// A PUT of the whole review, carrying the version the caller read. A
// version that is not the current one is answered 409 with the current
// review, so two operators cannot silently overwrite each other. The
// finding itself is never modified: the review sits beside it.
//
// What this does not do, stated here because the temptation is real: a
// false-positive disposition does not disable a detector, relax a policy,
// delete evidence or allow a domain. It records an assessment. Each of those
// other things has its own route, its own confirmation and its own reason to
// exist as a separate decision.
func (a *API) handleReviewFinding(w http.ResponseWriter, r *http.Request) {
	var body reviewBody
	if !decodeBody(w, r, &body) {
		return
	}
	p, _ := a.Auth.authenticate(r)
	in := store.ReviewInput{
		State:   strings.ToLower(strings.TrimSpace(body.State)),
		Note:    body.Note,
		Version: body.Version,
		Actor:   reviewActor(p),
	}
	review, err := a.Store.SetFindingReview(r.Context(), r.PathValue("id"), in)
	if err != nil {
		var stale *store.ErrStaleReview
		var bad *store.ErrReviewTransition
		switch {
		case errors.As(err, &stale):
			// 409 with the current state, so a dashboard can show what
			// changed rather than a bare failure.
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   err.Error(),
				"current": stale.Current,
			})
		case errors.As(err, &bad):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrReviewInvalid):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeStoreError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, review)
}

// reviewActor names the principal in the only terms the product has.
//
// A single admin password plus API tokens: there are no named users, and
// this does not invent one. A session is "session:admin"; a token is
// "token:<its name>". The session cookie itself is never written anywhere.
func reviewActor(p principal) string {
	if p.kind == "" {
		return ""
	}
	return p.kind + ":" + p.label
}

// handleFindingReviewHistory returns a finding's review changes, oldest
// first.
//
// GET /api/v1/findings/{id}/review/history
func (a *API) handleFindingReviewHistory(w http.ResponseWriter, r *http.Request) {
	events, err := a.Store.FindingReviewHistory(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findingId": r.PathValue("id"),
		"history":   events,
		// Application history: written by the same process into the same
		// database file as the findings. It explains what an operator did;
		// it is not tamper-proof evidence against a host administrator.
		"note": "application history, in write order; not tamper-evident",
	})
}

// Export continuation headers.
//
// NDJSON has no envelope to carry metadata in, and a trailer would be read by
// almost nothing, so the continuation travels in headers — set before the
// first byte of body, because the page is fetched whole before streaming.
const (
	// headerNextCursor names the position to pass as ?cursor= to continue.
	// Present only when more matching findings exist beyond this response.
	headerNextCursor = "X-Next-Cursor"
	// headerTruncated is "true" when the response stopped at its limit with
	// more matching findings remaining, and "false" when it is complete.
	// Stated explicitly so a 1,000-line export cannot be mistaken for the
	// whole of what matched.
	headerTruncated = "X-Truncated"
	// headerExportCount is how many lines the body carries.
	headerExportCount = "X-Export-Count"
)

// handleExportFindings streams findings as newline-delimited JSON.
//
// GET /api/v1/findings/export?hours=&severity=&type=&limit=&cursor=
//
// NDJSON rather than a JSON array, because that is what every log shipper and
// SIEM ingest pipeline already understands, and because a consumer can process
// it a record at a time instead of buffering the whole response. See
// docs/siem.md.
//
// Oldest first, and paged forward in time: the X-Next-Cursor header names the
// position after the last line, and passing it back continues from there. A
// consumer that keeps its last cursor between runs collects every finding
// exactly once, however many there are and however many the limit allows.
func (a *API) handleExportFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := store.FindingFilter{
		Severity:  strings.ToLower(strings.TrimSpace(q.Get("severity"))),
		EventType: strings.TrimSpace(q.Get("type")),
		Limit:     boundedParam(q.Get("limit"), 1000, 1, 1000),
		Cursor:    strings.TrimSpace(q.Get("cursor")),
		Ascending: true,
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

	findings, next, err := a.Store.ListFindings(r.Context(), filter)
	if err != nil {
		writeFindingsError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set(headerExportCount, strconv.Itoa(len(findings)))
	w.Header().Set(headerTruncated, strconv.FormatBool(next != ""))
	if next != "" {
		w.Header().Set(headerNextCursor, next)
	}
	w.WriteHeader(http.StatusOK)

	// Already oldest first: the store walked forward, so the cursor it
	// returned continues forward too.
	for _, f := range findings {
		line := f.Detail
		if !json.Valid([]byte(line)) {
			// Should not happen — detail is written by the engine — but a
			// malformed row must not corrupt the whole stream for a consumer
			// parsing line by line.
			continue
		}
		// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
		// NDJSON, not HTML. The body is written a record at a time rather than
		// marshalled as one array because that is the point of the format — a
		// consumer processes a line at a time instead of buffering everything.
		//
		// Each line was produced by encoding/json in the detection engine and
		// is re-checked with json.Valid above, so any domain name inside it is
		// already JSON-escaped. Running it through html/template would corrupt
		// the JSON rather than protect anyone. Content-Type is
		// application/x-ndjson with nosniff, so a browser cannot be talked into
		// reinterpreting it as markup.
		//
		// Consumers must still escape these values before rendering them: a
		// domain name in a finding is an attacker-chosen string, and a SIEM
		// dashboard that renders it as HTML has the problem this rule is about.
		// Documented in docs/threat-model.md (T17).
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
	byState, err := a.Store.ReviewStateCounts(r.Context(), since)
	if err != nil {
		writeStoreError(w, err)
		return
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
		// Review dispositions over the same period as byType, every state
		// present at zero. "new" counts findings nobody has reviewed as well
		// as those returned to new.
		"byState": byState,
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
