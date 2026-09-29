package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// exportWalk carries the frozen window and insertion boundary, not an offset.
// It is an opaque pagination value, not an authorisation credential. Every
// request still passes the ordinary management API authentication checks.
type exportWalk struct {
	Dataset  string `json:"dataset"`
	Position string `json:"position"`
	Since    int64  `json:"since"`
	Until    int64  `json:"until"`
	MaxID    int64  `json:"maxId"`
	Filters  string `json:"filters"`
}

func exportFilterDigest(q url.Values) string {
	copyQ := url.Values{}
	for key, values := range q {
		if key != "cursor" && key != "limit" {
			copyQ[key] = values
		}
	}
	hash := sha256.Sum256([]byte(copyQ.Encode()))
	return hex.EncodeToString(hash[:])
}

func (a *API) exportWindow(r *http.Request, dataset string) (exportWalk, error) {
	q := r.URL.Query()
	digest := exportFilterDigest(q)
	if raw := q.Get("cursor"); raw != "" {
		if len(raw) > 4096 || !strings.HasPrefix(raw, "e1.") {
			return exportWalk{}, store.ErrInvalidCursor
		}
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, "e1."))
		if err != nil {
			return exportWalk{}, store.ErrInvalidCursor
		}
		var walk exportWalk
		if err := json.Unmarshal(decoded, &walk); err != nil || walk.Dataset != dataset || walk.Filters != digest ||
			walk.Position == "" || walk.Since < 0 || walk.Until <= 0 || walk.Since > walk.Until || walk.MaxID < 0 {
			return exportWalk{}, store.ErrInvalidCursor
		}
		return walk, nil
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	since, until, err := requestTimeWindow(q, now, 24)
	if err != nil {
		return exportWalk{}, err
	}
	if until.IsZero() {
		until = now
	}
	upper, err := a.Store.ExportHighWater(r.Context(), dataset)
	if err != nil {
		return exportWalk{}, err
	}
	walk := exportWalk{Dataset: dataset, Until: until.UnixMilli(), MaxID: upper, Filters: digest}
	if !since.IsZero() {
		walk.Since = since.UnixMilli()
	}
	return walk, nil
}

func (e exportWalk) sinceTime() time.Time {
	if e.Since == 0 {
		return time.Time{}
	}
	return time.UnixMilli(e.Since).UTC()
}

func (e exportWalk) untilTime() time.Time { return time.UnixMilli(e.Until).UTC() }

func (e exportWalk) next(position string) string {
	if position == "" {
		return ""
	}
	e.Position = position
	raw, _ := json.Marshal(e) // all fields have infallible JSON representations
	return "e1." + base64.RawURLEncoding.EncodeToString(raw)
}

var errExportInput = errors.New("invalid export filters")

// requestTimeWindow accepts absolute RFC 3339 bounds for repeatable reads.
// hours=0 means all retained data; when since is supplied it replaces the
// default hours. Explicit hours and since together are ambiguous and refused.
func requestTimeWindow(q url.Values, now time.Time, defaultHours int) (time.Time, time.Time, error) {
	var since, until time.Time
	parse := func(key string) (time.Time, error) {
		t, err := time.Parse(time.RFC3339Nano, q.Get(key))
		if err != nil || t.UnixMilli() < 0 {
			return time.Time{}, fmt.Errorf("%w: %s must be an RFC 3339 timestamp on or after 1970-01-01", errExportInput, key)
		}
		return t.UTC().Truncate(time.Millisecond), nil
	}
	if q.Get("since") != "" {
		if q.Get("hours") != "" {
			return since, until, fmt.Errorf("%w: use since or hours, not both", errExportInput)
		}
		var err error
		since, err = parse("since")
		if err != nil {
			return since, until, err
		}
	} else {
		hours := defaultHours
		if raw := q.Get("hours"); raw != "" {
			var err error
			hours, err = strconv.Atoi(raw)
			if err != nil || hours < 0 || hours > 24*365 {
				return since, until, fmt.Errorf("%w: hours must be between 0 and 8760", errExportInput)
			}
		}
		if hours > 0 {
			since = now.Add(-time.Duration(hours) * time.Hour).UTC().Truncate(time.Millisecond)
		}
	}
	if q.Get("until") != "" {
		var err error
		until, err = parse("until")
		if err != nil {
			return since, until, err
		}
	}
	upper := until
	if upper.IsZero() {
		upper = now
	}
	if !since.IsZero() && since.After(upper) {
		return since, until, fmt.Errorf("%w: since must not be after until", errExportInput)
	}
	return since, until, nil
}

func writeExportError(w http.ResponseWriter, err error) {
	if errors.Is(err, errExportInput) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if errors.Is(err, store.ErrInvalidCursor) {
		writeError(w, http.StatusBadRequest, "invalid cursor or changed filters; follow the previous Link header or start a new export")
		return
	}
	writeStoreError(w, err)
}

// writeExport prepares every line before committing headers. A corrupt stored
// finding is counted as skipped, never silently described as exported. JSON
// documents are compacted so a pretty-printed document is still ONE NDJSON line.
func writeExport(w http.ResponseWriter, r *http.Request, walk exportWalk, position string, documents [][]byte) {
	lines := make([][]byte, 0, len(documents))
	for _, document := range documents {
		var compact bytes.Buffer
		if json.Compact(&compact, document) == nil {
			lines = append(lines, append([]byte(nil), compact.Bytes()...))
		}
	}
	next := walk.next(position)
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(headerExportCount, strconv.Itoa(len(lines)))
	w.Header().Set("X-Export-Skipped", strconv.Itoa(len(documents)-len(lines)))
	w.Header().Set("X-Export-Scanned", strconv.Itoa(len(documents)))
	w.Header().Set(headerTruncated, strconv.FormatBool(next != ""))
	if walk.Since != 0 {
		w.Header().Set("X-Export-Since", walk.sinceTime().Format(time.RFC3339Nano))
	}
	w.Header().Set("X-Export-Until", walk.untilTime().Format(time.RFC3339Nano))
	w.Header().Set("X-Export-Snapshot", strconv.FormatInt(walk.MaxID, 10))
	if next != "" {
		w.Header().Set(headerNextCursor, next)
		query := r.URL.Query()
		query.Set("cursor", next)
		u := &url.URL{Path: r.URL.Path, RawQuery: query.Encode()}
		w.Header().Set("Link", "<"+u.String()+">; rel=\"next\"")
	}
	w.WriteHeader(http.StatusOK)
	for _, line := range lines {
		// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
		// Validated compact NDJSON served with nosniff, never HTML.
		if _, err := w.Write(append(line, '\n')); err != nil {
			return
		}
	}
}

func queryFilterFromRequest(r *http.Request) (store.QueryFilter, error) {
	q := r.URL.Query()
	client := q.Get("clientIp")
	if alias := q.Get("client"); alias != "" {
		if client != "" && alias != client {
			return store.QueryFilter{}, fmt.Errorf("%w: client and clientIp disagree", errExportInput)
		}
		client = alias
	}
	client, err := parseClientParam(client)
	if err != nil {
		return store.QueryFilter{}, fmt.Errorf("%w: %s", errExportInput, err)
	}
	f := store.QueryFilter{
		NetworkID: q.Get("networkId"), Action: q.Get("action"), Category: q.Get("category"),
		Domain: q.Get("domain"), ClientIP: client, Limit: boundedParam(q.Get("limit"), 100, 1, 500),
	}
	if raw := q.Get("exactDomain"); raw != "" {
		f.ExactDomain, err = domainutil.NormalizeInput(raw)
		if err != nil {
			return f, fmt.Errorf("%w: %s", errExportInput, err)
		}
	}
	return f, nil
}

func decisionFilterFromRequest(r *http.Request) (store.DecisionFilter, error) {
	q := r.URL.Query()
	client, err := parseClientParam(q.Get("client"))
	if err != nil {
		return store.DecisionFilter{}, fmt.Errorf("%w: %s", errExportInput, err)
	}
	f := store.DecisionFilter{ClientIP: client, Action: strings.TrimSpace(q.Get("action")), Limit: boundedParam(q.Get("limit"), 100, 1, 500)}
	if raw := q.Get("domain"); raw != "" {
		f.Subject, err = domainutil.NormalizeInput(raw)
		if err != nil {
			return f, fmt.Errorf("%w: %s", errExportInput, err)
		}
	}
	return f, nil
}

func (a *API) handleExportQueries(w http.ResponseWriter, r *http.Request) {
	f, err := queryFilterFromRequest(r)
	if err != nil {
		writeExportError(w, err)
		return
	}
	walk, err := a.exportWindow(r, "queries")
	if err != nil {
		writeExportError(w, err)
		return
	}
	if walk.Position != "" {
		f.Cursor, err = strconv.ParseInt(walk.Position, 10, 64)
		if err != nil || f.Cursor <= 0 {
			writeExportError(w, store.ErrInvalidCursor)
			return
		}
	}
	f.Since, f.Until, f.MaxID, f.Ascending = walk.sinceTime(), walk.untilTime(), &walk.MaxID, true
	f.Limit = boundedParam(r.URL.Query().Get("limit"), 500, 1, 500)
	events, next, err := a.Store.ListQueries(r.Context(), f)
	if err != nil {
		writeExportError(w, err)
		return
	}
	// Annotation failures must be visible in an export. The interactive list
	// can degrade gracefully, but a machine export must not claim completeness.
	ids := make([]string, 0, len(events))
	for _, e := range events {
		if e.DNSSECObservationID != "" {
			ids = append(ids, e.DNSSECObservationID)
		}
	}
	observations, err := a.Store.DNSSECObservationsByID(r.Context(), ids)
	if err != nil {
		writeExportError(w, err)
		return
	}
	docs := make([][]byte, 0, len(events))
	for _, event := range events {
		row := queryRow{QueryEvent: event}
		if observation, found := observations[event.DNSSECObservationID]; found {
			row.DNSSECValidation = &observation
		}
		raw, err := json.Marshal(row)
		if err != nil {
			writeExportError(w, err)
			return
		}
		docs = append(docs, raw)
	}
	position := ""
	if next > 0 {
		position = strconv.FormatInt(next, 10)
	}
	writeExport(w, r, walk, position, docs)
}

func (a *API) handleExportDecisions(w http.ResponseWriter, r *http.Request) {
	f, err := decisionFilterFromRequest(r)
	if err != nil {
		writeExportError(w, err)
		return
	}
	walk, err := a.exportWindow(r, "decisions")
	if err != nil {
		writeExportError(w, err)
		return
	}
	f.Since, f.Until, f.MaxInsertionID, f.Ascending, f.Cursor = walk.sinceTime(), walk.untilTime(), &walk.MaxID, true, walk.Position
	f.Limit = boundedParam(r.URL.Query().Get("limit"), 500, 1, 500)
	decisions, next, err := a.Store.ListDecisionsPage(r.Context(), f)
	if err != nil {
		writeExportError(w, err)
		return
	}
	docs := make([][]byte, 0, len(decisions))
	for _, decision := range decisions {
		full, err := a.Store.DecisionWithEvidence(r.Context(), decision.ID)
		if err != nil {
			writeExportError(w, err)
			return
		}
		raw, err := json.Marshal(full)
		if err != nil {
			writeExportError(w, err)
			return
		}
		docs = append(docs, raw)
	}
	writeExport(w, r, walk, next, docs)
}
