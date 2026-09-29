package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/backup"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func (a *API) handleConfigHistory(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 || v > 200 {
			writeError(w, 400, "limit must be between 1 and 200")
			return
		}
		limit = v
	}
	var before int64
	if raw := r.URL.Query().Get("beforeId"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v < 1 {
			writeError(w, 400, "beforeId must be a positive history ID")
			return
		}
		before = v
	}
	events, more, err := a.Store.ListConfigChanges(r.Context(), before, limit)
	if err != nil {
		writeError(w, 500, "configuration history could not be read")
		return
	}
	var next int64
	if more && len(events) > 0 {
		next = events[len(events)-1].ID
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"events": events, "hasMore": more, "nextBeforeId": next,
		"scope":       "authenticated management configuration writes since this feature was installed; direct SQL/YAML edits and earlier changes are not reconstructed",
		"consistency": "durable intent followed by actual persisted changes; pending/incomplete entries need investigation"})
}

func (a *API) handleRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.Recovery == nil {
		var manager *backup.Manager
		writeJSON(w, 200, manager.Status())
		return
	}
	writeJSON(w, 200, a.Recovery.Status())
}

func (a *API) handleRecoveryBackup(w http.ResponseWriter, r *http.Request) {
	if a.Recovery == nil {
		writeError(w, 503, "encrypted backup is unavailable in this runtime")
		return
	}
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	passphrase := []byte(body.Passphrase)
	body.Passphrase = ""
	defer clear(passphrase)
	if err := backup.ValidatePassphrase(passphrase); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if !a.configWrites.TryLock() {
		writeError(w, 409, "a management change or backup is already running; try again when it completes")
		return
	}
	defer a.configWrites.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	// Return an attachment only after snapshot, key checks and encryption
	// have all completed successfully.
	f, err := os.CreateTemp("", "dnsdaddy-download-*.ddbackup")
	if err != nil {
		writeError(w, 500, "could not prepare encrypted backup download")
		return
	}
	defer func() { f.Close(); _ = os.Remove(f.Name()) }()
	if err := f.Chmod(0o600); err != nil {
		writeError(w, 500, "could not secure encrypted backup download")
		return
	}
	_, err = a.Recovery.Create(ctx, passphrase, f)
	if err != nil {
		status := 500
		if errors.Is(err, backup.ErrBusy) {
			status = 409
		}
		if errors.Is(err, backup.ErrLimit) {
			status = 413
		}
		a.Log.Error("encrypted recovery backup failed", "error", err)
		writeError(w, status, "encrypted backup could not be completed; no backup was returned. Check the recovery log for the failed prerequisite.")
		return
	}
	if err := f.Sync(); err != nil {
		writeError(w, 500, "encrypted backup could not be saved")
		return
	}
	stat, err := f.Stat()
	if err != nil {
		writeError(w, 500, "encrypted backup could not be read")
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		writeError(w, 500, "encrypted backup could not be read")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="dnsdaddy-`+time.Now().UTC().Format("20060102T150405Z")+`.ddbackup"`)
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, f)
}

type auditedRoute struct {
	scope          store.AuditScope
	action, target string
}

// The closed route set excludes login/logout, enrichment, provider tests,
// refreshes, exports and backup payloads. No raw URL query or body is logged.
func auditedManagementRoute(r *http.Request) (auditedRoute, bool) {
	if isSafeMethod(r.Method) {
		return auditedRoute{}, false
	}
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(p) < 3 || p[0] != "api" || p[1] != "v1" {
		return auditedRoute{}, false
	}
	parts := p[2:]
	kind, id, target := "", "", ""
	switch parts[0] {
	case "networks":
		kind = "network"
	case "policies":
		kind = "policy"
	case "feeds":
		kind = "feed"
		if parts[len(parts)-1] == "refresh" {
			return auditedRoute{}, false
		}
	case "clients":
		kind = "client"
	case "tokens":
		kind = "token"
	case "integrations":
		if len(parts) >= 2 && parts[1] == "webhook" {
			if parts[len(parts)-1] == "test" {
				return auditedRoute{}, false
			}
			kind = "webhook"
			id = "1"
			target = "integrations/webhook"
			break
		}
		if len(parts) == 2 && (parts[1] == "reputation" || parts[1] == "settings") {
			kind = "integration_settings"
			target = "settings/integrations"
			break
		}
		if len(parts) < 2 || parts[1] != "providers" {
			return auditedRoute{}, false
		}
		if parts[len(parts)-1] == "test" {
			return auditedRoute{}, false
		}
		kind = "provider"
		parts = parts[1:]
	case "findings":
		if len(parts) != 3 || parts[2] != "review" {
			return auditedRoute{}, false
		}
		kind = "review"
	case "auth":
		if len(parts) != 2 || parts[1] != "password" {
			return auditedRoute{}, false
		}
		kind = "settings"
		id = "admin_password_hash"
		target = "settings/admin_password"
	case "protection":
		kind = "settings"
		id = "protection.settings.v1"
		target = "settings/protection"
	case "dnssec":
		if len(parts) != 2 || parts[1] != "mode" {
			return auditedRoute{}, false
		}
		kind = "settings"
		id = "dnssec.mode"
		target = "settings/dnssec.mode"
	default:
		return auditedRoute{}, false
	}
	if target == "" {
		if len(parts) > 1 {
			id = parts[1]
		}
		target = kind
		if id != "" {
			target += "/" + store.CleanAuditLabel(id)
		}
	}
	action := strings.ToLower(r.Method)
	if len(parts) > 1 && parts[len(parts)-1] == "rotate-token" {
		action = "rotate_credential"
	}
	if len(parts) > 1 && parts[len(parts)-1] == "secret" {
		action = kind + "_credential_" + strings.ToLower(r.Method)
	}
	return auditedRoute{scope: store.AuditScope{Kind: kind, ID: id}, action: action, target: target}, true
}

// withConfigAudit serializes operator writes without involving the DNS path.
// A durable pending record precedes the handler. Response bytes are withheld
// until the resulting stored configuration has been recorded. Post-write
// failure is reported explicitly; it never claims the change rolled back.
func (a *API) withConfigAudit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, ok := auditedManagementRoute(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		p, ok := a.Auth.authenticate(r)
		if !ok {
			writeError(w, 401, "authentication required")
			return
		}
		a.configWrites.Lock()
		defer a.configWrites.Unlock()
		before, err := a.Store.CaptureConfig(r.Context(), route.scope)
		if err != nil {
			writeError(w, 503, "change refused: its current configuration could not be recorded")
			return
		}
		id, err := a.Store.BeginConfigChange(r.Context(), store.CleanAuditLabel(reviewActor(p)), route.action, route.target)
		if err != nil {
			writeError(w, 503, "change refused: configuration history is unavailable")
			return
		}
		buffer := &auditResponse{header: make(http.Header), status: 200}
		panicked := false
		func() {
			defer func() {
				if recover() != nil {
					panicked = true
				}
			}()
			next.ServeHTTP(buffer, r)
		}()
		// A disconnected browser cannot cancel the journal of an already
		// committed change; a separate deadline still bounds the work.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		after, captureErr := a.Store.CaptureConfig(ctx, route.scope)
		status := "complete"
		note := ""
		httpStatus := buffer.status
		if panicked || buffer.overflow {
			httpStatus = 500
		}
		if httpStatus >= 400 {
			status = "failed"
			note = "The request returned an error. Review any recorded persisted changes before retrying."
		}
		changes := store.DiffConfig(before, after)
		if captureErr != nil {
			status = "incomplete"
			note = "The request ran, but its resulting configuration could not be read. It may have changed; inspect configuration before retrying."
			changes = []store.ConfigChange{}
		}
		finishErr := a.Store.CompleteConfigChange(ctx, id, status, httpStatus, changes, note)
		if captureErr != nil || finishErr != nil {
			a.Log.Error("configuration audit incomplete", "history_id", id, "capture_failed", captureErr != nil, "completion_failed", finishErr != nil)
			w.Header().Set("X-DNSDaddy-Audit-Incomplete", "true")
			writeJSON(w, 500, map[string]any{"error": "The request ran, but its change history could not be completed. Configuration may have changed; inspect it before retrying.", "auditId": id, "configurationMayHaveChanged": true})
			return
		}
		if panicked || buffer.overflow {
			writeError(w, 500, "request could not complete; review configuration history for any persisted changes")
			return
		}
		for k, values := range buffer.header {
			for _, value := range values {
				w.Header().Add(k, value)
			}
		}
		w.Header().Set("X-DNSDaddy-Change-ID", strconv.FormatInt(id, 10))
		w.WriteHeader(buffer.status)
		_, _ = w.Write(buffer.body.Bytes())
	})
}

type auditResponse struct {
	header                http.Header
	status                int
	body                  bytes.Buffer
	wroteHeader, overflow bool
}

func (r *auditResponse) Header() http.Header { return r.header }
func (r *auditResponse) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = status
}
func (r *auditResponse) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(200)
	}
	if r.body.Len()+len(b) > 2<<20 {
		r.overflow = true
		return 0, errors.New("audited response too large")
	}
	return r.body.Write(b)
}
