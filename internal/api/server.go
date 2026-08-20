// Package api serves the DNS Daddy management REST API, the embedded
// dashboard, the DNS-over-HTTPS endpoint, and Prometheus metrics.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
	"github.com/jameshoulder/dnsdaddy/internal/httpx"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/querylog"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/jameshoulder/dnsdaddy/internal/web"
)

// Deps are everything the API needs to serve.
type Deps struct {
	Config   config.Config
	Store    *store.Store
	Engine   *policy.Engine
	Feeds    *blocklist.Manager
	Lists    *blocklist.Holder
	Resolver *resolver.Resolver
	DNS      *dnsserver.Handler
	DoH      *dnsserver.DoHHandler
	QueryLog *querylog.Logger
	// Detector is the behavioural detection engine, or nil when detection is
	// switched off. Every handler that touches it must tolerate nil.
	Detector  *detect.Engine
	Auth      *Auth
	Log       *slog.Logger
	StartedAt time.Time

	// TrustedProxies bounds which peers' forwarding headers are believed,
	// shared with the DoH handler and the cookie logic so all three agree on
	// who the client is.
	TrustedProxies *httpx.TrustedProxies
}

// API is the HTTP surface.
type API struct {
	Deps
}

// New returns an API bound to deps.
func New(d Deps) *API {
	if d.TrustedProxies == nil {
		d.TrustedProxies = &httpx.TrustedProxies{}
	}
	return &API{Deps: d}
}

// Handler builds the HTTP router.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	// --- DNS-over-HTTPS -----------------------------------------------------
	// Unauthenticated by design: it is a resolver endpoint, not an admin one.
	// The per-network token in the path is the credential.
	mux.Handle("/dns-query", a.DoH)
	mux.Handle("/dns-query/", a.DoH)

	// --- Unauthenticated operational endpoints ------------------------------
	mux.HandleFunc("GET /api/v1/health", a.handleHealth)
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", a.handleLogout)
	mux.HandleFunc("GET /api/v1/auth/session", a.handleSession)
	mux.HandleFunc("GET /openapi.yaml", a.handleOpenAPI)

	// --- Authenticated management API ---------------------------------------
	api := http.NewServeMux()

	api.HandleFunc("POST /api/v1/auth/password", a.handleChangePassword)

	api.HandleFunc("GET /api/v1/overview", a.handleOverview)
	api.HandleFunc("GET /api/v1/activity/queries", a.handleQueryActivity)
	api.HandleFunc("GET /api/v1/threats/categories", a.handleThreatsByCategory)
	api.HandleFunc("GET /api/v1/threats/top-domains", a.handleTopBlocked)
	api.HandleFunc("GET /api/v1/queries", a.handleQueryLog)
	api.HandleFunc("GET /api/v1/categories", a.handleCategories)
	api.HandleFunc("GET /api/v1/resolvers", a.handleResolvers)
	api.HandleFunc("GET /api/v1/settings", a.handleSettings)
	api.HandleFunc("GET /api/v1/reports/summary", a.handleReportSummary)

	// Behavioural findings. Read-only: there is nothing to configure here
	// because these detectors do not enforce anything.
	api.HandleFunc("GET /api/v1/findings", a.handleListFindings)
	api.HandleFunc("GET /api/v1/findings/summary", a.handleFindingsSummary)
	api.HandleFunc("GET /api/v1/findings/export", a.handleExportFindings)
	api.HandleFunc("GET /api/v1/findings/{id}", a.handleGetFinding)
	api.HandleFunc("GET /api/v1/detectors", a.handleDetectors)
	api.HandleFunc("GET /api/v1/intelligence", a.handleDomainIntelligence)

	api.HandleFunc("GET /api/v1/networks", a.handleListNetworks)
	api.HandleFunc("POST /api/v1/networks", a.handleCreateNetwork)
	api.HandleFunc("GET /api/v1/networks/{id}", a.handleGetNetwork)
	api.HandleFunc("PATCH /api/v1/networks/{id}", a.handleUpdateNetwork)
	api.HandleFunc("DELETE /api/v1/networks/{id}", a.handleDeleteNetwork)
	api.HandleFunc("POST /api/v1/networks/{id}/rotate-token", a.handleRotateToken)

	api.HandleFunc("GET /api/v1/policies", a.handleListPolicies)
	api.HandleFunc("POST /api/v1/policies", a.handleCreatePolicy)
	api.HandleFunc("GET /api/v1/policies/{id}", a.handleGetPolicy)
	api.HandleFunc("PATCH /api/v1/policies/{id}", a.handleUpdatePolicy)
	api.HandleFunc("DELETE /api/v1/policies/{id}", a.handleDeletePolicy)
	api.HandleFunc("POST /api/v1/policies/{id}/rules", a.handleAddRule)
	api.HandleFunc("DELETE /api/v1/policies/{id}/rules/{kind}/{domain}", a.handleDeleteRule)

	api.HandleFunc("GET /api/v1/feeds", a.handleListFeeds)
	api.HandleFunc("POST /api/v1/feeds", a.handleCreateFeed)
	api.HandleFunc("PATCH /api/v1/feeds/{id}", a.handleUpdateFeed)
	api.HandleFunc("DELETE /api/v1/feeds/{id}", a.handleDeleteFeed)
	api.HandleFunc("POST /api/v1/feeds/refresh", a.handleRefreshFeeds)

	api.HandleFunc("GET /api/v1/clients", a.handleListClients)
	api.HandleFunc("PUT /api/v1/clients", a.handleSetClient)

	api.HandleFunc("GET /api/v1/tokens", a.handleListTokens)
	api.HandleFunc("POST /api/v1/tokens", a.handleCreateToken)
	api.HandleFunc("DELETE /api/v1/tokens/{id}", a.handleDeleteToken)

	api.HandleFunc("GET /metrics", a.handleMetrics)

	mux.Handle("/api/v1/", a.requireAuth(api))
	mux.Handle("/metrics", a.requireAuth(api))

	// --- Dashboard ----------------------------------------------------------
	mux.Handle("/", web.Handler())

	return a.withRecovery(a.withLogging(mux))
}

// requireAuth rejects unauthenticated calls to the management API, and
// applies a same-origin check to cookie-authenticated state-changing requests.
func (a *API) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := a.Auth.authenticate(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		// A bearer token is never attached automatically by a browser, so it
		// cannot be driven cross-site and needs no CSRF check. A session
		// cookie can be, so state-changing requests must prove they came from
		// the dashboard's own origin.
		if p.kind == "session" && !isSafeMethod(r.Method) {
			if !sameOrigin(r, a.TrustedProxies) {
				writeError(w, http.StatusForbidden,
					"cross-origin request rejected; use an API token for programmatic access")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isSafeMethod reports whether a method is read-only and so exempt from the
// origin check.
func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// withLogging records request outcomes at debug level. Request paths can carry
// domain names from the query-log filter, so this stays off at info level.
func (a *API) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if strings.HasPrefix(r.URL.Path, "/dns-query") {
			return // DoH volume would drown the log
		}
		a.Log.Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds())
	})
}

// withRecovery turns a panic in any handler into a 500 rather than taking the
// resolver down with it.
func (a *API) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				a.Log.Error("panic serving request", "path", r.URL.Path, "panic", rec)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// --- helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status line is already sent; nothing useful left to do.
		return
	}
}

type errorBody struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// writeStoreError maps store errors onto HTTP status codes.
func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	// 1 MiB is far more than any management payload needs and bounds the
	// memory an unauthenticated login attempt can make us allocate.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func clientKey(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
