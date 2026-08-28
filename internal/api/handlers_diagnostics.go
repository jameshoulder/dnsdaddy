package api

import (
	"net/http"

	"github.com/jameshoulder/dnsdaddy/internal/diag"
)

// DiagnosticsResponse is the answer to "why is DNS not working?".
//
// Authenticated: the checks quote configured CIDRs and network names back at
// the reader, which is exactly what makes them useful and exactly why they do
// not belong on the unauthenticated health endpoint.
type DiagnosticsResponse struct {
	// Status is the worst verdict across every check, so a caller can act on
	// one field.
	Status diag.Status  `json:"status"`
	Checks []diag.Check `json:"checks"`
}

func (a *API) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	networks, err := a.Store.ListNetworks(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	policies, err := a.Store.ListPolicies(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	refused := a.DNS.RefusedClients()
	stale := a.ClientACL.Stale()
	checks := diag.ClientAccess(diag.ClientAccessInput{
		ACL: a.ClientACL.Current(),
		// Always known here: this handler runs inside the daemon that owns
		// the flag.
		Stale:          &stale,
		Networks:       diag.FromStoreNetworks(networks, diag.PolicyNames(policies)),
		RefusedQueries: &refused,
	})

	// Evidence the process has actually gathered about its own exposure. It
	// belongs beside the client-access checks: both answer "is this reachable
	// by the people it should be, and only by them?".
	exposureCount, exposureAddr := a.exposure.snapshot()
	checks = append(checks, diag.ManagementExposure(exposureCount, exposureAddr))

	writeJSON(w, http.StatusOK, DiagnosticsResponse{
		Status: diag.Worst(checks),
		Checks: checks,
	})
}
