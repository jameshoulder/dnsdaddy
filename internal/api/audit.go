package api

import (
	"net/http"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/audit"
)

// auditActor resolves who is making a request, for the audit log.
//
// Re-authenticates rather than threading the principal through a context. The
// request reached here only because requireAuth already admitted it, so this
// is a second cheap lookup of a fact that is certainly true — and it keeps the
// audit record dependent on the same function the access decision used, rather
// than on a value some middleware might forget to set.
func (a *API) auditActor(r *http.Request) (actor, kind string) {
	if a.Auth == nil {
		return "unknown", audit.ActorSystem
	}
	p, ok := a.Auth.authenticate(r)
	if !ok {
		return "unknown", audit.ActorSystem
	}
	switch p.kind {
	case "token":
		// The token's name, never its value: the value is a live credential
		// and the name is what an operator recognises in a list.
		return p.label, audit.ActorToken
	default:
		return p.label, audit.ActorSession
	}
}

// auditSource labels where a change came from.
//
// A cookie means somebody used the dashboard; a bearer token means a script or
// an integration. That distinction is most of what an operator wants when they
// find a change they did not expect.
func auditSource(kind string) string {
	if kind == audit.ActorToken {
		return audit.SourceAPI
	}
	return audit.SourceDashboard
}

// record writes one audit entry for a management change.
//
// Called after the change has committed, and it cannot fail the request: the
// mutation already happened, so returning an error here would leave an
// operator retrying something that has taken effect. A queue that is full
// counts the loss and dnsdaddy doctor reports it, because an audit log with
// holes is a fact the operator needs rather than one to hide.
func (a *API) record(r *http.Request, action, targetType, targetID string, before, after any) {
	if a.Audit == nil {
		return
	}
	actor, kind := a.auditActor(r)
	a.Audit.Record(audit.Entry{
		Time:       time.Now().UTC(),
		Actor:      actor,
		ActorKind:  kind,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Before:     before,
		After:      after,
		Source:     auditSource(kind),
	})
}
