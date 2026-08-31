package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The router registers management endpoints on a second mux that is wrapped in
// authentication, and the handful of deliberately public ones on the first.
// At the call site the difference between the two is one character —
// `api.HandleFunc` against `mux.HandleFunc` — and nothing else in the tree
// notices if a new endpoint is registered on the wrong one. That is the whole
// of the admin API's access control resting on a typo nobody would see in
// review.
//
// So this reads the routes back out of server.go and checks both halves: every
// management route is refused without a session, and the public set is exactly
// the list below and nothing else.
// Matches any {name} or {name...} path segment in a ServeMux pattern.
var wildcard = regexp.MustCompile(`\{[^}]*\}`)

func routeTable(t *testing.T) (public, managed []string) {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "HandleFunc" {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		switch recv.Name {
		case "mux":
			public = append(public, pattern)
		case "api":
			managed = append(managed, pattern)
		}
		return true
	})

	sort.Strings(public)
	sort.Strings(managed)
	return public, managed
}

func TestEveryManagementRouteRequiresAuthentication(t *testing.T) {
	_, managed := routeTable(t)
	// A parse that found nothing would pass silently, which is the failure
	// mode this whole test exists to prevent elsewhere.
	if len(managed) < 20 {
		t.Fatalf("only found %d management routes in server.go; the parser is not reading the router", len(managed))
	}

	h := newHarness(t)

	for _, pattern := range managed {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			t.Errorf("route %q has no method", pattern)
			continue
		}
		// Wildcards need a concrete value to route to the handler at all.
		// Substituted generically rather than from a list of known names, so
		// a route with a new wildcard is still covered instead of skipped.
		path = wildcard.ReplaceAllString(path, "x")
		if strings.Contains(path, "{") {
			t.Errorf("route %q still has an unsubstituted wildcard; this test would not reach its handler", path)
			continue
		}

		// No cookie, no bearer token. Anything but 401 means the endpoint is
		// reachable by anyone who can open a socket to the management port.
		resp, body := h.doWithHeaders(method, path, nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d without a session, want 401: %s",
				method, path, resp.StatusCode, string(body))
		}
	}
}

func TestTheUnauthenticatedRouteSetIsExactlyThis(t *testing.T) {
	// Each of these is public on purpose and the reason is worth restating,
	// because the list is the security boundary:
	//
	//   health   liveness for a container runtime and a load balancer, which
	//            have no credential; it answers {"status":"ok"} and adds
	//            detail only for a loopback peer or an authenticated caller.
	//   login    the endpoint that issues the credential.
	//   logout   revoking a session must work even from one already expired.
	//   session  the dashboard asks "am I signed in?" before rendering, and
	//            a 401 here is the answer rather than an error.
	//   openapi  the served spec describes the API; it carries no data.
	want := []string{
		"GET /api/v1/auth/session",
		"GET /api/v1/health",
		"GET /openapi.yaml",
		"POST /api/v1/auth/login",
		"POST /api/v1/auth/logout",
	}

	got, _ := routeTable(t)

	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the unauthenticated route set changed.\n got: %v\nwant: %v\n\n"+
			"If this is deliberate, say here why the new endpoint is safe to serve "+
			"to anyone who can reach the management port.", got, want)
	}
}
