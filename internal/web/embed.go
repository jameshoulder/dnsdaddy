// Package web serves the dashboard that ships inside the binary.
//
// The dashboard is hand-written HTML, CSS, and JavaScript with no build step
// and no runtime dependencies. That is a deliberate choice for a self-hosted
// product: `go build` produces the whole thing, there is no npm tree to audit
// before pointing your network at it, and the page works on a box with no
// outbound internet access.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static
var static embed.FS

// Handler serves the dashboard. Unknown paths fall back to index.html so the
// client-side router can own them.
func Handler() http.Handler {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		panic("web: embedded assets missing: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)

		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" {
			clean = "index.html"
		}
		if _, err := fs.Stat(sub, clean); err != nil {
			// Not a real asset: hand it to the SPA.
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		if strings.HasSuffix(clean, ".css") || strings.HasSuffix(clean, ".js") {
			// Assets are versioned by the binary they ship in; a short cache
			// keeps a browser from serving yesterday's dashboard after an
			// upgrade while still avoiding a refetch on every navigation.
			w.Header().Set("Cache-Control", "public, max-age=300")
		}
		files.ServeHTTP(w, r)
	})
}

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	// The dashboard loads nothing from anywhere else, so the policy can be
	// this tight. 'unsafe-inline' is not granted: all script and style is in
	// its own file.
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
}
