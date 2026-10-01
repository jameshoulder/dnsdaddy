// Package web serves the dashboard that ships inside the binary.
package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed static
var static embed.FS

// dashboardIndex ties the HTML to the exact script/style bytes in this binary.
// Stable /app.js names with max-age alone allowed an upgraded server to run an
// old cached dashboard. Fingerprinted URLs prevent that, including for a browser
// which still holds the old five-minute cache policy. No remote resources,
// credentials or runtime configuration enter the public page.
func dashboardIndex(sub fs.FS) ([]byte, map[string]string, error) {
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, nil, err
	}
	etags := make(map[string]string)
	for _, name := range []string{"app.js", "app.css"} {
		data, err := fs.ReadFile(sub, name)
		if err != nil {
			return nil, nil, err
		}
		hash := sha256.Sum256(data)
		etags[name] = fmt.Sprintf(`"%x"`, hash)
		index = bytes.ReplaceAll(index, []byte(`"/`+name+`"`), []byte(fmt.Sprintf(`"/%s?v=%x"`, name, hash[:8])))
	}
	return index, etags, nil
}

// Handler serves the embedded UI; a missing asset is not a successful HTML API
// response. Extensionless browser routes retain the SPA fallback.
func Handler() http.Handler {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		panic("web: embedded assets missing: " + err.Error())
	}
	index, etags, err := dashboardIndex(sub)
	if err != nil {
		panic("web: embedded dashboard incomplete: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))
	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		// Revalidate stable paths too: a bookmarked old fingerprint must never
		// be served as an immutable new build with yesterday's cache metadata.
		w.Header().Set("Cache-Control", "no-cache")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" || clean == "index.html" {
			serveIndex(w, r)
			return
		}
		info, err := fs.Stat(sub, clean)
		if err != nil || info.IsDir() {
			if path.Ext(clean) != "" || strings.HasPrefix(clean, "api/") {
				http.NotFound(w, r)
				return
			}
			serveIndex(w, r)
			return
		}
		if etag := etags[clean]; etag != "" {
			w.Header().Set("ETag", etag)
		}
		files.ServeHTTP(w, r)
	})
}

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
}
