package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// placeholderPage is served when the frontend has not been built into dist/.
const placeholderPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>InfraGuard</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#1f2937}
code{background:#f3f4f6;padding:.15rem .35rem;border-radius:.25rem}</style></head>
<body><h1>InfraGuard server</h1>
<p>The web UI has not been built yet. Run <code>make web</code> (or
<code>cd web && npm ci && npm run build</code>) and rebuild the binary.</p>
<p>The JSON API is available under <code>/api</code> and <code>/healthz</code>.</p>
</body></html>`

// hasFrontend reports whether a built frontend is embedded.
func hasFrontend(sub fs.FS) bool {
	_, err := fs.Stat(sub, "index.html")
	return err == nil
}

// staticHandler serves the embedded SPA with client-side-routing fallback.
func staticHandler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "static assets unavailable", http.StatusInternalServerError)
		})
	}
	built := hasFrontend(sub)
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !built {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(placeholderPage))
			return
		}
		// Serve existing files directly; fall back to index.html for SPA routes.
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}
