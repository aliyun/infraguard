package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestStaticServerBuiltAndUnbuiltFrontend(t *testing.T) {
	files := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>app</html>")}, "assets/app.js": &fstest.MapFile{Data: []byte("console.log('app')")}}
	for _, tc := range []struct{ path, want string }{{"/", "<html>app</html>"}, {"/assets/app.js", "console.log('app')"}, {"/settings/security", "<html>app</html>"}} {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			staticHandlerFS(files).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
			}
		})
	}
	rec := httptest.NewRecorder()
	staticHandlerFS(fstest.MapFS{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/unknown", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "web UI has not been built") || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("placeholder status=%d body=%q", rec.Code, rec.Body.String())
	}
}
