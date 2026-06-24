package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aliyun/infraguard/pkg/i18n"
)

// Options configures the server.
type Options struct {
	Host    string
	Port    int
	Token   string
	Version string
}

// Server is the InfraGuard local web server.
type Server struct {
	opts Options
	mux  *http.ServeMux
}

// New creates a server with all routes registered.
func New(opts Options) *Server {
	s := &Server{opts: opts, mux: http.NewServeMux()}
	s.routes()
	return s
}

// GenerateToken returns a random hex token for local authentication.
func GenerateToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "infraguard"
	}
	return hex.EncodeToString(b)
}

// IsLoopback reports whether host is a loopback address.
func IsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /api/meta", s.handleMeta)
	s.mux.HandleFunc("POST /api/scan", s.handleScan)
	s.mux.HandleFunc("GET /api/policies", s.handlePoliciesList)
	s.mux.HandleFunc("GET /api/policies/{id}", s.handlePolicyDetail)
	s.mux.HandleFunc("GET /api/coverage", s.handleCoverage)
	s.mux.HandleFunc("POST /api/rule/eval", s.handleRuleEval)
	s.mux.HandleFunc("POST /api/rule/test", s.handleRuleTest)
	s.mux.HandleFunc("GET /api/waivers", s.handleWaiversGet)
	s.mux.HandleFunc("POST /api/waivers", s.handleWaiversSave)
	s.mux.Handle("/", staticHandler())
}

// Handler returns the root handler with auth middleware applied.
func (s *Server) Handler() http.Handler {
	return s.authMiddleware(s.mux)
}

// authMiddleware enforces the token for non-loopback binds. Loopback binds are
// trusted (single local user). /healthz is always open.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || IsLoopback(s.opts.Host) || s.opts.Token == "" {
			next.ServeHTTP(w, r)
			return
		}
		if s.tokenOK(r) {
			// Persist the token as a cookie so subsequent requests pass.
			if r.URL.Query().Get("token") != "" {
				http.SetCookie(w, &http.Cookie{Name: "ig_token", Value: s.opts.Token, Path: "/", HttpOnly: true})
			}
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized: missing or invalid token", http.StatusUnauthorized)
	})
}

func (s *Server) tokenOK(r *http.Request) bool {
	if r.URL.Query().Get("token") == s.opts.Token {
		return true
	}
	if h := r.Header.Get("X-InfraGuard-Token"); h == s.opts.Token {
		return true
	}
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") &&
		strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == s.opts.Token {
		return true
	}
	if c, err := r.Cookie("ig_token"); err == nil && c.Value == s.opts.Token {
		return true
	}
	return false
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMeta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":   s.opts.Version,
		"languages": i18n.GetSupportedLanguages(),
	})
}

// Listen binds the configured host/port, falling back to an ephemeral port if a
// fixed port is busy. It records the resolved port on the server.
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.opts.Host, s.opts.Port))
	if err != nil && s.opts.Port != 0 {
		ln, err = net.Listen("tcp", fmt.Sprintf("%s:0", s.opts.Host))
	}
	if err != nil {
		return nil, err
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		s.opts.Port = tcp.Port
	}
	return ln, nil
}

// Serve serves HTTP on ln until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler()}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Port returns the (possibly resolved) port.
func (s *Server) Port() int { return s.opts.Port }

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
