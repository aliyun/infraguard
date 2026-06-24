package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1": true,
		"localhost": true,
		"::1":       true,
		"0.0.0.0":   false,
		"10.0.0.5":  false,
	}
	for host, want := range cases {
		if got := IsLoopback(host); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestGenerateTokenUnique(t *testing.T) {
	a, b := GenerateToken(), GenerateToken()
	if a == "" || a == b {
		t.Errorf("expected unique non-empty tokens, got %q and %q", a, b)
	}
}

func TestStateRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if got, _ := ReadState(); got != nil {
		t.Fatalf("expected no state initially, got %+v", got)
	}
	want := &State{PID: 4242, Host: "127.0.0.1", Port: 9527, URL: "http://127.0.0.1:9527", Version: "test"}
	if err := WriteState(want); err != nil {
		t.Fatalf("WriteState: %v", err)
	}
	got, err := ReadState()
	if err != nil || got == nil || got.PID != 4242 || got.Port != 9527 {
		t.Fatalf("ReadState mismatch: %+v, err=%v", got, err)
	}
	if err := RemoveState(); err != nil {
		t.Fatalf("RemoveState: %v", err)
	}
	if got, _ := ReadState(); got != nil {
		t.Fatalf("expected nil after remove, got %+v", got)
	}
}

func TestMetaAndAuth(t *testing.T) {
	// Loopback bind: no token required.
	s := New(Options{Host: "127.0.0.1", Token: "secret", Version: "1.2.3"})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/meta", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback meta = %d, want 200", rec.Code)
	}
	var meta map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &meta)
	if meta["version"] != "1.2.3" {
		t.Errorf("version = %v, want 1.2.3", meta["version"])
	}

	// Non-loopback bind: token required.
	pub := New(Options{Host: "0.0.0.0", Token: "secret"})
	rec = httptest.NewRecorder()
	pub.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/meta", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("public meta without token = %d, want 401", rec.Code)
	}
	rec = httptest.NewRecorder()
	pub.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/meta?token=secret", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("public meta with token = %d, want 200", rec.Code)
	}
	// Health is always open.
	rec = httptest.NewRecorder()
	pub.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health = %d, want 200", rec.Code)
	}
}
