package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestProcessAliveCurrentAndInvalid(t *testing.T) {
	if !ProcessAlive(os.Getpid()) {
		t.Fatal("current process should be alive")
	}
	if (&State{PID: 0}).IsRunning() || (*State)(nil).IsRunning() {
		t.Fatal("invalid state reported running")
	}
	if DetachAttr() == nil {
		t.Fatal("missing detach attributes")
	}
}

func TestTerminateOwnedProcess(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
	cmd.Env = append(os.Environ(), "INFRAGUARD_TEST_PROCESS_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	if !ProcessAlive(cmd.Process.Pid) {
		t.Fatal("started process not detected")
	}
	if err := TerminatePID(cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if ProcessAlive(cmd.Process.Pid) {
		t.Fatal("terminated process still detected")
	}
}

func TestProcessHelper(t *testing.T) {
	if os.Getenv("INFRAGUARD_TEST_PROCESS_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}

func TestListenFallbackAndGracefulShutdown(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port
	s := New(Options{Host: "127.0.0.1", Port: port})
	ln, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if s.Port() == 0 || s.Port() == port {
		t.Fatalf("did not choose fallback port: %d", s.Port())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", s.Port()))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
	if _, err := New(Options{Host: "invalid host name", Port: 0}).Listen(); err == nil {
		t.Fatal("invalid host accepted")
	}
}

func TestServerAuthenticationMethods(t *testing.T) {
	s := New(Options{Host: "0.0.0.0", Token: "secret"})
	for _, tc := range []struct {
		name      string
		configure func(*http.Request)
		want      int
	}{
		{"missing", func(*http.Request) {}, http.StatusUnauthorized},
		{"header", func(r *http.Request) { r.Header.Set("X-InfraGuard-Token", "secret") }, http.StatusOK},
		{"bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret") }, http.StatusOK},
		{"cookie", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "ig_token", Value: "secret"}) }, http.StatusOK},
		{"wrong", func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/meta", nil)
			tc.configure(req)
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
