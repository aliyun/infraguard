package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/infraguard/pkg/server"
)

func TestServerStatusAndReadiness(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := runServerStatus(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := runServerStop(nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := waitReady(0); err == nil {
		t.Fatal("expected readiness timeout")
	}
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()
	host, portText, err := net.SplitHostPort(httpServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := httpServer.Listener.Addr().(*net.TCPAddr).Port
	state := &server.State{PID: os.Getpid(), Host: host, Port: port, URL: httpServer.URL, StartedAt: time.Now(), Version: "test"}
	if err := server.WriteState(state); err != nil {
		t.Fatal(err)
	}
	ready, err := waitReady(time.Second)
	if err != nil || ready.Port != port {
		t.Fatalf("readiness: %+v %v", ready, err)
	}
	if err := runServerStatus(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := runServerStart(nil, nil); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("duplicate start: %v", err)
	}
	if err := server.RemoveState(); err != nil {
		t.Fatal(err)
	}
	if err := runServerStop(nil, nil); err != nil {
		t.Fatal(err)
	}
	path, err := server.StatePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runServerStatus(nil, nil); err == nil {
		t.Fatal("invalid state should fail status")
	}
	if err := runServerStop(nil, nil); err == nil {
		t.Fatal("invalid state should fail stop")
	}
	if got, err := serverLogPath(); err != nil || got != filepath.Join(home, ".infraguard", "server.log") {
		t.Fatalf("log path %q: %v", got, err)
	}
	if buildURL("0.0.0.0", port, "secret") != "http://127.0.0.1:"+portText {
		t.Fatal("wildcard URL")
	}
	if got := buildURL("192.0.2.1", 80, "secret"); got != "http://192.0.2.1:80/?token=secret" {
		t.Fatalf("public URL %q", got)
	}
	if err := serve("invalid host name", 0, ""); err == nil {
		t.Fatal("invalid listen host accepted")
	}
}

func TestServeLifecycleWritesAndCleansState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	oldForeground := serverForeground
	serverForeground = false
	t.Cleanup(func() { serverForeground = oldForeground })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
		}
	}()
	go func() { done <- serveWithContext(ctx, "127.0.0.1", 0, "test-token") }()
	state, err := waitReady(5 * time.Second)
	if err != nil {
		t.Fatalf("server readiness: %v", err)
	}
	if state.PID != os.Getpid() || state.Port <= 0 || state.Token != "test-token" {
		t.Fatalf("server state: %+v", state)
	}
	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("server shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
	if state, err := server.ReadState(); err != nil || state != nil {
		t.Fatalf("state not cleaned: %+v %v", state, err)
	}
}

func TestServerStopTerminatesOwnedProcess(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	child := exec.Command(os.Args[0], "-test.run=^TestServerStopHelper$")
	child.Env = append(os.Environ(), "INFRAGUARD_CLI_STOP_HELPER=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = child.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
		}
	}()
	if err := server.WriteState(&server.State{PID: child.Process.Pid, URL: "http://127.0.0.1:1234"}); err != nil {
		t.Fatal(err)
	}
	if err := runServerStop(nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		stopped = true
	case <-time.After(5 * time.Second):
		t.Fatal("child did not stop")
	}
	if state, err := server.ReadState(); err != nil || state != nil {
		t.Fatalf("state not removed: %+v %v", state, err)
	}
}

func TestServerStopHelper(t *testing.T) {
	if os.Getenv("INFRAGUARD_CLI_STOP_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}

func TestServerStartRemovesStaleStateBeforeForegroundBind(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	oldHost, oldPort, oldForeground := serverHost, serverPort, serverForeground
	t.Cleanup(func() { serverHost, serverPort, serverForeground = oldHost, oldPort, oldForeground })
	if err := server.WriteState(&server.State{PID: 0, URL: "stale"}); err != nil {
		t.Fatal(err)
	}
	serverHost, serverPort, serverForeground = "invalid host name", 0, true
	if err := runServerStart(nil, nil); err == nil || !strings.Contains(err.Error(), "failed to bind") {
		t.Fatalf("foreground bind error: %v", err)
	}
	if state, err := server.ReadState(); err != nil || state != nil {
		t.Fatalf("stale state not removed: %+v %v", state, err)
	}
}

func TestServeClosesListenerIfStateCannotBeWritten(t *testing.T) {
	home := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(home, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := serveWithContext(context.Background(), "127.0.0.1", port, ""); err == nil {
		t.Fatal("server started without a writable state directory")
	}
	listener, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		t.Fatalf("listener remained open after state write failed: %v", err)
	}
	listener.Close()
}

func TestServerWorkerAndBrowserStartupErrors(t *testing.T) {
	oldHost, oldPort, oldToken := runHost, runPort, runToken
	t.Cleanup(func() { runHost, runPort, runToken = oldHost, oldPort, oldToken })
	runHost, runPort, runToken = "invalid host name", 0, ""
	if err := runServerWorker(nil, nil); err == nil || !strings.Contains(err.Error(), "failed to bind") {
		t.Fatalf("worker bind error: %v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows can resolve system commands independently of PATH")
	}
	t.Setenv("PATH", t.TempDir())
	if err := openBrowser("http://127.0.0.1:1234"); err == nil {
		t.Fatal("missing browser command accepted")
	}
}

func TestServerBackgroundStartAndStop(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	t.Setenv("INFRAGUARD_SERVER_WORKER_TEST", "1")
	openLog := filepath.Join(home, "opened-url")
	openOnStart := runtime.GOOS == "darwin" || runtime.GOOS == "linux"
	if openOnStart {
		name := "xdg-open"
		if runtime.GOOS == "darwin" {
			name = "open"
		}
		if err := os.WriteFile(filepath.Join(home, name), []byte("#!/bin/sh\nprintf '%s' \"$1\" > \"$MOCK_BROWSER_LOG\"\n"), 0755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", home)
		t.Setenv("MOCK_BROWSER_LOG", openLog)
	}
	oldHost, oldPort, oldOpen, oldForeground := serverHost, serverPort, serverOpen, serverForeground
	var childPID int
	t.Cleanup(func() {
		if childPID > 0 {
			_ = server.TerminatePID(childPID)
		}
		_ = server.RemoveState()
		serverHost, serverPort, serverOpen, serverForeground = oldHost, oldPort, oldOpen, oldForeground
	})
	serverHost, serverPort, serverOpen, serverForeground = "127.0.0.1", 0, openOnStart, false
	err := runServerStart(nil, nil)
	state, stateErr := server.ReadState()
	if state != nil && state.PID > 1 && state.PID != os.Getpid() {
		childPID = state.PID
	}
	if err != nil || stateErr != nil || childPID == 0 || state.Port == 0 {
		t.Fatalf("background server: state=%+v start=%v state error=%v", state, err, stateErr)
	}
	resp, err := (&http.Client{Timeout: time.Second}).Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", state.Port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status: %d", resp.StatusCode)
	}
	if openOnStart {
		deadline := time.Now().Add(5 * time.Second)
		var opened []byte
		for time.Now().Before(deadline) {
			opened, err = os.ReadFile(openLog)
			if err == nil && string(opened) == state.URL {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil || string(opened) != state.URL {
			t.Fatalf("browser URL %q, expected %q: %v", opened, state.URL, err)
		}
	}
	if err := runServerStop(nil, nil); err != nil {
		t.Fatal(err)
	}
	childPID = 0
	if state, err := server.ReadState(); err != nil || state != nil {
		t.Fatalf("state after stop: %+v %v", state, err)
	}
}
