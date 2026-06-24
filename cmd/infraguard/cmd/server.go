package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/aliyun/infraguard/pkg/config"
	"github.com/aliyun/infraguard/pkg/server"
	"github.com/spf13/cobra"
)

var (
	serverHost       string
	serverPort       int
	serverOpen       bool
	serverForeground bool
	runHost          string
	runPort          int
	runToken         string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the local web UI server",
	Long: `Run the InfraGuard local web UI as a background daemon.

  infraguard server start    # start in the background, print the URL
  infraguard server status   # show whether it is running and where
  infraguard server stop     # stop the running server`,
}

var serverStartCmd = &cobra.Command{
	Use:          "start",
	Short:        "Start the web UI server in the background",
	Args:         cobra.NoArgs,
	RunE:         runServerStart,
	SilenceUsage: true,
}

var serverStopCmd = &cobra.Command{
	Use:          "stop",
	Short:        "Stop the running web UI server",
	Args:         cobra.NoArgs,
	RunE:         runServerStop,
	SilenceUsage: true,
}

var serverStatusCmd = &cobra.Command{
	Use:          "status",
	Short:        "Show web UI server status",
	Args:         cobra.NoArgs,
	RunE:         runServerStatus,
	SilenceUsage: true,
}

// serverRunCmd is the hidden foreground worker that the daemon re-execs into.
var serverRunCmd = &cobra.Command{
	Use:          "__run",
	Hidden:       true,
	Args:         cobra.NoArgs,
	RunE:         runServerWorker,
	SilenceUsage: true,
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.AddCommand(serverStartCmd, serverStopCmd, serverStatusCmd, serverRunCmd)

	serverStartCmd.Flags().StringVar(&serverHost, "host", "127.0.0.1", "Host/address to bind")
	serverStartCmd.Flags().IntVar(&serverPort, "port", 9527, "Port to bind (0 = random free port)")
	serverStartCmd.Flags().BoolVar(&serverOpen, "open", false, "Open the URL in a browser after starting")
	serverStartCmd.Flags().BoolVarP(&serverForeground, "foreground", "f", false, "Run in the foreground instead of detaching")

	serverRunCmd.Flags().StringVar(&runHost, "host", "127.0.0.1", "")
	serverRunCmd.Flags().IntVar(&runPort, "port", 9527, "")
	serverRunCmd.Flags().StringVar(&runToken, "token", "", "")
}

func runServerStart(cmd *cobra.Command, args []string) error {
	if existing, _ := server.ReadState(); existing != nil {
		if existing.IsRunning() {
			return fmt.Errorf("server already running at %s (use `infraguard server stop` first)", existing.URL)
		}
		_ = server.RemoveState() // stale state
	}

	if serverHost != "127.0.0.1" && serverHost != "localhost" {
		fmt.Fprintf(os.Stderr, "Warning: binding to %s exposes the server beyond localhost; a token is required.\n", serverHost)
	}

	token := server.GenerateToken()

	// Foreground mode: serve inline.
	if serverForeground {
		return serve(serverHost, serverPort, token)
	}

	// Background mode: re-exec a detached worker.
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logFile, _ := serverLogPath()
	args2 := []string{"server", "__run", "--host", serverHost, "--port", fmt.Sprintf("%d", serverPort), "--token", token}
	worker := exec.Command(exe, args2...)
	worker.SysProcAttr = server.DetachAttr()
	if logFile != "" {
		if f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
			worker.Stdout = f
			worker.Stderr = f
		}
	}
	if err := worker.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	_ = worker.Process.Release()

	// Wait for readiness via the state file + health check.
	st, err := waitReady(5 * time.Second)
	if err != nil {
		return err
	}
	fmt.Printf("InfraGuard server started: %s\n", st.URL)
	fmt.Printf("  PID %d  |  stop with `infraguard server stop`\n", st.PID)
	if serverOpen {
		_ = openBrowser(st.URL)
	}
	return nil
}

func runServerStop(cmd *cobra.Command, args []string) error {
	st, err := server.ReadState()
	if err != nil {
		return err
	}
	if st == nil || !st.IsRunning() {
		_ = server.RemoveState()
		fmt.Println("Server is not running.")
		return nil
	}
	if err := server.TerminatePID(st.PID); err != nil {
		return fmt.Errorf("failed to stop server (PID %d): %w", st.PID, err)
	}
	// Wait briefly for it to exit.
	for i := 0; i < 50; i++ {
		if !server.ProcessAlive(st.PID) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = server.RemoveState()
	fmt.Println("Server stopped.")
	return nil
}

func runServerStatus(cmd *cobra.Command, args []string) error {
	st, err := server.ReadState()
	if err != nil {
		return err
	}
	if st == nil || !st.IsRunning() {
		fmt.Println("Server is not running.")
		return nil
	}
	fmt.Printf("Server is running.\n")
	fmt.Printf("  URL:     %s\n", st.URL)
	fmt.Printf("  PID:     %d\n", st.PID)
	fmt.Printf("  Uptime:  %s\n", time.Since(st.StartedAt).Round(time.Second))
	fmt.Printf("  Version: %s\n", st.Version)
	return nil
}

func runServerWorker(cmd *cobra.Command, args []string) error {
	return serve(runHost, runPort, runToken)
}

// serve binds and runs the HTTP server, recording state until it exits.
func serve(host string, port int, token string) error {
	srv := server.New(server.Options{Host: host, Port: port, Token: token, Version: Version})
	ln, err := srv.Listen()
	if err != nil {
		return fmt.Errorf("failed to bind %s:%d: %w", host, port, err)
	}

	url := buildURL(host, srv.Port(), token)
	state := &server.State{
		PID:       os.Getpid(),
		Host:      host,
		Port:      srv.Port(),
		URL:       url,
		Token:     token,
		StartedAt: time.Now(),
		Version:   Version,
	}
	if err := server.WriteState(state); err != nil {
		return err
	}
	defer server.RemoveState()

	if serverForeground {
		fmt.Printf("InfraGuard server listening on %s (Ctrl-C to stop)\n", url)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return srv.Serve(ctx, ln)
}

func buildURL(host string, port int, token string) string {
	display := host
	if host == "0.0.0.0" || host == "::" {
		display = "127.0.0.1"
	}
	url := fmt.Sprintf("http://%s:%d", display, port)
	if !server.IsLoopback(display) && token != "" {
		url += "/?token=" + token
	}
	return url
}

func waitReady(timeout time.Duration) (*server.State, error) {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	for time.Now().Before(deadline) {
		st, _ := server.ReadState()
		if st != nil && st.IsRunning() {
			if resp, err := client.Get(fmt.Sprintf("http://%s:%d/healthz", st.Host, st.Port)); err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return st, nil
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("server did not become ready in time; check the log")
}

func serverLogPath() (string, error) {
	dir, err := config.DefaultConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "server.log"), nil
}

func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	return exec.Command(cmd, append(args, url)...).Start()
}
