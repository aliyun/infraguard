//go:build ignore

package main

import (
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestFetchCommandRequiresCredentials(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestFetchFailureHelper$")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "INFRAGUARD_FETCH_FAILURE_TEST=1", "ALIBABA_CLOUD_ACCESS_KEY_ID=", "ALIBABA_CLOUD_ACCESS_KEY_SECRET=")
	output, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "Failed to create ROS client") {
		t.Fatalf("missing credentials: output=%q error=%v", output, err)
	}
}

func TestFetchFailureHelper(t *testing.T) {
	if os.Getenv("INFRAGUARD_FETCH_FAILURE_TEST") != "1" || flag.Lookup("test.run").Value.String() != "^TestFetchFailureHelper$" {
		return
	}
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "")
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "")
	flag.CommandLine = flag.NewFlagSet("fetch-ros-schema", flag.ContinueOnError)
	os.Args = []string{"fetch-ros-schema"}
	main()
	t.Fatal("fetch returned without credentials")
}

func TestCreateClient(t *testing.T) {
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "")
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "")
	if _, err := createClient(); err == nil {
		t.Fatal("expected missing credentials error")
	}
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "test-key")
	if _, err := createClient(); err == nil {
		t.Fatal("expected missing secret error")
	}
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "test-secret")
	client, err := createClient()
	if err != nil || client == nil {
		t.Fatalf("client: %v %v", client, err)
	}
}
