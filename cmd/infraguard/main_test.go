package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMainRejectsInvalidFlag(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainInvalidFlagHelper$")
	cmd.Env = append(os.Environ(), "INFRAGUARD_MAIN_INVALID_FLAG_TEST=1", "HOME="+home, "USERPROFILE="+home)
	output, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "unknown flag") {
		t.Fatalf("invalid flag: output=%q error=%v", output, err)
	}
}

func TestMainInvalidFlagHelper(t *testing.T) {
	if os.Getenv("INFRAGUARD_MAIN_INVALID_FLAG_TEST") != "1" {
		return
	}
	os.Args = []string{"infraguard", "--unknown-flag"}
	main()
	t.Fatal("main returned for an invalid flag")
}

func TestMainHelp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	args, stdout := os.Args, os.Stdout
	t.Cleanup(func() { os.Args, os.Stdout = args, stdout })
	output, err := os.Create(filepath.Join(home, "help.txt"))
	if err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"infraguard", "--help"}
	os.Stdout = output
	main()
	os.Stdout = stdout
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output.Name())
	if err != nil || !strings.Contains(string(data), "infraguard") || !strings.Contains(string(data), "scan") {
		t.Fatalf("help=%q err=%v", data, err)
	}
}
