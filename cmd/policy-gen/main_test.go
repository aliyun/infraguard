package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestGeneratorMainReportsMissingPolicies(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestGeneratorFailureHelper$")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "INFRAGUARD_GENERATOR_FAILURE_TEST=1")
	output, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "policies") {
		t.Fatalf("missing policies: output=%q error=%v", output, err)
	}
}

func TestGeneratorFailureHelper(t *testing.T) {
	if os.Getenv("INFRAGUARD_GENERATOR_FAILURE_TEST") != "1" || flag.Lookup("test.run").Value.String() != "^TestGeneratorFailureHelper$" {
		return
	}
	dir, err := os.MkdirTemp(".", "generator-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	main()
	t.Fatal("generator returned without a policy directory")
}

func TestGenerateIndex(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rule, err := os.ReadFile(filepath.Join(original, "../../pkg/policy/testdata/validate/valid/valid-rule.rego"))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := os.ReadFile(filepath.Join(original, "../../pkg/policy/testdata/validate/valid/valid-pack.rego"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	if err := run(); err == nil {
		t.Fatal("missing policies directory should fail")
	}
	for name, content := range map[string][]byte{
		"policies/aliyun/rules/ros/sample.rego": rule,
		"policies/aliyun/packs/sample.rego":     pack,
		"policies/aliyun/lib/helpers.rego":      []byte("package helper\n"),
	} {
		if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, content, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(); err == nil {
		t.Fatal("missing output directory should fail")
	}
	if err := os.MkdirAll("pkg/policy", 0755); err != nil {
		t.Fatal(err)
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile("pkg/policy/index_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Code generated", "valid-test-rule", "valid-test-pack", strconv.Quote(filepath.Join("aliyun", "lib", "helpers.rego"))} {
		if !strings.Contains(string(first), want) {
			t.Errorf("generated index missing %q", want)
		}
	}
	main() // Exercise the command entry point using the isolated fixture.
	second, err := os.ReadFile("pkg/policy/index_gen.go")
	if err != nil || string(first) != string(second) {
		t.Fatalf("generation is not deterministic: %v", err)
	}
}
