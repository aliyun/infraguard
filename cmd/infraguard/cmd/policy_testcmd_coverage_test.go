package cmd

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/policytest"
)

func TestPolicyTestCommandExitCodes(t *testing.T) {
	for _, tc := range []struct {
		mode          string
		code          int
		cases, failed int
	}{{"empty", 2, 0, 0}, {"failed", 1, 1, 1}} {
		t.Run(tc.mode, func(t *testing.T) {
			root := t.TempDir()
			if tc.mode == "failed" {
				path := filepath.Join(root, "testdata", "aliyun", "rules", "fixture-absent-rule", "ros", "compliant.yaml")
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestPolicyTestExitHelper$")
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "INFRAGUARD_POLICY_TEST_EXIT="+tc.mode)
			output, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != tc.code {
				t.Fatalf("exit: output=%q error=%v", output, err)
			}
			start := strings.IndexByte(string(output), '{')
			if start < 0 {
				t.Fatalf("missing JSON: %q", output)
			}
			var report struct {
				Summary policytest.Summary `json:"summary"`
			}
			if err := json.NewDecoder(strings.NewReader(string(output[start:]))).Decode(&report); err != nil || report.Summary.Cases != tc.cases || report.Summary.Failed != tc.failed {
				t.Fatalf("summary: %+v %v", report.Summary, err)
			}
		})
	}
}

func TestPolicyTestExitHelper(t *testing.T) {
	mode := os.Getenv("INFRAGUARD_POLICY_TEST_EXIT")
	if (mode != "empty" && mode != "failed") || flag.Lookup("test.run").Value.String() != "^TestPolicyTestExitHelper$" {
		return
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(dir, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(dir, "isolated-workspace"))
	testDir, testIaC, testFormat, testAllowEmpty, testRules = dir, "ros", "json", false, nil
	if mode == "failed" {
		testRules = []string{"fixture-absent-rule"}
	}
	if err := runPolicyTest(nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Fatal("policy test did not exit")
}

func TestPolicyTestCommand(t *testing.T) {
	oldDir, oldRules, oldIaC, oldFormat, oldAllow := testDir, testRules, testIaC, testFormat, testAllowEmpty
	t.Cleanup(func() {
		testDir, testRules, testIaC, testFormat, testAllowEmpty = oldDir, oldRules, oldIaC, oldFormat, oldAllow
	})
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	testDir = t.TempDir()
	testRules = nil
	testIaC = "both"
	testAllowEmpty = true
	testFormat = "invalid"
	if err := runPolicyTest(nil, nil); err == nil {
		t.Fatal("invalid format accepted")
	}
	testFormat = "table"
	testIaC = "invalid"
	if err := runPolicyTest(nil, nil); err == nil {
		t.Fatal("invalid IaC accepted")
	}
	testIaC = "ros"
	if err := runPolicyTest(nil, nil); err != nil {
		t.Fatal(err)
	}
	testFormat = "json"
	if err := runPolicyTest(nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{policytest.CodeNoRule, policytest.CodeExpectOne, policytest.CodeExpectZero, policytest.CodeLoad, policytest.CodeLoadTF, policytest.CodeEval} {
		if testDetail(policytest.CaseResult{Code: code, Detail: "detail"}) == "" {
			t.Errorf("missing detail for %s", code)
		}
	}
	if testDetail(policytest.CaseResult{Code: "unknown"}) != "" {
		t.Fatal("unexpected detail")
	}
	for _, state := range []string{policytest.StatusPass, policytest.StatusFail, policytest.StatusError} {
		if colorTestStatus(state) == "" {
			t.Errorf("missing label for %s", state)
		}
	}
	printTestTable([]policytest.CaseResult{{Rule: "sample", Case: "ros/compliant", Status: policytest.StatusPass}, {Rule: "sample", Case: "ros/violation", Status: policytest.StatusFail, Code: policytest.CodeExpectOne}}, policytest.Summary{Rules: 1, Cases: 2, Passed: 1, Failed: 1})
}

func TestPolicyTestJSON(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old }()
	if err := printTestJSON([]policytest.CaseResult{{Rule: "sample", Status: policytest.StatusPass}}, policytest.Summary{Rules: 1, Cases: 1, Passed: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Schema  string                  `json:"schema_version"`
		Results []policytest.CaseResult `json:"results"`
		Summary policytest.Summary      `json:"summary"`
	}
	if err := json.NewDecoder(f).Decode(&got); err != nil || got.Schema != "1.0" || len(got.Results) != 1 || got.Summary.Passed != 1 {
		t.Fatalf("invalid JSON output: %+v %v", got, err)
	}
}
