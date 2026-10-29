//go:build ignore

package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSyncCommandReportsMissingPolicyRoot(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestSyncFailureHelper$")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "INFRAGUARD_SYNC_FAILURE_TEST=1")
	output, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "read policy lib dir") {
		t.Fatalf("missing policy root: output=%q error=%v", output, err)
	}
}

func TestSyncFailureHelper(t *testing.T) {
	if os.Getenv("INFRAGUARD_SYNC_FAILURE_TEST") != "1" || flag.Lookup("test.run").Value.String() != "^TestSyncFailureHelper$" {
		return
	}
	dir, err := os.MkdirTemp(".", "sync-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	flag.CommandLine = flag.NewFlagSet("sync-scenario-packs", flag.ContinueOnError)
	os.Args = []string{"sync-scenario-packs", "-policy-root", dir}
	main()
	t.Fatal("sync returned without a policy root")
}

func writeTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestSyncScenarioPacks(t *testing.T) {
	rule, err := os.ReadFile("../pkg/policy/testdata/validate/valid/valid-rule.rego")
	if err != nil {
		t.Fatal(err)
	}
	pack, err := os.ReadFile("../pkg/policy/testdata/validate/valid/valid-pack.rego")
	if err != nil {
		t.Fatal(err)
	}
	pack = []byte(strings.Replace(string(pack), `"rules": ["valid-test-rule"],`, "\"rules\": [\n\t\t\"valid-test-rule\"\n\t],", 1))
	root := t.TempDir()
	if _, err := helperModules(root); err == nil {
		t.Fatal("missing lib directory should fail")
	}
	writeTestFile(t, filepath.Join(root, "aliyun/lib/helpers.rego"), []byte("package example.helpers\n"))
	writeTestFile(t, filepath.Join(root, "aliyun/lib/readme.txt"), []byte("ignored"))
	mods, err := helperModules(root)
	if err != nil || len(mods) != 1 || mods[0].Path != "aliyun/lib/helpers.rego" {
		t.Fatalf("helpers %+v: %v", mods, err)
	}
	writeTestFile(t, filepath.Join(root, "aliyun/rules/ros/a.rego"), rule)
	another := strings.ReplaceAll(strings.ReplaceAll(string(rule), "valid-test-rule", "another-rule"), "valid_test_rule", "another_rule")
	writeTestFile(t, filepath.Join(root, "aliyun/rules/ros/b.rego"), []byte(another))
	dir := filepath.Join(root, "aliyun/packs/example")
	target := filepath.Join(dir, "root.rego")
	writeTestFile(t, target, pack)
	sibling := strings.ReplaceAll(strings.ReplaceAll(string(pack), "valid-test-pack", "sibling"), "valid_test_pack", "sibling")
	sibling = strings.ReplaceAll(sibling, `"valid-test-rule"`, `"another-rule", "valid-test-rule"`)
	writeTestFile(t, filepath.Join(dir, "sibling.rego"), []byte(sibling))
	previous := scenarioPacks
	scenarioPacks = []scenarioPack{{ID: "pack:aliyun:example", Dir: "example", PackFile: "root.rego"}}
	t.Cleanup(func() { scenarioPacks = previous })
	ids, err := scenarioRuleIDs(dir)
	if err != nil || !reflect.DeepEqual(ids, []string{"rule:aliyun:another-rule", "rule:aliyun:valid-test-rule"}) {
		t.Fatalf("IDs %v: %v", ids, err)
	}
	if err := run(root, true); err == nil {
		t.Fatal("check should detect out-of-date pack")
	}
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err != nil {
		t.Fatal(err)
	}
	oldFlags, oldArgs := flag.CommandLine, os.Args
	flag.CommandLine = flag.NewFlagSet("sync-scenario-packs", flag.ContinueOnError)
	os.Args = []string{"sync-scenario-packs", "-policy-root", root, "-check"}
	main()
	flag.CommandLine, os.Args = oldFlags, oldArgs
	data, err := os.ReadFile(target)
	if err != nil || !strings.Contains(string(data), `"another-rule"`) {
		t.Fatalf("missing merged rule: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "aliyun/rules/ros/b.rego")); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err == nil || !strings.Contains(err.Error(), "references missing rule") {
		t.Fatalf("expected missing rule error, got %v", err)
	}
	if _, err := updateRulesBlock(filepath.Join(dir, "missing"), nil, false); err == nil {
		t.Fatal("missing file should fail")
	}
	bad := filepath.Join(dir, "bad.txt")
	writeTestFile(t, bad, []byte("no rules"))
	if _, err := updateRulesBlock(bad, nil, false); err == nil {
		t.Fatal("missing block should fail")
	}
	scenarioPacks = []scenarioPack{{ID: "empty-scenario", Dir: "empty", PackFile: "root.rego"}}
	if err := run(root, true); err == nil || !strings.Contains(err.Error(), "discover packs") {
		t.Fatalf("expected missing scenario directory error, got %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "aliyun", "packs", "empty"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err == nil || !strings.Contains(err.Error(), "produced no rules") {
		t.Fatalf("expected empty scenario error, got %v", err)
	}
	missingRulesRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(missingRulesRoot, "aliyun", "lib"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := discoverRuleIDs(missingRulesRoot); err == nil || !strings.Contains(err.Error(), "discover rules") {
		t.Fatalf("expected missing rules directory error, got %v", err)
	}
}
