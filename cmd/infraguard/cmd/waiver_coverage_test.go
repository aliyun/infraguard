package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aliyun/infraguard/pkg/waiver"
)

func TestWaiverListAndLint(t *testing.T) {
	oldFile, oldRules := waiverFile, waiverRulesDir
	t.Cleanup(func() { waiverFile, waiverRulesDir = oldFile, oldRules })
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(dir, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(dir, "isolated-workspace"))
	waiverFile = filepath.Join(dir, "waivers.yaml")
	waiverRulesDir = ""
	if _, err := resolveWaiverSet(); err == nil {
		t.Fatal("missing waiver file should fail")
	}
	if err := runWaiverList(nil, nil); err == nil {
		t.Fatal("list should fail for missing file")
	}
	if err := runWaiverLint(nil, nil); err == nil {
		t.Fatal("lint should fail for missing file")
	}
	if err := waiver.Save(waiverFile, nil); err != nil {
		t.Fatal(err)
	}
	if err := runWaiverList(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := runWaiverLint(nil, nil); err != nil {
		t.Fatal(err)
	}
	entries := []waiver.Waiver{
		{Rule: "*", Reason: "active", Expires: "2099-12-31"},
		{Rule: "*", Resource: "my-resource", Reason: "expired", Expires: "2000-01-01"},
		{Rule: "*", Reason: "permanent"},
	}
	if err := waiver.Save(waiverFile, entries); err != nil {
		t.Fatal(err)
	}
	if err := runWaiverList(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := runWaiverLint(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := waiver.Save(waiverFile, []waiver.Waiver{{Expires: "bad"}}); err != nil {
		t.Fatal(err)
	}
	if err := runWaiverLint(nil, nil); err == nil {
		t.Fatal("invalid waiver should fail lint")
	}
	for _, code := range []string{waiver.CodeMissingRule, waiver.CodeMissingReason, waiver.CodeUnknownRule, waiver.CodeInvalidExpires, waiver.CodeExpired, waiver.CodePermanent} {
		if lintMessage(waiver.Issue{Code: code, Detail: "example"}) == "" {
			t.Errorf("no message for %s", code)
		}
	}
	if lintMessage(waiver.Issue{Code: "unknown"}) != "" {
		t.Fatal("unexpected unknown message")
	}
	if err := os.WriteFile(waiverFile, []byte("[invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveWaiverSet(); err == nil {
		t.Fatal("invalid waiver YAML should fail")
	}
}

func TestWaiverAutoDetectionAndWorkspaceRules(t *testing.T) {
	dir := t.TempDir()
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	oldFile, oldRules := waiverFile, waiverRulesDir
	t.Cleanup(func() { waiverFile, waiverRulesDir = oldFile, oldRules; _ = os.Chdir(original) })
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(dir, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(dir, "isolated-workspace"))
	waiverFile, waiverRulesDir = "", ""
	if _, err := resolveWaiverSet(); err == nil {
		t.Fatal("missing auto-detected waiver file accepted")
	}
	if err := waiver.Save(waiver.DefaultRelPath, []waiver.Waiver{{Rule: "custom-rule", Reason: "approved"}}); err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join("policies", "rules", "custom-rule.rego")
	if err := os.MkdirAll(filepath.Dir(rulePath), 0755); err != nil {
		t.Fatal(err)
	}
	const rule = `package infraguard.rules.aliyun.custom_rule
import rego.v1
rule_meta := {"name": "Custom", "severity": "low"}`
	if err := os.WriteFile(rulePath, []byte(rule), 0644); err != nil {
		t.Fatal(err)
	}
	if set, err := resolveWaiverSet(); err != nil || len(set.Waivers) != 1 {
		t.Fatalf("auto-detected waivers: %+v %v", set, err)
	}
	if err := runWaiverLint(nil, nil); err != nil {
		t.Fatalf("workspace rule should be known: %v", err)
	}
}
