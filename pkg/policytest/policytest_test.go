package policytest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
)

const testRule = `package infraguard.rules.test.sample
import rego.v1
deny contains result if {
 input.violate == true
 result := {"id": "sample", "resource_id": "resource", "violation_path": ["violate"], "meta": {"severity": "high", "reason": "test"}}
}`

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestROSFixtures(t *testing.T) {
	dir := t.TempDir()
	rule := &models.Rule{ID: "rule:aliyun:sample", FilePath: "sample.rego", Content: testRule}
	writeFixture(t, filepath.Join(dir, "ros", "compliant.yaml"), "violate: false\n")
	writeFixture(t, filepath.Join(dir, "ros", "violation.yaml"), "violate: true\n")
	got := runROS(dir, "sample", rule, nil)
	if len(got) != 2 || got[0].Status != StatusPass || got[1].Status != StatusPass {
		t.Fatalf("results: %+v", got)
	}
	if got := evalROSCase("sample", rule, "incorrect", filepath.Join(dir, "ros", "violation.yaml"), nil, false); got.Status != StatusFail || got.Code != CodeExpectZero || got.Detail != "1" {
		t.Fatalf("unexpected compliant result: %+v", got)
	}
	if got := evalROSCase("sample", rule, "incorrect", filepath.Join(dir, "ros", "compliant.yaml"), nil, true); got.Status != StatusFail || got.Code != CodeExpectOne {
		t.Fatalf("unexpected violation result: %+v", got)
	}
	writeFixture(t, filepath.Join(dir, "bad.yaml"), "[invalid")
	if got := evalROSCase("sample", rule, "bad", filepath.Join(dir, "bad.yaml"), nil, false); got.Status != StatusError || got.Code != CodeLoad {
		t.Fatalf("invalid yaml: %+v", got)
	}
	rule.Content = "invalid rego"
	if got := evalROSCase("sample", rule, "bad", filepath.Join(dir, "ros", "compliant.yaml"), nil, false); got.Status != StatusError || got.Code != CodeEval {
		t.Fatalf("invalid rego: %+v", got)
	}
}

func TestTerraformFixtures(t *testing.T) {
	dir := t.TempDir()
	rule := &models.Rule{ID: "rule:aliyun:sample", FilePath: "sample.rego", Content: "package infraguard.rules.test.sample\n"}
	writeFixture(t, filepath.Join(dir, "terraform", "compliant", "main.tf"), "resource \"alicloud_vpc\" \"sample\" {}")
	writeFixture(t, filepath.Join(dir, "terraform", "violation", "main.tf"), "resource { invalid")
	got := runTF(dir, "sample", rule, nil)
	if len(got) != 2 || got[0].Status != StatusPass || got[1].Status != StatusError || got[1].Code != CodeLoadTF {
		t.Fatalf("terraform results: %+v", got)
	}
}

func TestRunDiscoversAndFiltersFixtures(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	old := policy.EmbeddedIndex
	t.Cleanup(func() { policy.EmbeddedIndex = old })
	rule := &models.Rule{ID: "rule:aliyun:sample", FilePath: "sample.rego", Content: testRule, IaCTypes: []string{"ros"}}
	policy.EmbeddedIndex = &models.PolicyIndex{RuleList: []*models.Rule{rule}}
	root := filepath.Join(dir, "testdata", "aliyun", "rules")
	writeFixture(t, filepath.Join(root, "sample", "ros", "compliant.yaml"), "violate: false\n")
	writeFixture(t, filepath.Join(root, "sample", "ros", "violation.yaml"), "violate: true\n")
	results, summary, err := Run(Options{Dir: dir, RuleIDs: []string{"rule:aliyun:sample"}, IaC: "ros"})
	if err != nil || len(results) != 2 || summary.Rules != 1 || summary.Cases != 2 || summary.Passed != 2 || summary.Failed != 0 {
		t.Fatalf("results %+v summary %+v err %v", results, summary, err)
	}
	_, summary, err = Run(Options{Dir: dir, RuleIDs: []string{"absent"}})
	if err != nil || summary.Cases != 0 {
		t.Fatalf("filter: %+v %v", summary, err)
	}
	writeFixture(t, filepath.Join(root, "missing", "ros", "compliant.yaml"), "{}")
	results, summary, err = Run(Options{Dir: dir, RuleIDs: []string{"missing"}})
	if err != nil || len(results) != 1 || results[0].Code != CodeNoRule || summary.Cases != 1 || summary.Failed != 1 {
		t.Fatalf("missing rule: %+v summary %+v err %v", results, summary, err)
	}
}

func TestRunDiscoversCustomRuleImplementation(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "isolated-policy"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "isolated-workspace"))
	custom := `package infraguard.rules.aliyun.custom
import rego.v1
rule_meta := {"id": "rule:aliyun:custom", "name": "custom", "severity": "high", "reason": "test"}
deny contains result if {
 input.violate == true
 result := {"id":"custom", "resource_id":"resource", "violation_path":["violate"], "meta":{"severity":"high", "reason":"test"}}
}`
	writeFixture(t, filepath.Join(root, "rules", "aliyun", "ros", "custom.rego"), custom)
	fixture := filepath.Join(root, "testdata", "aliyun", "rules", "custom", "ros")
	writeFixture(t, filepath.Join(fixture, "compliant.yaml"), "violate: false\n")
	writeFixture(t, filepath.Join(fixture, "violation.yaml"), "violate: true\n")
	results, summary, err := Run(Options{Dir: root, IaC: "ros"})
	if err != nil || summary.Rules != 1 || summary.Cases != 2 || summary.Passed != 2 || len(results) != 2 {
		t.Fatalf("custom rule: results=%+v summary=%+v err=%v", results, summary, err)
	}
}

func TestRunDiscoversTerraformFixtures(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(home, "policies"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(home, "workspace"))
	old := policy.EmbeddedIndex
	t.Cleanup(func() { policy.EmbeddedIndex = old })
	rule := &models.Rule{ID: "rule:aliyun:sample", FilePath: "sample.rego", Content: "package infraguard.rules.test.sample\n", IaCTypes: []string{"terraform"}}
	policy.EmbeddedIndex = &models.PolicyIndex{RuleList: []*models.Rule{rule}}
	fixture := filepath.Join(root, "testdata", "aliyun", "rules", "sample", "terraform")
	writeFixture(t, filepath.Join(fixture, "compliant", "main.tf"), `resource "alicloud_vpc" "sample" {}`)
	writeFixture(t, filepath.Join(fixture, "violation", "main.tf"), `resource { invalid`)
	results, summary, err := Run(Options{Dir: root, IaC: "terraform"})
	if err != nil || len(results) != 2 || summary.Rules != 1 || summary.Passed != 1 || summary.Failed != 1 || results[1].Code != CodeLoadTF {
		t.Fatalf("terraform fixtures: %+v %+v %v", results, summary, err)
	}
}
