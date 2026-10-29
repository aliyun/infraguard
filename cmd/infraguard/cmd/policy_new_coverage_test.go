package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
)

func TestPolicyNewScaffolding(t *testing.T) {
	oldIaC, oldSeverity, oldDir, oldPack := newIaC, newSeverity, newDir, newPack
	oldROS, oldTF := newResourceTypes, newTFResourceType
	oldNameEN, oldNameZH, oldDescEN, oldDescZH := newNameEN, newNameZH, newDescEN, newDescZH
	oldNoTest, oldForce := newNoTest, newForce
	t.Cleanup(func() {
		newIaC, newSeverity, newDir, newPack = oldIaC, oldSeverity, oldDir, oldPack
		newResourceTypes, newTFResourceType = oldROS, oldTF
		newNameEN, newNameZH, newDescEN, newDescZH = oldNameEN, oldNameZH, oldDescEN, oldDescZH
		newNoTest, newForce = oldNoTest, oldForce
	})
	newDir = t.TempDir()
	newIaC = "both"
	newSeverity = "high"
	newPack = ""
	newNoTest = false
	newForce = true
	newResourceTypes = []string{"ALIYUN::OSS::Bucket"}
	newTFResourceType = []string{"alicloud_oss_bucket"}
	newNameEN = "Example"
	newNameZH = "示例"
	newDescEN = "desc"
	newDescZH = "描述"
	if err := runPolicyNew(nil, []string{"sample-rule"}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"rules/ros/sample-rule.rego", "rules/terraform/sample-rule.rego",
		"testdata/aliyun/rules/sample-rule/ros/compliant.yaml", "testdata/aliyun/rules/sample-rule/ros/violation.yaml",
		"testdata/aliyun/rules/sample-rule/terraform/compliant/main.tf", "testdata/aliyun/rules/sample-rule/terraform/violation/main.tf",
	} {
		if b, err := os.ReadFile(filepath.Join(newDir, filepath.FromSlash(path))); err != nil || !strings.Contains(string(b), "sample-rule") && !strings.HasSuffix(path, "main.tf") {
			t.Errorf("missing/invalid %s: %v", path, err)
		}
	}
	newForce = false
	if err := writeTemplate(filepath.Join(newDir, "rules/ros/sample-rule.rego"), "test", scaffoldCtx{}); err == nil {
		t.Fatal("expected existing file error")
	}
	newPack = "example-pack"
	if err := runPolicyNew(nil, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(newDir, "packs", "example-pack.rego"))
	if err != nil || !strings.Contains(string(b), "example_pack") {
		t.Fatalf("pack contents: %v", err)
	}
	newPack = "Invalid"
	if err := runPolicyNew(nil, nil); err == nil {
		t.Fatal("expected invalid pack id")
	}
	newPack = ""
	newIaC, newSeverity, newNoTest, newForce = "ros", "low", true, true
	newResourceTypes, newTFResourceType, newNameEN, newNameZH = nil, nil, "", ""
	if err := runPolicyNew(nil, []string{"no-fixtures"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(newDir, "testdata", "aliyun", "rules", "no-fixtures")); !os.IsNotExist(err) {
		t.Fatalf("fixtures unexpectedly exist: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(newDir, "rules", "ros", "no-fixtures.rego"))
	if err != nil || !strings.Contains(string(data), "ALIYUN::ECS::Instance") {
		t.Fatalf("default ROS resource type missing: %v", err)
	}
	for _, tc := range []struct {
		args          []string
		iac, severity string
	}{
		{nil, "ros", "high"}, {[]string{"INVALID"}, "ros", "high"}, {[]string{"x"}, "ros", "bad"}, {[]string{"x"}, "bad", "high"},
	} {
		newIaC, newSeverity = tc.iac, tc.severity
		if err := runPolicyNew(nil, tc.args); err == nil {
			t.Errorf("expected validation error for %+v", tc)
		}
	}
	if err := writeTemplate(filepath.Join(newDir, "invalid.rego"), "{{", scaffoldCtx{}); err == nil {
		t.Fatal("expected template parse error")
	}
	if err := writeTemplate(filepath.Join(newDir, "execution.rego"), "{{.Missing}}", scaffoldCtx{}); err == nil {
		t.Fatal("expected template execution error")
	}
}

func TestPolicyNewRejectsDuplicateRuleIDs(t *testing.T) {
	oldDir, oldForce, oldIndex := newDir, newForce, policy.EmbeddedIndex
	t.Cleanup(func() { newDir, newForce, policy.EmbeddedIndex = oldDir, oldForce, oldIndex })
	newDir = t.TempDir()
	t.Setenv("INFRAGUARD_POLICY_DIR", filepath.Join(newDir, "user"))
	t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", filepath.Join(newDir, "workspace"))
	policy.EmbeddedIndex = &models.PolicyIndex{RuleList: []*models.Rule{{ID: "rule:aliyun:builtin"}}}
	newForce = false
	if err := ensureRuleIDAvailable("builtin"); err == nil {
		t.Fatal("builtin rule ID was accepted")
	}
	ruleDir := filepath.Join(newDir, "rules")
	if err := os.MkdirAll(ruleDir, 0755); err != nil {
		t.Fatal(err)
	}
	const rule = `package infraguard.rules.aliyun.local
import rego.v1
rule_meta := {"name": "Local", "severity": "low"}`
	if err := os.WriteFile(filepath.Join(ruleDir, "local.rego"), []byte(rule), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureRuleIDAvailable("local"); err == nil {
		t.Fatal("local rule ID was accepted")
	}
	if err := ensureRuleIDAvailable("new-rule"); err != nil {
		t.Fatalf("new rule ID rejected: %v", err)
	}
	newForce = true
	if err := ensureRuleIDAvailable("builtin"); err != nil {
		t.Fatalf("forced duplicate rejected: %v", err)
	}
}
