package policies_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/policy"
)

func TestScenarioPacksUseNormalizedNames(t *testing.T) {
	oldUserPolicyDir := os.Getenv("INFRAGUARD_POLICY_DIR")
	oldWorkspacePolicyDir := os.Getenv("INFRAGUARD_WORKSPACE_POLICY_DIR")
	t.Cleanup(func() {
		os.Setenv("INFRAGUARD_POLICY_DIR", oldUserPolicyDir)
		os.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", oldWorkspacePolicyDir)
	})

	userPolicyDir := t.TempDir()
	os.Setenv("INFRAGUARD_POLICY_DIR", userPolicyDir)
	os.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", policiesDir)

	loader, err := policy.LoadWithFallback()
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}

	expectedPacks := map[string]string{
		"pack:aliyun:best-practice":        "aliyun/packs/best-practice/best-practice-pack.rego",
		"pack:aliyun:compliance":           "aliyun/packs/compliance/common-compliance-pack.rego",
		"pack:aliyun:cost-optimization":    "aliyun/packs/cost-optimization/common-cost-optimization-pack.rego",
		"pack:aliyun:elasticity":           "aliyun/packs/elasticity/common-elasticity-pack.rego",
		"pack:aliyun:high-availability":    "aliyun/packs/high-availability/common-high-availability-pack.rego",
		"pack:aliyun:network-architecture": "aliyun/packs/network-architecture/common-network-architecture-pack.rego",
		"pack:aliyun:operations":           "aliyun/packs/operations/common-operations-pack.rego",
		"pack:aliyun:security":             "aliyun/packs/security/common-security-pack.rego",
	}

	for id, filePath := range expectedPacks {
		pack := loader.GetPack(id)
		if pack == nil {
			t.Fatalf("expected scenario pack %s to be loaded", id)
		}
		oldSourceName := "iac" + "-" + "code"
		if strings.Contains(pack.ID, oldSourceName) {
			t.Fatalf("scenario pack %s should not use old source naming", id)
		}
		if got := filepath.ToSlash(pack.FilePath); !strings.HasSuffix(got, filePath) {
			t.Fatalf("pack %s loaded from %s, want suffix %s", id, got, filePath)
		}
		for _, ruleID := range pack.RuleIDs {
			if loader.GetRule(ruleID) == nil {
				t.Fatalf("pack %s references missing rule %s", id, ruleID)
			}
		}
	}

	oldSourcePackPrefix := "pack:aliyun:" + "iac" + "-" + "code" + "-"
	for _, id := range []string{
		oldSourcePackPrefix + "best-practice",
		oldSourcePackPrefix + "compliance",
		oldSourcePackPrefix + "cost-optimization",
		oldSourcePackPrefix + "elasticity",
		oldSourcePackPrefix + "high-availability",
		oldSourcePackPrefix + "network-architecture",
		oldSourcePackPrefix + "operations",
		oldSourcePackPrefix + "security",
		"pack:aliyun:" + "cloud-infrastructure" + "-security-baseline",
	} {
		if pack := loader.GetPack(id); pack != nil {
			t.Fatalf("old scenario pack name %s should not be loaded", id)
		}
	}
}
