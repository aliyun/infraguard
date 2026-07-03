package policies_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
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

		scenarioDir := filepath.Dir(filepath.Join(policiesDir, filePath))
		dirPacks, err := policy.DiscoverPacks(scenarioDir)
		if err != nil {
			t.Fatalf("discover packs for %s: %v", scenarioDir, err)
		}
		if got, want := pack.RuleIDs, sortedUnique(pack.RuleIDs); !equalStrings(got, want) {
			t.Fatalf("scenario pack %s rules should be sorted and de-duplicated:\ngot  %d %v\nwant %d %v", id, len(got), got, len(want), want)
		}
		siblingRules := sortedUnique(packRuleIDsExcept(dirPacks, id))
		if missing := missingStrings(pack.RuleIDs, siblingRules); len(missing) > 0 {
			t.Fatalf("scenario pack %s does not include all sibling pack rules: missing %d %v", id, len(missing), missing)
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

func packRuleIDsExcept(packs []*models.Pack, excludedID string) []string {
	var ruleIDs []string
	for _, pack := range packs {
		if pack.ID == excludedID {
			continue
		}
		ruleIDs = append(ruleIDs, pack.RuleIDs...)
	}
	return ruleIDs
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func missingStrings(have, want []string) []string {
	seen := make(map[string]struct{}, len(have))
	for _, value := range have {
		seen[value] = struct{}{}
	}
	var missing []string
	for _, value := range want {
		if _, ok := seen[value]; !ok {
			missing = append(missing, value)
		}
	}
	return missing
}
