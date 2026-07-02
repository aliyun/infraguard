// Command sync-scenario-packs updates top-level scenario packs so each one
// explicitly contains the de-duplicated rule union from its current curated
// rules and all sibling packs in the scenario directory.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aliyun/infraguard/pkg/policy"
)

type scenarioPack struct {
	ID       string
	Dir      string
	PackFile string
}

var scenarioPacks = []scenarioPack{
	{ID: "pack:aliyun:best-practice", Dir: "best-practice", PackFile: "best-practice-pack.rego"},
	{ID: "pack:aliyun:compliance", Dir: "compliance", PackFile: "common-compliance-pack.rego"},
	{ID: "pack:aliyun:cost-optimization", Dir: "cost-optimization", PackFile: "common-cost-optimization-pack.rego"},
	{ID: "pack:aliyun:elasticity", Dir: "elasticity", PackFile: "common-elasticity-pack.rego"},
	{ID: "pack:aliyun:high-availability", Dir: "high-availability", PackFile: "common-high-availability-pack.rego"},
	{ID: "pack:aliyun:network-architecture", Dir: "network-architecture", PackFile: "common-network-architecture-pack.rego"},
	{ID: "pack:aliyun:operations", Dir: "operations", PackFile: "common-operations-pack.rego"},
	{ID: "pack:aliyun:security", Dir: "security", PackFile: "common-security-pack.rego"},
}

var rulesBlockPattern = regexp.MustCompile(`(?s)(\n\t"rules": \[\n).*?(\n\t\])`)

func main() {
	policyRoot := flag.String("policy-root", "policies", "Policy root containing provider directories")
	check := flag.Bool("check", false, "Only report files that need updates")
	flag.Parse()

	if err := run(*policyRoot, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(policyRoot string, check bool) error {
	ruleIDs, err := discoverRuleIDs(policyRoot)
	if err != nil {
		return err
	}

	packsRoot := filepath.Join(policyRoot, "aliyun", "packs")
	changed := false
	for _, scenario := range scenarioPacks {
		scenarioDir := filepath.Join(packsRoot, scenario.Dir)
		rules, err := scenarioRuleIDs(scenarioDir)
		if err != nil {
			return err
		}
		if len(rules) == 0 {
			return fmt.Errorf("%s produced no rules", scenario.ID)
		}
		for _, ruleID := range rules {
			if _, ok := ruleIDs[ruleID]; !ok {
				return fmt.Errorf("%s references missing rule %s", scenario.ID, ruleID)
			}
		}

		targetPath := filepath.Join(scenarioDir, scenario.PackFile)
		updated, err := updateRulesBlock(targetPath, rules, !check)
		if err != nil {
			return err
		}
		if updated {
			changed = true
			if check {
				fmt.Printf("%s needs update (%d rules)\n", targetPath, len(rules))
			} else {
				fmt.Printf("updated %s (%d rules)\n", targetPath, len(rules))
			}
		}
	}

	if check && changed {
		return fmt.Errorf("scenario packs are out of date; run go run scripts/sync-scenario-packs.go")
	}
	if !changed {
		fmt.Println("scenario packs are up to date")
	}
	return nil
}

func discoverRuleIDs(policyRoot string) (map[string]struct{}, error) {
	helpers, err := helperModules(policyRoot)
	if err != nil {
		return nil, err
	}

	rulesDir := filepath.Join(policyRoot, "aliyun", "rules")
	rules, err := policy.DiscoverRulesWithExtraModules(rulesDir, helpers)
	if err != nil {
		return nil, fmt.Errorf("discover rules: %w", err)
	}

	ruleIDs := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		ruleIDs[rule.ID] = struct{}{}
	}
	return ruleIDs, nil
}

func helperModules(policyRoot string) ([]policy.RegoModule, error) {
	libDir := filepath.Join(policyRoot, "aliyun", "lib")
	entries, err := os.ReadDir(libDir)
	if err != nil {
		return nil, fmt.Errorf("read policy lib dir: %w", err)
	}

	var modules []policy.RegoModule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}
		path := filepath.Join(libDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read helper module %s: %w", path, err)
		}
		modules = append(modules, policy.RegoModule{
			Path:    filepath.ToSlash(filepath.Join("aliyun", "lib", entry.Name())),
			Content: string(content),
		})
	}
	return modules, nil
}

func scenarioRuleIDs(scenarioDir string) ([]string, error) {
	packs, err := policy.DiscoverPacks(scenarioDir)
	if err != nil {
		return nil, fmt.Errorf("discover packs in %s: %w", scenarioDir, err)
	}

	// Include the top-level pack's existing rules as curated scenario coverage,
	// then merge in rules from the smaller sibling packs.
	seen := map[string]struct{}{}
	for _, pack := range packs {
		for _, ruleID := range pack.RuleIDs {
			seen[ruleID] = struct{}{}
		}
	}

	rules := make([]string, 0, len(seen))
	for ruleID := range seen {
		rules = append(rules, ruleID)
	}
	sort.Strings(rules)
	return rules, nil
}

func updateRulesBlock(path string, ruleIDs []string, write bool) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}

	if !rulesBlockPattern.MatchString(string(content)) {
		return false, fmt.Errorf("could not find rules block in %s", path)
	}
	rulesBlock := formatRulesBlock(ruleIDs)
	next := rulesBlockPattern.ReplaceAllString(string(content), "${1}"+rulesBlock+"${2}")
	if next == string(content) {
		return false, nil
	}
	if !write {
		return true, nil
	}
	if err := os.WriteFile(path, []byte(next), 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

func formatRulesBlock(ruleIDs []string) string {
	lines := make([]string, 0, len(ruleIDs))
	for i, ruleID := range ruleIDs {
		suffix := ","
		if i == len(ruleIDs)-1 {
			suffix = ""
		}
		lines = append(lines, fmt.Sprintf("\t\t%q%s", shortRuleID(ruleID), suffix))
	}
	return strings.Join(lines, "\n")
}

func shortRuleID(ruleID string) string {
	parts := strings.Split(ruleID, ":")
	if len(parts) >= 3 {
		return parts[len(parts)-1]
	}
	return ruleID
}
