package policies_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/engine"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
	"github.com/aliyun/infraguard/pkg/providers/terraform"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/yaml.v3"
)

const (
	policiesTestDir = "testdata"
	policiesDir     = "."
)

// loadTemplate loads a YAML template file and returns it as a map
func loadTemplate(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var template map[string]interface{}
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, err
	}
	return template, nil
}

// hasTestTemplates checks if a directory contains test templates in ros/ or terraform/ subdirectories.
func hasTestTemplates(dir string) bool {
	// Check ROS format: ros/compliant.yaml and ros/violation.yaml
	rosCompliant := filepath.Join(dir, "ros", "compliant.yaml")
	rosViolation := filepath.Join(dir, "ros", "violation.yaml")
	_, err1 := os.Stat(rosCompliant)
	_, err2 := os.Stat(rosViolation)
	if err1 == nil && err2 == nil {
		return true
	}
	// Check Terraform format: terraform/compliant/main.tf and terraform/violation/main.tf
	tfCompliant := filepath.Join(dir, "terraform", "compliant", "main.tf")
	tfViolation := filepath.Join(dir, "terraform", "violation", "main.tf")
	_, err1 = os.Stat(tfCompliant)
	_, err2 = os.Stat(tfViolation)
	return err1 == nil && err2 == nil
}

// discoverTestDirs discovers all test directories under a base path
func discoverTestDirs(basePath string) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(basePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && hasTestTemplates(path) {
			dirs = append(dirs, path)
		}
		return nil
	})
	return dirs, err
}

// filterByRuleID filters violations by rule ID
func filterByRuleID(violations []models.OPAViolation, ruleID string) []models.OPAViolation {
	var filtered []models.OPAViolation
	for _, v := range violations {
		if v.ID == ruleID {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// getRuleFile returns the path to the rule file based on provider, rule name, and IaC type.
// When iacType is specified, it looks in that subdirectory first.
func getRuleFile(provider, ruleName, iacType string) string {
	if iacType != "" {
		path := filepath.Join(policiesDir, provider, "rules", iacType, ruleName+".rego")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	// Check IaC type subdirectories
	for _, it := range []string{"ros", "terraform"} {
		path := filepath.Join(policiesDir, provider, "rules", it, ruleName+".rego")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	// Fallback to flat structure (backward compat)
	return filepath.Join(policiesDir, provider, "rules", ruleName+".rego")
}

// buildEvalOpts constructs EvalOptions using the correct implementation for the given IaC type.
func buildEvalOpts(loader *policy.Loader, ruleID, iacType, ruleFile string, libModules map[string]string) *engine.EvalOptions {
	opts := &engine.EvalOptions{
		LibModules: libModules,
	}
	rule := loader.GetRule(ruleID)
	if rule != nil {
		// Pick the implementation matching the test's IaC type
		if iacType != "" && rule.Implementations != nil {
			if impl, ok := rule.Implementations[iacType]; ok && impl.Content != "" {
				opts.Modules = map[string]string{impl.FilePath: impl.Content}
				return opts
			}
		}
		if rule.Content != "" {
			opts.Modules = map[string]string{rule.FilePath: rule.Content}
			return opts
		}
	}
	opts.PolicyPaths = []string{ruleFile}
	return opts
}

// getPackFile returns the path to the pack file based on provider and pack name
func getPackFile(provider, packName string) string {
	return filepath.Join(policiesDir, provider, "packs", packName+".rego")
}

func containsIaCType(types []string, target string) bool {
	for _, t := range types {
		if t == target {
			return true
		}
	}
	return false
}

// extractShortRuleID extracts the short ID from a full rule ID.
// e.g., "rule:aliyun:rds-instance-enabled-tde" -> "rds-instance-enabled-tde"
func extractShortRuleID(fullID string) string {
	if !strings.HasPrefix(fullID, "rule:") && !strings.HasPrefix(fullID, "pack:") {
		return fullID // Already a short ID
	}
	parts := strings.Split(fullID, ":")
	if len(parts) >= 3 {
		return parts[len(parts)-1]
	}
	return fullID
}

func TestPolicyRules(t *testing.T) {
	rulesTestDir := filepath.Join(policiesTestDir, "aliyun", "rules")
	if _, err := os.Stat(rulesTestDir); os.IsNotExist(err) {
		t.Skip("testdata/aliyun/rules directory not found")
		return
	}

	testDirs, err := discoverTestDirs(rulesTestDir)
	if err != nil {
		t.Fatalf("Failed to discover test directories: %v", err)
	}

	if len(testDirs) == 0 {
		t.Skip("No rule test directories found")
		return
	}

	// Set environment variable to use the policies directory for testing
	oldWorkspaceDir := os.Getenv("INFRAGUARD_WORKSPACE_POLICY_DIR")
	os.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", policiesDir)
	defer os.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", oldWorkspaceDir)

	// Load policy index for optimized evaluation
	loader, err := policy.LoadWithFallback()
	if err != nil {
		t.Fatalf("Failed to load policy index: %v", err)
	}
	libModules := loader.GetLibModules()

	for _, testDir := range testDirs {
		// Extract provider and rule name from path
		// testDir: testdata/aliyun/rules/rule-name (contains ros/ and/or terraform/ subdirs)
		provider := "aliyun"
		ruleName := filepath.Base(testDir)
		ruleID := fmt.Sprintf("rule:%s:%s", provider, ruleName)

		// Check if rule file exists
		if _, err := os.Stat(getRuleFile(provider, ruleName, "")); os.IsNotExist(err) {
			ruleID = ruleName
		}

		// Test ROS if ros/ subdirectory exists
		rosDir := filepath.Join(testDir, "ros")
		if _, err := os.Stat(filepath.Join(rosDir, "compliant.yaml")); err == nil {
			testIaCType := "ros"
			ruleFile := getRuleFile(provider, ruleName, testIaCType)

			t.Run(ruleName+"/ros", func(t *testing.T) {
				Convey("Given the ROS "+ruleName+" rule", t, func() {
					Convey("When evaluating compliant template", func() {
						compliantPath := filepath.Join(rosDir, "compliant.yaml")
						relPath, _ := filepath.Rel(policiesDir, compliantPath)
						template, err := loadTemplate(compliantPath)
						So(err, ShouldBeNil)

						opts := buildEvalOpts(loader, ruleID, testIaCType, ruleFile, libModules)

						evalResult, err := engine.EvaluateWithOpts(opts, template)
						violations := []models.OPAViolation{}
						if err == nil {
							violations = evalResult.Violations
						}

						Convey("It should return no violations for this rule", func() {
							So(err, ShouldBeNil)
							filtered := filterByRuleID(violations, ruleID)
							if len(filtered) == 0 {
								filtered = filterByRuleID(violations, ruleName)
							}
							if len(filtered) > 0 {
								t.Logf("Template file: %s", relPath)
								t.Logf("Unexpected violations found: %+v", filtered)
							}
							So(filtered, ShouldBeEmpty)
						})
					})

					Convey("When evaluating violation template", func() {
						violationPath := filepath.Join(rosDir, "violation.yaml")
						relPath, _ := filepath.Rel(policiesDir, violationPath)
						template, err := loadTemplate(violationPath)
						So(err, ShouldBeNil)

						opts := buildEvalOpts(loader, ruleID, testIaCType, ruleFile, libModules)

						evalResult, err := engine.EvaluateWithOpts(opts, template)
						violations := []models.OPAViolation{}
						if err == nil {
							violations = evalResult.Violations
						}

						Convey("It should return violations for this rule", func() {
							So(err, ShouldBeNil)
							filtered := filterByRuleID(violations, ruleID)
							if len(filtered) == 0 {
								filtered = filterByRuleID(violations, ruleName)
							}
							if len(filtered) == 0 {
								t.Logf("Template file: %s", relPath)
								t.Logf("Expected violations but found none")
							}
							So(len(filtered), ShouldBeGreaterThan, 0)
						})
					})
				})
			})
		}

		// Test Terraform if terraform/ subdirectory exists
		tfDir := filepath.Join(testDir, "terraform")
		if _, err := os.Stat(filepath.Join(tfDir, "compliant", "main.tf")); err == nil {
			testIaCType := "terraform"
			ruleFile := getRuleFile(provider, ruleName, testIaCType)

			t.Run(ruleName+"/terraform", func(t *testing.T) {
				Convey("Given the Terraform "+ruleName+" rule", t, func() {
					Convey("When evaluating compliant terraform config", func() {
						compliantDir := filepath.Join(tfDir, "compliant")
						template, err := terraform.Load(compliantDir, nil)
						So(err, ShouldBeNil)

						opts := buildEvalOpts(loader, ruleID, testIaCType, ruleFile, libModules)

						evalResult, err := engine.EvaluateWithOpts(opts, template)
						violations := []models.OPAViolation{}
						if err == nil {
							violations = evalResult.Violations
						}

						Convey("It should return no violations for this rule", func() {
							So(err, ShouldBeNil)
							filtered := filterByRuleID(violations, ruleID)
							if len(filtered) == 0 {
								filtered = filterByRuleID(violations, ruleName)
							}
							if len(filtered) > 0 {
								t.Logf("Template dir: %s", compliantDir)
								t.Logf("Unexpected violations found: %+v", filtered)
							}
							So(filtered, ShouldBeEmpty)
						})
					})

					Convey("When evaluating violation terraform config", func() {
						violationDir := filepath.Join(tfDir, "violation")
						template, err := terraform.Load(violationDir, nil)
						So(err, ShouldBeNil)

						opts := buildEvalOpts(loader, ruleID, testIaCType, ruleFile, libModules)

						evalResult, err := engine.EvaluateWithOpts(opts, template)
						violations := []models.OPAViolation{}
						if err == nil {
							violations = evalResult.Violations
						}

						Convey("It should return violations for this rule", func() {
							So(err, ShouldBeNil)
							filtered := filterByRuleID(violations, ruleID)
							if len(filtered) == 0 {
								filtered = filterByRuleID(violations, ruleName)
							}
							if len(filtered) == 0 {
								t.Logf("Template dir: %s", violationDir)
								t.Logf("Expected violations but found none")
							}
							So(len(filtered), ShouldBeGreaterThan, 0)
						})
					})
				})
			})
		}
	}
}

func TestPolicyPacks(t *testing.T) {
	packsTestDir := filepath.Join(policiesTestDir, "aliyun", "packs")
	if _, err := os.Stat(packsTestDir); os.IsNotExist(err) {
		t.Skip("testdata/aliyun/packs directory not found")
		return
	}

	testDirs, err := discoverTestDirs(packsTestDir)
	if err != nil {
		t.Fatalf("Failed to discover test directories: %v", err)
	}

	if len(testDirs) == 0 {
		t.Skip("No pack test directories found")
		return
	}

	// Set environment variable to use the policies directory for testing
	oldWorkspaceDir := os.Getenv("INFRAGUARD_WORKSPACE_POLICY_DIR")
	os.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", policiesDir)
	defer os.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", oldWorkspaceDir)

	// Load policy index for optimized evaluation
	loader, err := policy.LoadWithFallback()
	if err != nil {
		t.Fatalf("Failed to load policy index: %v", err)
	}
	libModules := loader.GetLibModules()

	// Build ID mapping for short IDs to full IDs
	idMapping := make(map[string]string)
	for _, rule := range loader.GetAllRules() {
		shortID := extractShortRuleID(rule.ID)
		if shortID != rule.ID {
			idMapping[shortID] = rule.ID
		}
	}

	for _, testDir := range testDirs {
		// Extract provider and pack name from path
		// testDir: testdata/aliyun/packs/pack-name
		provider := "aliyun"
		packName := filepath.Base(testDir)
		packFile := getPackFile(provider, packName)

		// For pack testing, we evaluate all rules in the pack directory
		// Pack tests verify that the combined rules work correctly
		rulesDir := filepath.Join(policiesDir, provider, "rules")

		t.Run(packName, func(t *testing.T) {
			Convey("Given the "+packName+" pack", t, func() {
				// Skip if pack file doesn't exist
				if _, err := os.Stat(packFile); os.IsNotExist(err) {
					SkipConvey("Pack file not found: "+packFile, func() {})
					return
				}

				Convey("When evaluating compliant template", func() {
					compliantPath := filepath.Join(testDir, "ros", "compliant.yaml")
					relPath, _ := filepath.Rel(policiesDir, compliantPath)
					template, err := loadTemplate(compliantPath)
					So(err, ShouldBeNil)

					// Parse pack to get rules
					content, err := os.ReadFile(packFile)
					So(err, ShouldBeNil)
					pack, err := policy.ParsePackFromContentWithPath(string(content), packFile, filepath.Join(policiesDir, provider, "packs"))
					So(err, ShouldBeNil)
					So(pack, ShouldNotBeNil)

					// Evaluate against all rules in the provider directory, but filter by pack rules
					opts := &engine.EvalOptions{
						RuleIDs:    pack.RuleIDs,
						LibModules: libModules,
						IDMapping:  idMapping,
					}
					// Add rule contents from index, filtering to ROS-compatible rules only
					opts.Modules = make(map[string]string)
					for _, rID := range pack.RuleIDs {
						rule := loader.GetRule(rID)
						if rule == nil {
							continue
						}
						if !containsIaCType(rule.IaCTypes, "ros") {
							continue
						}
						if rule.Content != "" {
							opts.Modules[rule.FilePath] = rule.Content
						}
					}
					// If no modules added, fallback to ROS rules path
					if len(opts.Modules) == 0 {
						opts.PolicyPaths = []string{filepath.Join(rulesDir, "ros")}
					}

					evalResult, err := engine.EvaluateWithOpts(opts, template)
					So(err, ShouldBeNil)
					violations := evalResult.Violations

					Convey("It should return no violations", func() {
						if len(violations) > 0 {
							t.Logf("Template file: %s", relPath)
							t.Logf("Unexpected violations found: %+v", violations)
						}
						So(violations, ShouldBeEmpty)
					})
				})

				Convey("When evaluating violation template", func() {
					violationPath := filepath.Join(testDir, "ros", "violation.yaml")
					relPath, _ := filepath.Rel(policiesDir, violationPath)
					template, err := loadTemplate(violationPath)
					So(err, ShouldBeNil)

					// Parse pack to get rules
					content, err := os.ReadFile(packFile)
					So(err, ShouldBeNil)
					pack, err := policy.ParsePackFromContentWithPath(string(content), packFile, filepath.Join(policiesDir, provider, "packs"))
					So(err, ShouldBeNil)
					So(pack, ShouldNotBeNil)

					// Evaluate against all rules in the provider directory, but filter by pack rules
					opts := &engine.EvalOptions{
						RuleIDs:    pack.RuleIDs,
						LibModules: libModules,
						IDMapping:  idMapping,
					}
					// Add rule contents from index, filtering to ROS-compatible rules only
					opts.Modules = make(map[string]string)
					for _, rID := range pack.RuleIDs {
						rule := loader.GetRule(rID)
						if rule == nil {
							continue
						}
						if !containsIaCType(rule.IaCTypes, "ros") {
							continue
						}
						if rule.Content != "" {
							opts.Modules[rule.FilePath] = rule.Content
						}
					}
					// If no modules added, fallback to ROS rules path
					if len(opts.Modules) == 0 {
						opts.PolicyPaths = []string{filepath.Join(rulesDir, "ros")}
					}

					evalResult, err := engine.EvaluateWithOpts(opts, template)
					So(err, ShouldBeNil)
					violations := evalResult.Violations

					Convey("It should return violations", func() {
						if len(violations) == 0 {
							t.Logf("Template file: %s", relPath)
							t.Logf("Expected violations but found none")
						}
						So(len(violations), ShouldBeGreaterThan, 0)
					})
				})
			})
		})
	}
}
