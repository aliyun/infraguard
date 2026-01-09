package policies_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/aliyun/infraguard/pkg/engine"
	"github.com/aliyun/infraguard/pkg/models"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/yaml.v3"
)

const (
	policiesTestDir = "."
	policiesDir     = ".."
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

// hasTestTemplates checks if a directory contains both compliant.yaml and violation.yaml
func hasTestTemplates(dir string) bool {
	compliantPath := filepath.Join(dir, "compliant.yaml")
	violationPath := filepath.Join(dir, "violation.yaml")
	_, err1 := os.Stat(compliantPath)
	_, err2 := os.Stat(violationPath)
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

// getRuleFile returns the path to the rule file based on provider and rule name
func getRuleFile(provider, ruleName string) string {
	return filepath.Join(policiesDir, provider, "rules", ruleName+".rego")
}

// getPackFile returns the path to the pack file based on provider and pack name
func getPackFile(provider, packName string) string {
	return filepath.Join(policiesDir, provider, "packs", packName+".rego")
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

	for _, testDir := range testDirs {
		// Extract provider and rule name from path
		// testDir: ./aliyun/rules/rule-name
		provider := "aliyun"
		ruleName := filepath.Base(testDir)
		ruleID := fmt.Sprintf("rule:%s:%s", provider, ruleName)
		ruleFile := getRuleFile(provider, ruleName)

		// Check if rule file exists
		if _, err := os.Stat(ruleFile); os.IsNotExist(err) {
			// Try short rule ID (some rules use short ID in deny result)
			ruleID = ruleName
		}

		t.Run(ruleName, func(t *testing.T) {
			Convey("Given the "+ruleName+" rule", t, func() {
				Convey("When evaluating compliant template", func() {
					compliantPath := filepath.Join(testDir, "compliant.yaml")
					template, err := loadTemplate(compliantPath)
					So(err, ShouldBeNil)

					violations, err := engine.Evaluate(ruleFile, template)

					Convey("It should return no violations for this rule", func() {
						So(err, ShouldBeNil)
						// Filter by both full rule ID and short rule ID
						filtered := filterByRuleID(violations, ruleID)
						if len(filtered) == 0 {
							filtered = filterByRuleID(violations, ruleName)
						}
						So(filtered, ShouldBeEmpty)
					})
				})

				Convey("When evaluating violation template", func() {
					violationPath := filepath.Join(testDir, "violation.yaml")
					template, err := loadTemplate(violationPath)
					So(err, ShouldBeNil)

					violations, err := engine.Evaluate(ruleFile, template)

					Convey("It should return violations for this rule", func() {
						So(err, ShouldBeNil)
						// Filter by both full rule ID and short rule ID
						filtered := filterByRuleID(violations, ruleID)
						if len(filtered) == 0 {
							filtered = filterByRuleID(violations, ruleName)
						}
						So(len(filtered), ShouldBeGreaterThan, 0)
					})
				})
			})
		})
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

	for _, testDir := range testDirs {
		// Extract provider and pack name from path
		// testDir: ./aliyun/packs/pack-name
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
					compliantPath := filepath.Join(testDir, "compliant.yaml")
					template, err := loadTemplate(compliantPath)
					So(err, ShouldBeNil)

					// Evaluate against all rules in the provider directory
					violations, err := engine.Evaluate(rulesDir, template)

					Convey("It should return no violations", func() {
						So(err, ShouldBeNil)
						So(violations, ShouldBeEmpty)
					})
				})

				Convey("When evaluating violation template", func() {
					violationPath := filepath.Join(testDir, "violation.yaml")
					template, err := loadTemplate(violationPath)
					So(err, ShouldBeNil)

					// Evaluate against all rules in the provider directory
					violations, err := engine.Evaluate(rulesDir, template)

					Convey("It should return violations", func() {
						So(err, ShouldBeNil)
						So(len(violations), ShouldBeGreaterThan, 0)
					})
				})
			})
		})
	}
}
