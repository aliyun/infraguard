package policies_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aliyun/infraguard/pkg/engine"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/providers/terraform"
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

// hasROSTestTemplates checks if a directory contains both ros/compliant.yaml and ros/violation.yaml
func hasROSTestTemplates(dir string) bool {
	compliantPath := filepath.Join(dir, "ros", "compliant.yaml")
	violationPath := filepath.Join(dir, "ros", "violation.yaml")
	_, err1 := os.Stat(compliantPath)
	_, err2 := os.Stat(violationPath)
	return err1 == nil && err2 == nil
}

// discoverROSTestDirs discovers all test directories that have ros/ subdirectory with test templates
func discoverROSTestDirs(basePath string) ([]string, error) {
	var dirs []string
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			dir := filepath.Join(basePath, e.Name())
			if hasROSTestTemplates(dir) {
				dirs = append(dirs, dir)
			}
		}
	}
	return dirs, nil
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
	return filepath.Join(policiesDir, provider, "rules", "ros", ruleName+".rego")
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

	testDirs, err := discoverROSTestDirs(rulesTestDir)
	if err != nil {
		t.Fatalf("Failed to discover test directories: %v", err)
	}

	if len(testDirs) == 0 {
		t.Skip("No rule test directories found")
		return
	}

	rosLibFile := filepath.Join(policiesDir, "aliyun", "lib", "helpers.rego")

	for _, testDir := range testDirs {
		provider := "aliyun"
		ruleName := filepath.Base(testDir)
		ruleID := ruleName
		ruleFile := getRuleFile(provider, ruleName)

		// Check if rule file exists
		if _, err := os.Stat(ruleFile); os.IsNotExist(err) {
			t.Logf("Skipping %s: rule file not found at %s", ruleName, ruleFile)
			continue
		}

		t.Run(ruleName, func(t *testing.T) {
			Convey("Given the "+ruleName+" rule", t, func() {
				Convey("When evaluating compliant template", func() {
					compliantPath := filepath.Join(testDir, "ros", "compliant.yaml")
					template, err := loadTemplate(compliantPath)
					So(err, ShouldBeNil)

					opts := &engine.EvalOptions{
						PolicyPaths: []string{ruleFile, rosLibFile},
					}
					result, err := engine.EvaluateWithOpts(opts, template)

					Convey("It should return no violations for this rule", func() {
						So(err, ShouldBeNil)
						filtered := filterByRuleID(result.Violations, ruleID)
						So(filtered, ShouldBeEmpty)
					})
				})

				Convey("When evaluating violation template", func() {
					violationPath := filepath.Join(testDir, "ros", "violation.yaml")
					template, err := loadTemplate(violationPath)
					So(err, ShouldBeNil)

					opts := &engine.EvalOptions{
						PolicyPaths: []string{ruleFile, rosLibFile},
					}
					result, err := engine.EvaluateWithOpts(opts, template)

					Convey("It should return violations for this rule", func() {
						So(err, ShouldBeNil)
						filtered := filterByRuleID(result.Violations, ruleID)
						So(len(filtered), ShouldBeGreaterThan, 0)
					})
				})
			})
		})
	}
}

// hasTerraformTestData checks if a directory contains both compliant/ and violation/ subdirs with .tf files
func hasTerraformTestData(dir string) bool {
	compliantDir := filepath.Join(dir, "compliant")
	violationDir := filepath.Join(dir, "violation")

	hasCompliant := hasTFFiles(compliantDir)
	hasViolation := hasTFFiles(violationDir)
	return hasCompliant && hasViolation
}

// hasTFFiles checks if a directory exists and contains at least one .tf file
func hasTFFiles(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".tf" {
			return true
		}
	}
	return false
}

// discoverTerraformRuleTestDirs discovers rule directories that have terraform/ subdirectory with test data
func discoverTerraformRuleTestDirs(basePath string) ([]string, error) {
	var dirs []string
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			tfDir := filepath.Join(basePath, e.Name(), "terraform")
			if hasTerraformTestData(tfDir) {
				dirs = append(dirs, filepath.Join(basePath, e.Name()))
			}
		}
	}
	return dirs, nil
}

func TestTerraformPolicyRules(t *testing.T) {
	rulesTestDir := filepath.Join(policiesTestDir, "aliyun", "rules")
	if _, err := os.Stat(rulesTestDir); os.IsNotExist(err) {
		t.Skip("testdata/aliyun/rules directory not found")
		return
	}

	testDirs, err := discoverTerraformRuleTestDirs(rulesTestDir)
	if err != nil {
		t.Fatalf("Failed to discover terraform test directories: %v", err)
	}

	if len(testDirs) == 0 {
		t.Skip("No terraform rule test directories found")
		return
	}

	tfLibFile := filepath.Join(policiesDir, "aliyun", "lib", "terraform.rego")

	for _, testDir := range testDirs {
		ruleName := filepath.Base(testDir)
		ruleID := ruleName
		ruleFile := filepath.Join(policiesDir, "aliyun", "rules", "terraform", ruleName+".rego")

		// Check if rule file exists
		if _, err := os.Stat(ruleFile); os.IsNotExist(err) {
			t.Logf("Skipping %s: rule file not found at %s", ruleName, ruleFile)
			continue
		}

		t.Run(ruleName, func(t *testing.T) {
			Convey("Given the terraform "+ruleName+" rule", t, func() {
				Convey("When evaluating compliant terraform config", func() {
					compliantDir := filepath.Join(testDir, "terraform", "compliant")
					opaInput, err := terraform.Load(compliantDir, nil)
					So(err, ShouldBeNil)

					opts := &engine.EvalOptions{
						PolicyPaths: []string{ruleFile, tfLibFile},
					}
					result, err := engine.EvaluateWithOpts(opts, opaInput)

					Convey("It should return no violations for this rule", func() {
						So(err, ShouldBeNil)
						filtered := filterByRuleID(result.Violations, ruleID)
						So(filtered, ShouldBeEmpty)
					})
				})

				Convey("When evaluating violation terraform config", func() {
					violationDir := filepath.Join(testDir, "terraform", "violation")
					opaInput, err := terraform.Load(violationDir, nil)
					So(err, ShouldBeNil)

					opts := &engine.EvalOptions{
						PolicyPaths: []string{ruleFile, tfLibFile},
					}
					result, err := engine.EvaluateWithOpts(opts, opaInput)

					Convey("It should return violations for this rule", func() {
						So(err, ShouldBeNil)
						filtered := filterByRuleID(result.Violations, ruleID)
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

	testDirs, err := discoverROSTestDirs(packsTestDir)
	if err != nil {
		t.Fatalf("Failed to discover test directories: %v", err)
	}

	if len(testDirs) == 0 {
		t.Skip("No pack test directories found")
		return
	}

	rosLibFile := filepath.Join(policiesDir, "aliyun", "lib", "helpers.rego")

	for _, testDir := range testDirs {
		provider := "aliyun"
		packName := filepath.Base(testDir)
		packFile := getPackFile(provider, packName)

		rosRulesDir := filepath.Join(policiesDir, provider, "rules", "ros")

		t.Run(packName, func(t *testing.T) {
			Convey("Given the "+packName+" pack", t, func() {
				// Skip if pack file doesn't exist
				if _, err := os.Stat(packFile); os.IsNotExist(err) {
					SkipConvey("Pack file not found: "+packFile, func() {})
					return
				}

				Convey("When evaluating compliant template", func() {
					compliantPath := filepath.Join(testDir, "ros", "compliant.yaml")
					template, err := loadTemplate(compliantPath)
					So(err, ShouldBeNil)

					opts := &engine.EvalOptions{
						PolicyPaths: []string{rosRulesDir, rosLibFile},
					}
					result, err := engine.EvaluateWithOpts(opts, template)

					Convey("It should return no violations", func() {
						So(err, ShouldBeNil)
						So(result.Violations, ShouldBeEmpty)
					})
				})

				Convey("When evaluating violation template", func() {
					violationPath := filepath.Join(testDir, "ros", "violation.yaml")
					template, err := loadTemplate(violationPath)
					So(err, ShouldBeNil)

					opts := &engine.EvalOptions{
						PolicyPaths: []string{rosRulesDir, rosLibFile},
					}
					result, err := engine.EvaluateWithOpts(opts, template)

					Convey("It should return violations", func() {
						So(err, ShouldBeNil)
						So(len(result.Violations), ShouldBeGreaterThan, 0)
					})
				})
			})
		})
	}
}

func TestTerraformPolicyPacks(t *testing.T) {
	packsTestDir := filepath.Join(policiesTestDir, "aliyun", "packs")
	if _, err := os.Stat(packsTestDir); os.IsNotExist(err) {
		t.Skip("testdata/aliyun/packs directory not found")
		return
	}

	entries, err := os.ReadDir(packsTestDir)
	if err != nil {
		t.Fatalf("Failed to read packs test directory: %v", err)
	}

	tfRulesDir := filepath.Join(policiesDir, "aliyun", "rules", "terraform")
	tfLibFile := filepath.Join(policiesDir, "aliyun", "lib", "terraform.rego")

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		packName := entry.Name()
		tfTestDir := filepath.Join(packsTestDir, packName, "terraform")
		if !hasTerraformTestData(tfTestDir) {
			continue
		}

		t.Run(packName, func(t *testing.T) {
			Convey("Given the terraform "+packName+" pack", t, func() {
				Convey("When evaluating compliant terraform config", func() {
					compliantDir := filepath.Join(tfTestDir, "compliant")
					opaInput, err := terraform.Load(compliantDir, nil)
					So(err, ShouldBeNil)

					opts := &engine.EvalOptions{
						PolicyPaths: []string{tfRulesDir, tfLibFile},
					}
					result, err := engine.EvaluateWithOpts(opts, opaInput)

					Convey("It should return no violations", func() {
						So(err, ShouldBeNil)
						So(result.Violations, ShouldBeEmpty)
					})
				})

				Convey("When evaluating violation terraform config", func() {
					violationDir := filepath.Join(tfTestDir, "violation")
					opaInput, err := terraform.Load(violationDir, nil)
					So(err, ShouldBeNil)

					opts := &engine.EvalOptions{
						PolicyPaths: []string{tfRulesDir, tfLibFile},
					}
					result, err := engine.EvaluateWithOpts(opts, opaInput)

					Convey("It should return violations", func() {
						So(err, ShouldBeNil)
						So(len(result.Violations), ShouldBeGreaterThan, 0)
					})
				})
			})
		})
	}
}
