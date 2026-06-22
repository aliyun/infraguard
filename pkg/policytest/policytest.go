// Package policytest runs convention-based behavior tests for policy rules.
//
// For each rule it discovers fixtures under <dir>/testdata/aliyun/rules/<rule>/
// and asserts that "compliant" fixtures produce no violations of the rule while
// "violation" fixtures produce at least one. The same engine and helper libraries
// used by `infraguard scan` are used here, so results match real scans.
package policytest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/aliyun/infraguard/pkg/engine"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
	"github.com/aliyun/infraguard/pkg/providers/terraform"
	"gopkg.in/yaml.v3"
)

// Status values for a case result.
const (
	StatusPass  = "pass"
	StatusFail  = "fail"
	StatusError = "error"
)

// Options configures a test run.
type Options struct {
	Dir     string   // Root directory containing rules/ and testdata/
	RuleIDs []string // Short rule IDs to test; empty means all
	IaC     string   // "ros", "terraform", or "both"
}

// Result codes (localized by the caller).
const (
	CodeNoRule     = "no_rule"     // no rule definition found
	CodeExpectOne  = "expect_one"  // expected >=1 violation, got 0
	CodeExpectZero = "expect_zero" // expected 0 violations, got N (Detail = N)
	CodeLoad       = "load"        // failed to load template
	CodeLoadTF     = "load_tf"     // failed to load terraform
	CodeEval       = "eval"        // evaluation error
)

// CaseResult is the outcome of a single fixture case.
type CaseResult struct {
	Rule   string `json:"rule"`
	IaC    string `json:"iac"`
	Case   string `json:"case"` // e.g. "ros/compliant"
	Status string `json:"status"`
	Code   string `json:"code,omitempty"`   // Reason code when not pass
	Detail string `json:"detail,omitempty"` // Extra context (count or error text)
}

// Summary aggregates results.
type Summary struct {
	Rules  int
	Cases  int
	Passed int
	Failed int
}

// Run discovers and executes all matching rule tests.
func Run(opts Options) ([]CaseResult, Summary, error) {
	wantIaC := func(iac string) bool {
		return opts.IaC == "" || opts.IaC == "both" || opts.IaC == iac
	}
	ruleFilter := toSet(opts.RuleIDs)

	// Helper libraries (data.infraguard.helpers, ...terraform) come from the
	// built-in loader so custom rules can import them transparently.
	libModules := map[string]string{}
	builtin, err := policy.LoadWithFallback()
	if err == nil {
		libModules = builtin.GetLibModules()
	}

	// Built-in helper modules are passed to discovery so custom rules that import
	// data.infraguard.helpers compile while their metadata is parsed.
	var extraModules []policy.RegoModule
	for name, content := range libModules {
		extraModules = append(extraModules, policy.RegoModule{Path: name, Content: content})
	}

	// Index rules discovered under <dir>/rules by short ID, merging the per-IaC
	// implementations (ros/ and terraform/ are separate files sharing an ID).
	ruleIndex := map[string]*models.Rule{}
	rulesDir := filepath.Join(opts.Dir, "rules")
	if _, statErr := os.Stat(rulesDir); statErr == nil {
		discovered, derr := policy.DiscoverRulesWithExtraModules(rulesDir, extraModules)
		if derr != nil {
			return nil, Summary{}, fmt.Errorf("discover rules in %s: %w", rulesDir, derr)
		}
		for _, r := range discovered {
			if r.Content == "" {
				if b, rerr := os.ReadFile(r.FilePath); rerr == nil {
					r.Content = string(b)
				}
			}
			sid := shortID(r.ID)
			existing := ruleIndex[sid]
			if existing == nil {
				existing = &models.Rule{ID: r.ID, Implementations: map[string]*models.RuleImpl{}}
				ruleIndex[sid] = existing
			}
			for _, iac := range r.IaCTypes {
				existing.Implementations[iac] = &models.RuleImpl{
					FilePath:    r.FilePath,
					PackageName: r.PackageName,
					Content:     r.Content,
				}
			}
		}
	}

	testRoot := filepath.Join(opts.Dir, "testdata", "aliyun", "rules")
	testDirs, err := discoverTestDirs(testRoot)
	if err != nil {
		return nil, Summary{}, fmt.Errorf("discover test fixtures in %s: %w", testRoot, err)
	}

	var results []CaseResult
	summary := Summary{}
	seenRules := map[string]bool{}

	for _, testDir := range testDirs {
		ruleName := filepath.Base(testDir)
		if len(ruleFilter) > 0 && !ruleFilter[ruleName] {
			continue
		}

		rule := resolveRule(ruleName, ruleIndex, builtin)
		if rule == nil {
			results = append(results, CaseResult{
				Rule: ruleName, Status: StatusError, Code: CodeNoRule, Detail: rulesDir,
			})
			summary.Failed++
			seenRules[ruleName] = true
			continue
		}

		// ROS cases
		if wantIaC("ros") {
			if cases := runROS(testDir, ruleName, rule, libModules); cases != nil {
				results = append(results, cases...)
				seenRules[ruleName] = true
			}
		}
		// Terraform cases
		if wantIaC("terraform") {
			if cases := runTF(testDir, ruleName, rule, libModules); cases != nil {
				results = append(results, cases...)
				seenRules[ruleName] = true
			}
		}
	}

	for _, c := range results {
		summary.Cases++
		if c.Status == StatusPass {
			summary.Passed++
		} else {
			summary.Failed++
		}
	}
	summary.Rules = len(seenRules)
	return results, summary, nil
}

func runROS(testDir, ruleName string, rule *models.Rule, libModules map[string]string) []CaseResult {
	rosDir := filepath.Join(testDir, "ros")
	compliant := filepath.Join(rosDir, "compliant.yaml")
	violation := filepath.Join(rosDir, "violation.yaml")
	if !fileExists(compliant) && !fileExists(violation) {
		return nil
	}
	var out []CaseResult
	if fileExists(compliant) {
		out = append(out, evalROSCase(ruleName, rule, "ros/compliant", compliant, libModules, false))
	}
	if fileExists(violation) {
		out = append(out, evalROSCase(ruleName, rule, "ros/violation", violation, libModules, true))
	}
	return out
}

func runTF(testDir, ruleName string, rule *models.Rule, libModules map[string]string) []CaseResult {
	tfDir := filepath.Join(testDir, "terraform")
	compliant := filepath.Join(tfDir, "compliant")
	violation := filepath.Join(tfDir, "violation")
	cMain := filepath.Join(compliant, "main.tf")
	vMain := filepath.Join(violation, "main.tf")
	if !fileExists(cMain) && !fileExists(vMain) {
		return nil
	}
	var out []CaseResult
	if fileExists(cMain) {
		out = append(out, evalTFCase(ruleName, rule, "terraform/compliant", compliant, libModules, false))
	}
	if fileExists(vMain) {
		out = append(out, evalTFCase(ruleName, rule, "terraform/violation", violation, libModules, true))
	}
	return out
}

func evalROSCase(ruleName string, rule *models.Rule, caseName, path string, libModules map[string]string, expectViolation bool) CaseResult {
	data, err := loadYAML(path)
	if err != nil {
		return errorCase(ruleName, "ros", caseName, CodeLoad, err.Error())
	}
	opts := buildOpts(rule, "ros", libModules)
	return evalAndCheck(ruleName, "ros", caseName, opts, data, expectViolation)
}

func evalTFCase(ruleName string, rule *models.Rule, caseName, dir string, libModules map[string]string, expectViolation bool) CaseResult {
	data, err := terraform.Load(dir, nil)
	if err != nil {
		return errorCase(ruleName, "terraform", caseName, CodeLoadTF, err.Error())
	}
	opts := buildOpts(rule, "terraform", libModules)
	return evalAndCheck(ruleName, "terraform", caseName, opts, data, expectViolation)
}

func buildOpts(rule *models.Rule, iac string, libModules map[string]string) *engine.EvalOptions {
	opts := &engine.EvalOptions{LibModules: libModules}
	if rule.Implementations != nil {
		if impl, ok := rule.Implementations[iac]; ok && impl.Content != "" {
			opts.Modules = map[string]string{impl.FilePath: impl.Content}
			return opts
		}
	}
	if rule.Content != "" {
		opts.Modules = map[string]string{rule.FilePath: rule.Content}
	}
	return opts
}

func evalAndCheck(ruleName, iac, caseName string, opts *engine.EvalOptions, input map[string]interface{}, expectViolation bool) CaseResult {
	res, err := engine.EvaluateWithOpts(opts, input)
	if err != nil {
		return errorCase(ruleName, iac, caseName, CodeEval, err.Error())
	}
	count := 0
	for _, v := range res.Violations {
		if shortID(v.ID) == ruleName {
			count++
		}
	}
	if expectViolation {
		if count >= 1 {
			return CaseResult{Rule: ruleName, IaC: iac, Case: caseName, Status: StatusPass}
		}
		return CaseResult{Rule: ruleName, IaC: iac, Case: caseName, Status: StatusFail, Code: CodeExpectOne}
	}
	if count == 0 {
		return CaseResult{Rule: ruleName, IaC: iac, Case: caseName, Status: StatusPass}
	}
	return CaseResult{Rule: ruleName, IaC: iac, Case: caseName, Status: StatusFail,
		Code: CodeExpectZero, Detail: fmt.Sprintf("%d", count)}
}

func errorCase(rule, iac, caseName, code, detail string) CaseResult {
	return CaseResult{Rule: rule, IaC: iac, Case: caseName, Status: StatusError, Code: code, Detail: detail}
}

// resolveRule finds a rule by short name in the discovered index, falling back to
// the built-in loader (for testing built-in rules in-repo).
func resolveRule(ruleName string, index map[string]*models.Rule, builtin *policy.Loader) *models.Rule {
	if r, ok := index[ruleName]; ok {
		return r
	}
	if builtin != nil {
		if r := builtin.GetRule(fmt.Sprintf("rule:aliyun:%s", ruleName)); r != nil {
			return r
		}
		if r := builtin.GetRule(ruleName); r != nil {
			return r
		}
	}
	return nil
}

func discoverTestDirs(root string) ([]string, error) {
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil, nil
	}
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && hasFixtures(path) {
			dirs = append(dirs, path)
		}
		return nil
	})
	return dirs, err
}

func hasFixtures(dir string) bool {
	candidates := []string{
		filepath.Join(dir, "ros", "compliant.yaml"),
		filepath.Join(dir, "ros", "violation.yaml"),
		filepath.Join(dir, "terraform", "compliant", "main.tf"),
		filepath.Join(dir, "terraform", "violation", "main.tf"),
	}
	for _, c := range candidates {
		if fileExists(c) {
			return true
		}
	}
	return false
}

func loadYAML(path string) (map[string]interface{}, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]bool, len(items))
	for _, it := range items {
		out[shortID(it)] = true
	}
	return out
}

func shortID(id string) string {
	if !strings.HasPrefix(id, "rule:") && !strings.HasPrefix(id, "pack:") {
		return id
	}
	parts := strings.Split(id, ":")
	if len(parts) >= 3 {
		return parts[len(parts)-1]
	}
	return id
}
