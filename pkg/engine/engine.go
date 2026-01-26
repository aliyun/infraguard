// Package engine provides OPA/Rego policy evaluation.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/print"
)

// Query is the OPA evaluation entry point that collects deny results from all packages.
// This query finds all "deny" sets from infraguard.rules.* packages (e.g., data.infraguard.rules.aliyun.xxx)
const Query = "[v | v := data.infraguard.rules[_][_].deny[_]]"

// RulesQuery is the query for all declared rule IDs.
const RulesQuery = "[id | id := data.infraguard.rules[_][_].rule_meta.id]"

// printHook implements print.Hook interface to capture print() output from Rego policies.
type printHook struct{}

// Print implements the print.Hook interface, sending output to stderr.
func (h *printHook) Print(ctx print.Context, msg string) error {
	location := ""
	if ctx.Location != nil {
		location = ctx.Location.String() + ": "
	}
	fmt.Fprintf(os.Stderr, "%s%s\n", location, msg)
	return nil
}

// EvalResult contains the evaluation results including violations and rule statistics.
type EvalResult struct {
	Violations      []models.OPAViolation
	TotalRulesCount int
}

// EvalOptions contains options for policy evaluation.
type EvalOptions struct {
	PolicyPaths []string          // Paths to policy files or directories
	RuleIDs     []string          // Filter to specific rule IDs (optional)
	PackIDs     []string          // Filter to specific pack IDs (optional)
	IDMapping   map[string]string // Mapping from short ID to full ID (e.g., "xxx" -> "rule:aliyun:xxx")
	Modules     map[string]string // Pre-loaded modules (name -> content)
	LibModules  map[string]string // Pre-loaded lib modules (name -> content)
}

// Evaluate loads policies from a path (directory or single .rego file) and evaluates them against input data.
func Evaluate(policyPath string, input map[string]interface{}) ([]models.OPAViolation, error) {
	result, err := EvaluateWithStats(policyPath, input)
	if err != nil {
		return nil, err
	}
	return result.Violations, nil
}

// EvaluateWithStats loads policies and returns violations along with rule statistics.
func EvaluateWithStats(policyPath string, input map[string]interface{}) (*EvalResult, error) {
	opts := &EvalOptions{
		PolicyPaths: []string{policyPath},
	}
	return EvaluateWithOpts(opts, input)
}

// EvaluateWithOpts evaluates policies with flexible options.
func EvaluateWithOpts(opts *EvalOptions, input map[string]interface{}) (*EvalResult, error) {
	msg := i18n.Msg()
	if opts == nil || (len(opts.PolicyPaths) == 0 && len(opts.Modules) == 0) {
		return nil, fmt.Errorf("%s", msg.Errors.NoPolicyPaths)
	}

	// Discover all .rego files from all paths
	var allRegoFiles []string
	for _, path := range opts.PolicyPaths {
		files, err := discoverRegoFiles(path)
		if err != nil {
			return nil, fmt.Errorf(msg.Errors.DiscoverRegoFiles, path, err)
		}
		allRegoFiles = append(allRegoFiles, files...)
	}

	// Load all rego modules
	modules := make(map[string]string)
	if opts.Modules != nil {
		for k, v := range opts.Modules {
			modules[k] = v
		}
	}

	// Add lib modules (provided via LibModules)
	if opts.LibModules != nil {
		for k, v := range opts.LibModules {
			// Use a special prefix for library modules to avoid collision with policy paths
			modules["_lib_/"+k] = v
		}
	}

	for _, file := range allRegoFiles {
		// Skip if already in modules
		if _, ok := modules[file]; ok {
			continue
		}

		var content []byte
		var err error

		// Check if it's an embedded path
		// Legacy support for embedded paths removed
		content, err = os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf(msg.Errors.ReadRegoFile, file, err)
		}
		// Use path as module name (filesystem uses absolute path)
		moduleName := file
		absPath, _ := filepath.Abs(file)
		if absPath != "" {
			moduleName = absPath
		}
		modules[moduleName] = string(content)
	}

	if len(modules) == 0 {
		return nil, fmt.Errorf("%s", msg.Errors.NoRegoFilesInPaths)
	}

	ctx := context.Background()

	// Build module options (shared between queries)
	moduleOpts := make([]func(*rego.Rego), 0, len(modules)+2)
	for name, content := range modules {
		moduleOpts = append(moduleOpts, rego.Module(name, content))
	}

	// Enable print output to stderr for debugging
	moduleOpts = append(moduleOpts, rego.EnablePrintStatements(true))
	moduleOpts = append(moduleOpts, rego.PrintHook(&printHook{}))

	// Determine targeted query if specific rules are requested
	evaluationQuery := Query
	// If RuleIDs are provided and we have the modules/package info, we could target the query further.
	// But since we only load the requested modules into OPA in scan.go, the generic query already targets them.

	// Query for violations (deny rules)
	denyOpts := append([]func(*rego.Rego){
		rego.Query(evaluationQuery),
		rego.Input(input),
	}, moduleOpts...)

	r := rego.New(denyOpts...)
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf(msg.Errors.PrepareRegoQuery, err)
	}

	results, err := query.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf(msg.Errors.EvaluatePoliciesInternal, err)
	}

	violations, err := parseResults(results)
	if err != nil {
		return nil, err
	}

	// Expand short IDs to full IDs using the mapping
	if len(opts.IDMapping) > 0 {
		violations = expandViolationIDs(violations, opts.IDMapping)
	}

	// Filter violations by rule IDs if specified (now using exact match)
	if len(opts.RuleIDs) > 0 {
		violations = filterViolationsByRuleIDs(violations, opts.RuleIDs)
	}

	// Query for declared rules (optional - policies may not define this)
	totalRulesCount := 0
	rulesOpts := append([]func(*rego.Rego){
		rego.Query(RulesQuery),
		rego.Input(input),
	}, moduleOpts...)

	rulesRego := rego.New(rulesOpts...)
	rulesQuery, err := rulesRego.PrepareForEval(ctx)
	if err == nil {
		rulesResults, err := rulesQuery.Eval(ctx)
		if err == nil {
			totalRulesCount = parseRulesCount(rulesResults)
		}
	}

	// Adjust total rules count if filtering
	if len(opts.RuleIDs) > 0 {
		totalRulesCount = len(opts.RuleIDs)
	}

	return &EvalResult{
		Violations:      violations,
		TotalRulesCount: totalRulesCount,
	}, nil
}

// expandViolationIDs expands short IDs in violations to full IDs using the provided mapping.
func expandViolationIDs(violations []models.OPAViolation, idMapping map[string]string) []models.OPAViolation {
	for i := range violations {
		if fullID, ok := idMapping[violations[i].ID]; ok {
			violations[i].ID = fullID
		}
	}
	return violations
}

// filterViolationsByRuleIDs filters violations to only include those matching the specified rule IDs.
// Uses exact matching on the full rule ID.
func filterViolationsByRuleIDs(violations []models.OPAViolation, ruleIDs []string) []models.OPAViolation {
	if len(ruleIDs) == 0 {
		return violations
	}

	ruleIDSet := make(map[string]bool)
	for _, id := range ruleIDs {
		ruleIDSet[id] = true
	}

	var filtered []models.OPAViolation
	for _, v := range violations {
		if ruleIDSet[v.ID] {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// uniqueStrings removes duplicates from a string slice.
func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// discoverRegoFiles finds all .rego files from a path.
// If path is a directory, it recursively finds all .rego files.
// If path is a .rego file, it returns that single file.
// Supports both filesystem and embedded paths.
func discoverRegoFiles(path string) ([]string, error) {
	msg := i18n.Msg()
	// Check if it's an embedded path first
	// isEmbeddedPath removed as we no longer support raw embedded FS access during evaluate
	// if isEmbeddedPath(path) {
	// 	return discoverEmbeddedRegoFiles(path)
	// }

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// If it's a single .rego file, return it directly
	if !info.IsDir() {
		if strings.HasSuffix(path, ".rego") {
			return []string{path}, nil
		}
		return nil, fmt.Errorf(msg.Errors.FileMustBeRego, path)
	}

	// It's a directory - walk and find all .rego files
	var files []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".rego") {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

// parseResults converts OPA results to OPAViolation slice.
func parseResults(results rego.ResultSet) ([]models.OPAViolation, error) {
	var violations []models.OPAViolation

	for _, result := range results {
		for _, expr := range result.Expressions {
			// The deny rule should return a set of violation objects
			items, ok := expr.Value.([]interface{})
			if !ok {
				// Try as a single value
				if expr.Value != nil {
					items = []interface{}{expr.Value}
				} else {
					continue
				}
			}

			for _, item := range items {
				violation, err := parseViolation(item)
				if err != nil {
					// Skip malformed violations
					continue
				}
				violations = append(violations, violation)
			}
		}
	}

	return violations, nil
}

// parseViolation converts a single OPA result item to OPAViolation.
func parseViolation(item interface{}) (models.OPAViolation, error) {
	var v models.OPAViolation

	// Convert to JSON and back for easy parsing
	data, err := json.Marshal(item)
	if err != nil {
		return v, err
	}

	if err := json.Unmarshal(data, &v); err != nil {
		return v, err
	}

	return v, nil
}

// parseRulesCount extracts the count of declared rules from OPA results.
// The rules query should return a set of rule IDs.
func parseRulesCount(results rego.ResultSet) int {
	for _, result := range results {
		for _, expr := range result.Expressions {
			// The rules should be a set of rule IDs
			switch items := expr.Value.(type) {
			case []interface{}:
				return len(items)
			case map[string]interface{}:
				// OPA sets are sometimes returned as maps
				return len(items)
			}
		}
	}
	return 0
}
