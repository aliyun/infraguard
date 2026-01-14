// Package policy manages policy library operations including rule and pack parsing.
package policy

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
)

// RegoModule represents a Rego module with its path and content.
type RegoModule struct {
	Path    string
	Content string
}

// ParseRuleFromContentWithModules parses a rule from rego content with additional modules.
// The extraModules parameter allows loading helper libraries that the rule depends on.
func ParseRuleFromContentWithModules(content, filePath, baseDir string, extraModules []RegoModule) (*models.Rule, error) {
	// Extract package name
	packageName := extractPackageName(content)
	if packageName == "" {
		return nil, nil // Not a valid rego file
	}

	// Build the query for this specific package's rule_meta
	query := fmt.Sprintf("data.%s.rule_meta", packageName)

	ctx := context.Background()

	// Build rego options
	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Module(filePath, content),
	}

	// Add extra modules (e.g., helpers library)
	for _, mod := range extraModules {
		opts = append(opts, rego.Module(mod.Path, mod.Content))
	}

	r := rego.New(opts...)

	preparedQuery, err := r.PrepareForEval(ctx)
	if err != nil {
		// File doesn't have rule_meta or has syntax errors
		return nil, nil
	}

	results, err := preparedQuery.Eval(ctx)
	if err != nil || len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, nil
	}

	// Parse rule_meta from results
	expr := results[0].Expressions[0]
	if expr.Value == nil {
		return nil, nil
	}

	rule, err := parseRuleMeta(expr.Value, filePath, packageName, baseDir)
	if err != nil {
		msg := i18n.Msg()
		return nil, fmt.Errorf(msg.Errors.ParseRuleMeta, err)
	}

	return rule, nil
}

// parseRuleMeta converts OPA result to Rule struct.
// ID is auto-generated from the file path if not specified in rule_meta.
func parseRuleMeta(value interface{}, filePath, packageName, baseDir string) (*models.Rule, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	var rawMeta struct {
		ID             string      `json:"id"`
		Name           interface{} `json:"name"`
		Severity       string      `json:"severity"`
		Description    interface{} `json:"description"`
		Reason         interface{} `json:"reason"`
		Recommendation interface{} `json:"recommendation"`
		ResourceTypes  []string    `json:"resource_types"`
	}

	if err := json.Unmarshal(data, &rawMeta); err != nil {
		return nil, err
	}

	// Auto-generate ID from file path if not specified
	ruleID := rawMeta.ID
	if ruleID == "" {
		// Extract name from filename (without .rego extension)
		baseName := filepath.Base(filePath)
		name := strings.TrimSuffix(baseName, ".rego")
		// Convert snake_case to kebab-case
		name = strings.ReplaceAll(name, "_", "-")
		ruleID = GenerateRuleID(filePath, baseDir, name)
	} else {
		// If ID is specified but doesn't have prefix, add it
		if !strings.HasPrefix(ruleID, "rule:") {
			name := ruleID
			ruleID = GenerateRuleID(filePath, baseDir, name)
		}
	}

	rule := &models.Rule{
		ID:             ruleID,
		Name:           parseI18nString(rawMeta.Name),
		Severity:       models.NormalizeSeverity(rawMeta.Severity),
		Description:    parseI18nString(rawMeta.Description),
		Reason:         parseI18nString(rawMeta.Reason),
		Recommendation: parseI18nString(rawMeta.Recommendation),
		ResourceTypes:  rawMeta.ResourceTypes,
		FilePath:       filePath,
		PackageName:    packageName,
	}

	return rule, nil
}

// parseI18nString converts an interface{} to I18nString.
// Handles both string and map[string]interface{} formats.
func parseI18nString(v interface{}) models.I18nString {
	result := make(models.I18nString)

	switch val := v.(type) {
	case string:
		result["en"] = val
	case map[string]interface{}:
		for k, v := range val {
			if s, ok := v.(string); ok {
				result[k] = s
			}
		}
	case map[string]string:
		for k, v := range val {
			result[k] = v
		}
	}

	return result
}

// extractPackageName extracts the package name from rego content.
func extractPackageName(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

// DiscoverRules finds all rules in a directory.
func DiscoverRules(dir string) ([]*models.Rule, error) {
	return DiscoverRulesWithExtraModules(dir, nil)
}

// DiscoverRulesWithExtraModules finds all rules in a directory with additional helper modules.
// The extraModules parameter allows providing helper libraries (e.g., embedded helpers)
// that rules may depend on but are not present in the local directory.
func DiscoverRulesWithExtraModules(dir string, extraModules []RegoModule) ([]*models.Rule, error) {
	var rules []*models.Rule

	// Load helper libraries from lib directory
	helperModules := loadHelperModulesFromDir(dir)

	// Append extra modules (e.g., embedded helpers)
	helperModules = append(helperModules, extraModules...)

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		// Skip lib directory
		if strings.Contains(path, string(filepath.Separator)+"lib"+string(filepath.Separator)) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip files that can't be read
		}

		rule, err := ParseRuleFromContentWithModules(string(content), path, dir, helperModules)
		if err != nil {
			// Log warning but continue
			return nil
		}
		if rule != nil {
			rules = append(rules, rule)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return rules, nil
}

// loadHelperModulesFromDir loads all helper modules from the lib subdirectory.
func loadHelperModulesFromDir(dir string) []RegoModule {
	var modules []RegoModule

	libDir := filepath.Join(dir, "lib")
	if !dirExists(libDir) {
		// Try parent directory if we are in {provider}/rules or {provider}/packs
		libDir = filepath.Join(filepath.Dir(dir), "lib")
	}
	if !dirExists(libDir) {
		return modules
	}

	filepath.WalkDir(libDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		modules = append(modules, RegoModule{
			Path:    path,
			Content: string(content),
		})
		return nil
	})

	return modules
}
