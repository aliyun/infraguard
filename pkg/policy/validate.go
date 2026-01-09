// Package policy manages policy library operations including validation.
package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Error codes for validation errors
const (
	// Rule validation error codes
	ErrCodeRuleMissingMeta       = "RULE_MISSING_META"
	ErrCodeRuleMissingID         = "RULE_MISSING_ID"
	ErrCodeRuleMissingName       = "RULE_MISSING_NAME"
	ErrCodeRuleMissingSeverity   = "RULE_MISSING_SEVERITY"
	ErrCodeRuleMissingReason     = "RULE_MISSING_REASON"
	ErrCodeRuleInvalidSeverity   = "RULE_INVALID_SEVERITY"
	ErrCodeRuleInvalidFieldType  = "RULE_INVALID_FIELD_TYPE"
	ErrCodeRuleMissingDeny       = "RULE_MISSING_DENY"
	ErrCodeRuleInvalidDenyFormat = "RULE_INVALID_DENY_FORMAT"

	// Pack validation error codes
	ErrCodePackMissingMeta      = "PACK_MISSING_META"
	ErrCodePackMissingID        = "PACK_MISSING_ID"
	ErrCodePackMissingName      = "PACK_MISSING_NAME"
	ErrCodePackMissingRules     = "PACK_MISSING_RULES"
	ErrCodePackInvalidFieldType = "PACK_INVALID_FIELD_TYPE"

	// General error codes
	ErrCodeSyntaxError = "SYNTAX_ERROR"
	ErrCodeReadError   = "READ_ERROR"
)

// Package name prefixes for InfraGuard policies
const (
	RulesPackagePrefix = "infraguard.rules."
	PacksPackagePrefix = "infraguard.packs."
)

// ValidationError represents a single validation error with context and fix suggestion.
type ValidationError struct {
	FilePath   string `json:"file_path"`
	Line       int    `json:"line,omitempty"` // 0 if unknown
	ErrorCode  string `json:"error_code"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion"`
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", e.FilePath, e.Line, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.FilePath, e.Message)
}

// ValidationResult holds the validation result for a single file.
type ValidationResult struct {
	FilePath string             `json:"file_path"`
	FileType string             `json:"file_type"` // "rule", "pack", or "unknown"
	Valid    bool               `json:"valid"`
	Errors   []*ValidationError `json:"errors,omitempty"`
}

// ValidationSummary holds the summary of validation results.
type ValidationSummary struct {
	TotalFiles   int                 `json:"total_files"`
	PassedFiles  int                 `json:"passed_files"`
	FailedFiles  int                 `json:"failed_files"`
	SkippedFiles int                 `json:"skipped_files"`
	Results      []*ValidationResult `json:"results"`
	Skipped      []string            `json:"skipped,omitempty"` // Skipped file paths
}

// ValidateFile validates a single Rego file for InfraGuard compliance.
// Returns a ValidationResult with any errors found.
func ValidateFile(filePath string) (*ValidationResult, error) {
	// Load helper modules for the file
	helperModules := loadHelperModulesFromPath(filePath)
	return ValidateFileWithModules(filePath, helperModules)
}

// ValidateFileWithModules validates a single Rego file with extra modules.
func ValidateFileWithModules(filePath string, extraModules []RegoModule) (*ValidationResult, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		msg := i18n.Msg()
		return &ValidationResult{
			FilePath: filePath,
			FileType: "unknown",
			Valid:    false,
			Errors: []*ValidationError{{
				FilePath:   filePath,
				ErrorCode:  ErrCodeReadError,
				Message:    fmt.Sprintf(msg.Errors.ReadFileError, err),
				Suggestion: msg.PolicyValidate.Errors["READ_ERROR_suggestion"],
			}},
		}, nil
	}

	return ValidateContentWithModules(string(content), filePath, extraModules)
}

// ValidateContent validates Rego content for InfraGuard compliance.
func ValidateContent(content, filePath string) (*ValidationResult, error) {
	return ValidateContentWithModules(content, filePath, nil)
}

// ValidateContentWithModules validates Rego content with optional extra modules.
func ValidateContentWithModules(content, filePath string, extraModules []RegoModule) (*ValidationResult, error) {
	result := &ValidationResult{
		FilePath: filePath,
		FileType: "unknown",
		Valid:    true,
		Errors:   []*ValidationError{},
	}

	// Check for syntax errors first
	if syntaxErr := checkSyntax(content, filePath); syntaxErr != nil {
		result.Valid = false
		result.Errors = append(result.Errors, syntaxErr)
		return result, nil
	}

	// Extract package name
	packageName := extractPackageName(content)
	if packageName == "" {
		// Not a valid Rego file, skip
		return result, nil
	}

	// Determine file type based on package name prefix
	// - infraguard.rules.* → rule
	// - infraguard.packs.* → pack
	// - other → skip (not an InfraGuard policy file)
	if strings.HasPrefix(packageName, RulesPackagePrefix) {
		result.FileType = "rule"
		errors := validateRuleContent(content, filePath, packageName, extraModules)
		result.Errors = append(result.Errors, errors...)
	} else if strings.HasPrefix(packageName, PacksPackagePrefix) {
		result.FileType = "pack"
		errors := validatePackContent(content, filePath, packageName, extraModules)
		result.Errors = append(result.Errors, errors...)
	}
	// If package name doesn't match rule/pack prefixes, FileType remains "unknown"
	// and the file will be skipped by ValidateDirectory

	result.Valid = len(result.Errors) == 0
	return result, nil
}

// ValidateDirectory validates all Rego files in a directory recursively.
func ValidateDirectory(dir string) (*ValidationSummary, error) {
	summary := &ValidationSummary{
		Results: []*ValidationResult{},
		Skipped: []string{},
	}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		// Skip lib directory (helper modules)
		if strings.Contains(path, string(filepath.Separator)+"lib"+string(filepath.Separator)) {
			return nil
		}

		// Load helper modules for each file individually to handle nested directory structures
		helperModules := loadHelperModulesFromPath(path)
		result, err := ValidateFileWithModules(path, helperModules)
		if err != nil {
			return err
		}

		// Include files that are rules or packs, track skipped files
		if result.FileType != "unknown" {
			summary.Results = append(summary.Results, result)
			summary.TotalFiles++
			if result.Valid {
				summary.PassedFiles++
			} else {
				summary.FailedFiles++
			}
		} else {
			// File doesn't have infraguard.rules.* or infraguard.packs.* package prefix
			summary.SkippedFiles++
			summary.Skipped = append(summary.Skipped, path)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return summary, nil
}

// ValidatePolicies validates a file or directory for policy compliance.
func ValidatePolicies(path string) (*ValidationSummary, error) {
	msg := i18n.Msg()
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf(msg.Errors.PathDoesNotExist, path)
	}

	if info.IsDir() {
		return ValidateDirectory(path)
	}

	// Single file
	result, err := ValidateFile(path)
	if err != nil {
		return nil, err
	}

	summary := &ValidationSummary{
		Results: []*ValidationResult{},
		Skipped: []string{},
	}

	// Only count files with valid InfraGuard package prefixes
	if result.FileType != "unknown" {
		summary.TotalFiles = 1
		summary.Results = append(summary.Results, result)
		if result.Valid {
			summary.PassedFiles = 1
		} else {
			summary.FailedFiles = 1
		}
	} else {
		// File doesn't have infraguard.rules.* or infraguard.packs.* package prefix
		summary.SkippedFiles = 1
		summary.Skipped = append(summary.Skipped, path)
	}

	return summary, nil
}

// checkSyntax checks for Rego syntax errors.
func checkSyntax(content, filePath string) *ValidationError {
	msg := i18n.Msg()
	_, err := ast.ParseModule(filePath, content)
	if err != nil {
		return &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeSyntaxError,
			Message:    fmt.Sprintf(msg.Errors.SyntaxErrorWithDetail, err),
			Suggestion: msg.PolicyValidate.Errors["SYNTAX_ERROR_suggestion"],
		}
	}
	return nil
}

// validateRuleContent validates rule-specific content.
func validateRuleContent(content, filePath, packageName string, extraModules []RegoModule) []*ValidationError {
	var errors []*ValidationError

	// Validate rule_meta
	metaErrors := validateRuleMeta(content, filePath, packageName, extraModules)
	errors = append(errors, metaErrors...)

	// Validate deny rule
	denyErrors := validateDenyRule(content, filePath, packageName, extraModules)
	errors = append(errors, denyErrors...)

	return errors
}

// validateRuleMeta validates the rule_meta object.
func validateRuleMeta(content, filePath, packageName string, extraModules []RegoModule) []*ValidationError {
	var errors []*ValidationError

	query := fmt.Sprintf("data.%s.rule_meta", packageName)
	ctx := context.Background()

	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Module(filePath, content),
	}
	for _, mod := range extraModules {
		opts = append(opts, rego.Module(mod.Path, mod.Content))
	}
	r := rego.New(opts...)

	preparedQuery, err := r.PrepareForEval(ctx)
	if err != nil {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeRuleMissingMeta,
			Message:    "rule_meta is required but not found or has errors.",
			Suggestion: "Add a rule_meta object with required fields: id, name, severity, reason",
		})
		return errors
	}

	results, err := preparedQuery.Eval(ctx)
	if err != nil || len(results) == 0 || len(results[0].Expressions) == 0 {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeRuleMissingMeta,
			Message:    "rule_meta is required but not found.",
			Suggestion: "Add a rule_meta object with required fields: id, name, severity, reason",
		})
		return errors
	}

	expr := results[0].Expressions[0]
	if expr.Value == nil {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeRuleMissingMeta,
			Message:    "rule_meta is empty.",
			Suggestion: "Add required fields to rule_meta: id, name, severity, reason",
		})
		return errors
	}

	meta, ok := expr.Value.(map[string]interface{})
	if !ok {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeRuleMissingMeta,
			Message:    "rule_meta must be an object.",
			Suggestion: "Define rule_meta as an object with required fields",
		})
		return errors
	}

	// Validate required fields
	if err := validateRequiredStringField(meta, "id", filePath, ErrCodeRuleMissingID,
		"rule_meta.id is required.", "Add id field to rule_meta"); err != nil {
		errors = append(errors, err)
	}

	if err := validateRequiredI18nField(meta, "name", filePath, ErrCodeRuleMissingName,
		"rule_meta.name is required.", "Add name field with English and Chinese translations"); err != nil {
		errors = append(errors, err)
	}

	if err := validateRequiredI18nField(meta, "reason", filePath, ErrCodeRuleMissingReason,
		"rule_meta.reason is required.", "Add reason field explaining why violations occur"); err != nil {
		errors = append(errors, err)
	}

	// Validate severity
	if severity, ok := meta["severity"]; !ok || severity == nil {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeRuleMissingSeverity,
			Message:    "rule_meta.severity is required.",
			Suggestion: "Add severity field with value: high, medium, or low",
		})
	} else if severityStr, ok := severity.(string); !ok {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeRuleInvalidFieldType,
			Message:    "rule_meta.severity must be a string.",
			Suggestion: "Change severity to a string value: high, medium, or low",
		})
	} else if !isValidSeverity(severityStr) {
		msg := i18n.Msg()
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeRuleInvalidSeverity,
			Message:    fmt.Sprintf(msg.Errors.RuleInvalidSeverityWithValue, severityStr),
			Suggestion: msg.PolicyValidate.Errors["RULE_INVALID_SEVERITY_suggestion"],
		})
	}

	// Validate optional i18n fields
	for _, field := range []string{"description", "recommendation"} {
		if val, exists := meta[field]; exists && val != nil {
			if err := validateI18nFieldType(val, field, filePath); err != nil {
				errors = append(errors, err)
			}
		}
	}

	return errors
}

// validateDenyRule validates the deny rule presence and output format.
func validateDenyRule(content, filePath, packageName string, extraModules []RegoModule) []*ValidationError {
	var errors []*ValidationError

	// Check if deny rule exists
	query := fmt.Sprintf("data.%s.deny", packageName)
	ctx := context.Background()

	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Module(filePath, content),
	}
	for _, mod := range extraModules {
		opts = append(opts, rego.Module(mod.Path, mod.Content))
	}

	r := rego.New(opts...)

	preparedQuery, err := r.PrepareForEval(ctx)
	if err != nil {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeRuleMissingDeny,
			Message:    "deny rule is required but not found or has errors.",
			Suggestion: "Add a deny rule: deny contains result if { ... }",
		})
		return errors
	}

	// Check if deny is defined (it may be empty set if no violations)
	results, err := preparedQuery.Eval(ctx)
	if err != nil {
		msg := i18n.Msg()
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeRuleMissingDeny,
			Message:    fmt.Sprintf(msg.Errors.DenyRuleEvaluationError, err),
			Suggestion: "Fix the deny rule syntax and ensure it returns valid results",
		})
		return errors
	}

	// Check if deny exists in the module by parsing AST
	module, err := ast.ParseModule(filePath, content)
	if err != nil {
		return errors // Syntax error already handled
	}

	hasDeny := false
	for _, rule := range module.Rules {
		if rule.Head.Name.String() == "deny" {
			hasDeny = true
			break
		}
	}

	if !hasDeny {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeRuleMissingDeny,
			Message:    "deny rule is required.",
			Suggestion: "Add a deny rule: deny contains result if { ... } with result containing id, resource_id, violation_path, meta",
		})
		return errors
	}

	// If deny has results, validate the output format
	if len(results) > 0 && len(results[0].Expressions) > 0 {
		denyResults := results[0].Expressions[0].Value
		if set, ok := denyResults.([]interface{}); ok && len(set) > 0 {
			// Validate first result's structure
			if result, ok := set[0].(map[string]interface{}); ok {
				errors = append(errors, validateDenyResultFormat(result, filePath)...)
			}
		}
	}

	return errors
}

// validateDenyResultFormat validates the structure of a deny result.
func validateDenyResultFormat(result map[string]interface{}, filePath string) []*ValidationError {
	var errors []*ValidationError

	// Check required fields
	msg := i18n.Msg()
	requiredFields := []string{"id", "resource_id", "violation_path", "meta"}
	for _, field := range requiredFields {
		if _, exists := result[field]; !exists {
			errors = append(errors, &ValidationError{
				FilePath:   filePath,
				ErrorCode:  ErrCodeRuleInvalidDenyFormat,
				Message:    fmt.Sprintf(msg.Errors.DenyResultFieldRequired, field),
				Suggestion: fmt.Sprintf(msg.Errors.AddFieldToDenyResult, field),
			})
		}
	}

	// Validate meta structure if present
	if meta, exists := result["meta"]; exists {
		if metaMap, ok := meta.(map[string]interface{}); ok {
			// Check required meta fields
			if _, exists := metaMap["severity"]; !exists {
				errors = append(errors, &ValidationError{
					FilePath:   filePath,
					ErrorCode:  ErrCodeRuleInvalidDenyFormat,
					Message:    "deny result.meta.severity is required.",
					Suggestion: "Add severity field to meta: severity: rule_meta.severity",
				})
			}
			if _, exists := metaMap["reason"]; !exists {
				errors = append(errors, &ValidationError{
					FilePath:   filePath,
					ErrorCode:  ErrCodeRuleInvalidDenyFormat,
					Message:    "deny result.meta.reason is required.",
					Suggestion: "Add reason field to meta: reason: rule_meta.reason",
				})
			}
		}
	}

	return errors
}

// validatePackContent validates pack-specific content.
func validatePackContent(content, filePath, packageName string, extraModules []RegoModule) []*ValidationError {
	return validatePackMeta(content, filePath, packageName, extraModules)
}

// validatePackMeta validates the pack_meta object.
func validatePackMeta(content, filePath, packageName string, extraModules []RegoModule) []*ValidationError {
	var errors []*ValidationError

	query := fmt.Sprintf("data.%s.pack_meta", packageName)
	ctx := context.Background()

	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Module(filePath, content),
	}
	for _, mod := range extraModules {
		opts = append(opts, rego.Module(mod.Path, mod.Content))
	}
	r := rego.New(opts...)

	preparedQuery, err := r.PrepareForEval(ctx)
	if err != nil {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodePackMissingMeta,
			Message:    "pack_meta is required but not found or has errors.",
			Suggestion: "Add a pack_meta object with required fields: id, name, rules",
		})
		return errors
	}

	results, err := preparedQuery.Eval(ctx)
	if err != nil || len(results) == 0 || len(results[0].Expressions) == 0 {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodePackMissingMeta,
			Message:    "pack_meta is required but not found.",
			Suggestion: "Add a pack_meta object with required fields: id, name, rules",
		})
		return errors
	}

	expr := results[0].Expressions[0]
	if expr.Value == nil {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodePackMissingMeta,
			Message:    "pack_meta is empty.",
			Suggestion: "Add required fields to pack_meta: id, name, rules",
		})
		return errors
	}

	meta, ok := expr.Value.(map[string]interface{})
	if !ok {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodePackMissingMeta,
			Message:    "pack_meta must be an object.",
			Suggestion: "Define pack_meta as an object with required fields",
		})
		return errors
	}

	// Validate required fields
	if err := validateRequiredStringField(meta, "id", filePath, ErrCodePackMissingID,
		"pack_meta.id is required.", "Add id field to pack_meta"); err != nil {
		errors = append(errors, err)
	}

	if err := validateRequiredI18nField(meta, "name", filePath, ErrCodePackMissingName,
		"pack_meta.name is required.", "Add name field with English and Chinese translations"); err != nil {
		errors = append(errors, err)
	}

	// Validate rules field
	if rules, ok := meta["rules"]; !ok || rules == nil {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodePackMissingRules,
			Message:    "pack_meta.rules is required.",
			Suggestion: "Add rules field with list of rule IDs",
		})
	} else if rulesList, ok := rules.([]interface{}); !ok {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodePackInvalidFieldType,
			Message:    "pack_meta.rules must be an array.",
			Suggestion: "Define rules as an array of rule ID strings",
		})
	} else if len(rulesList) == 0 {
		errors = append(errors, &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodePackMissingRules,
			Message:    "pack_meta.rules must not be empty.",
			Suggestion: "Add at least one rule ID to the rules array",
		})
	}

	// Validate optional i18n fields
	if val, exists := meta["description"]; exists && val != nil {
		if err := validateI18nFieldType(val, "description", filePath); err != nil {
			errors = append(errors, err)
		}
	}

	return errors
}

// Helper functions

// validateRequiredStringField validates that a required string field exists and is non-empty.
func validateRequiredStringField(meta map[string]interface{}, field, filePath, errCode, message, suggestion string) *ValidationError {
	val, exists := meta[field]
	if !exists || val == nil {
		return &ValidationError{
			FilePath:   filePath,
			ErrorCode:  errCode,
			Message:    message,
			Suggestion: suggestion,
		}
	}

	if str, ok := val.(string); !ok || str == "" {
		return &ValidationError{
			FilePath:   filePath,
			ErrorCode:  errCode,
			Message:    message + " and must be non-empty.",
			Suggestion: suggestion,
		}
	}

	return nil
}

// validateRequiredI18nField validates that a required i18n field exists and has valid type.
func validateRequiredI18nField(meta map[string]interface{}, field, filePath, errCode, message, suggestion string) *ValidationError {
	val, exists := meta[field]
	if !exists || val == nil {
		return &ValidationError{
			FilePath:   filePath,
			ErrorCode:  errCode,
			Message:    message,
			Suggestion: suggestion,
		}
	}

	// Check type: must be string or map
	switch v := val.(type) {
	case string:
		if v == "" {
			return &ValidationError{
				FilePath:   filePath,
				ErrorCode:  errCode,
				Message:    message + " and must be non-empty.",
				Suggestion: suggestion,
			}
		}
	case map[string]interface{}:
		if len(v) == 0 {
			return &ValidationError{
				FilePath:   filePath,
				ErrorCode:  errCode,
				Message:    message + " and must be non-empty.",
				Suggestion: suggestion,
			}
		}
	default:
		msg := i18n.Msg()
		return &ValidationError{
			FilePath:   filePath,
			ErrorCode:  errCode + "_TYPE",
			Message:    fmt.Sprintf(msg.Errors.FieldMustBeStringOrDict, field),
			Suggestion: fmt.Sprintf(msg.Errors.ChangeFieldToI18nFormat, field),
		}
	}

	return nil
}

// validateI18nFieldType validates that a field has a valid i18n type.
func validateI18nFieldType(val interface{}, field, filePath string) *ValidationError {
	switch val.(type) {
	case string, map[string]interface{}:
		return nil
	default:
		msg := i18n.Msg()
		return &ValidationError{
			FilePath:   filePath,
			ErrorCode:  ErrCodeRuleInvalidFieldType,
			Message:    fmt.Sprintf(msg.Errors.RuleMetaFieldMustBeStringOrDict, field),
			Suggestion: fmt.Sprintf(msg.Errors.ChangeFieldToI18nFormat, field),
		}
	}
}

// isValidSeverity checks if severity is valid.
func isValidSeverity(severity string) bool {
	s := strings.ToLower(severity)
	return s == models.SeverityHigh || s == models.SeverityMedium || s == models.SeverityLow
}

// loadHelperModulesFromPath loads helper modules based on file or directory path.
func loadHelperModulesFromPath(path string) []RegoModule {
	// Determine starting directory based on whether path is file or directory
	var dir string
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if info.IsDir() {
		dir = path
	} else {
		dir = filepath.Dir(path)
	}

	// Walk up to find rules directory and its lib subdirectory
	for i := 0; i < 5; i++ {
		libDir := filepath.Join(dir, "lib")
		if dirExists(libDir) {
			return loadHelperModulesFromDir(dir)
		}
		parentDir := filepath.Dir(dir)
		if parentDir == dir {
			break
		}
		dir = parentDir
	}

	return nil
}
