package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aliyun/infraguard/pkg/engine"
	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/loader"
	"github.com/aliyun/infraguard/pkg/mapper"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/aliyun/infraguard/pkg/policy"
	"github.com/aliyun/infraguard/pkg/providers/ros"
	"github.com/aliyun/infraguard/pkg/reporter"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	scanPolicies []string // Changed to support multiple values
	scanFormat   string
	scanOutput   string
	scanInput    []string
	scanMode     string // New: scan mode (static or preview)
)

// Color functions for error output
var (
	errorColor = color.New(color.FgRed, color.Bold)
	dimColor   = color.New(color.Faint)
)

var scanCmd = &cobra.Command{
	Use:          "scan <template>...",
	Short:        "", // Set dynamically
	Long:         "", // Set dynamically
	Args:         cobra.MinimumNArgs(1),
	RunE:         runScan,
	SilenceUsage: true,
}

func init() {
	// Flag descriptions - using English as default since init runs before language detection
	scanCmd.Flags().StringArrayVarP(&scanPolicies, "policy", "p", nil,
		"Policy specification: rule ID, pack ID, .rego file, or directory (can be specified multiple times)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "table",
		"Output format (table, json, or html)")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "",
		"Output file path (default: report.html for html format)")
	scanCmd.Flags().StringArrayVarP(&scanInput, "input", "i", nil,
		"Parameter values in key=value, JSON format, or file path (can be specified multiple times)")
	scanCmd.Flags().StringVarP(&scanMode, "mode", "m", "static",
		"Scan mode: 'static' for local analysis or 'preview' for ROS PreviewStack API (default: static)")

	scanCmd.MarkFlagRequired("policy")
}

// PolicySpec represents a parsed policy specification.
type PolicySpec struct {
	Type      string // "rule", "pack", "file", "dir"
	Value     string // The ID or path
	IsPattern bool   // True if Value contains wildcard pattern
}

// parsePolicySpec parses a policy specification string.
// Returns the type ("rule", "pack", "file", "dir") and value.
func parsePolicySpec(spec string) (*PolicySpec, error) {
	msg := i18n.Msg()
	// Check for rule ID format: rule:<provider>:<name>
	if strings.HasPrefix(spec, "rule:") {
		isPattern := strings.Contains(spec, "*")
		return &PolicySpec{Type: "rule", Value: spec, IsPattern: isPattern}, nil
	}

	// Check for pack ID format: pack:<provider>:<name>
	if strings.HasPrefix(spec, "pack:") {
		isPattern := strings.Contains(spec, "*")
		return &PolicySpec{Type: "pack", Value: spec, IsPattern: isPattern}, nil
	}

	// Check if it's a file or directory path
	info, err := os.Stat(spec)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(msg.Errors.PathNotFound, spec)
		}
		return nil, err
	}

	if info.IsDir() {
		// Validate directory contains .rego files
		hasRego := false
		filepath.WalkDir(spec, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(path, ".rego") {
				hasRego = true
				return filepath.SkipAll
			}
			return nil
		})
		if !hasRego {
			return nil, fmt.Errorf(msg.Errors.NoRegoFilesInDir, spec)
		}
		return &PolicySpec{Type: "dir", Value: spec}, nil
	}

	// It's a file
	if !strings.HasSuffix(spec, ".rego") {
		return nil, fmt.Errorf(msg.Errors.PolicyFileExtension, spec)
	}
	return &PolicySpec{Type: "file", Value: spec}, nil
}

func runScan(cmd *cobra.Command, args []string) error {
	msg := i18n.Msg()
	lang := i18n.GetLanguage()

	// Validate format
	validFormats := map[string]bool{"table": true, "json": true, "html": true}
	if !validFormats[scanFormat] {
		return fmt.Errorf(msg.Errors.InvalidFormat, scanFormat)
	}

	// Validate mode
	validModes := map[string]bool{"static": true, "preview": true}
	if !validModes[scanMode] {
		return fmt.Errorf(msg.Errors.InvalidMode, scanMode)
	}

	// Validate global language flag if provided
	if globalLang != "" {
		supportedLangs := i18n.GetSupportedLanguages()

		// Extract language code prefix (e.g., "fr-FR" -> "fr", "fr" -> "fr")
		langCode := strings.ToLower(globalLang)
		if parts := strings.Split(langCode, "-"); len(parts) > 0 {
			langCode = parts[0]
		}

		// Check if the language code is in the supported languages list
		isSupported := false
		for _, lang := range supportedLangs {
			if lang == langCode {
				isSupported = true
				break
			}
		}

		if !isSupported {
			return fmt.Errorf(msg.Errors.InvalidLang, globalLang)
		}
	}

	// Parse policy specifications
	policySpecs, err := parsePolicySpecs(scanPolicies)
	if err != nil {
		return err
	}

	// Build evaluation options based on policy specs
	evalOpts, err := buildEvalOptions(policySpecs, msg)
	if err != nil {
		return err
	}

	// Parse parameter inputs
	inputParams, err := loader.ParseInputValues(scanInput)
	if err != nil {
		return err
	}

	// Collect all template files
	templateFiles, err := collectTemplates(args)
	if err != nil {
		return err
	}

	if len(templateFiles) == 0 {
		return fmt.Errorf("%s", msg.Scan.NoTemplatesFound)
	}

	var results []models.FileResult
	hasViolations := false
	hasHighSeverity := false

	// Process each template
	for _, templatePath := range templateFiles {
		// Load template based on mode
		var yamlRoot *yaml.Node
		var templateData map[string]interface{}
		var err error

		// Use unified loading logic for both static and preview modes
		yamlRoot, templateData, err = loadTemplateWithMode(templatePath, inputParams, scanMode)
		if err != nil {
			// Format and display error with color
			formatAndPrintError(templatePath, err, msg)

			// Skip this file and continue processing other files
			// This applies to both static and preview modes
			continue
		}

		// At this point, templateData is ready for policy evaluation
		// (parameters resolved, conditions evaluated, intrinsic functions processed)

		// Load and evaluate policies
		// We reuse evalOpts which contains loaded policies
		evalResult, err := engine.EvaluateWithOpts(evalOpts, templateData)
		if err != nil {
			return fmt.Errorf(msg.Scan.FileError, templatePath, fmt.Errorf(msg.Errors.EvaluatePolicies, err))
		}

		// Map violations to source locations with i18n support
		richViolations := mapper.MapViolationsWithLang(evalResult.Violations, yamlRoot, templatePath, lang)

		// Sort violations by severity
		sort.Slice(richViolations, func(i, j int) bool {
			return models.SeverityOrder(richViolations[i].Severity) < models.SeverityOrder(richViolations[j].Severity)
		})

		// Check for severity logic for exit code
		if len(richViolations) > 0 {
			hasViolations = true
			for _, v := range richViolations {
				if strings.EqualFold(v.Severity, models.SeverityHigh) {
					hasHighSeverity = true
				}
			}
		}

		// Append to results
		results = append(results, models.FileResult{
			File:       templatePath,
			Violations: richViolations,
		})
	}

	// If no templates were successfully processed, return error
	// This prevents showing "No violations found" when all templates failed validation
	if len(results) == 0 {
		return fmt.Errorf("%s", msg.Scan.NoTemplatesProcessed)
	}

	// Determine output writer
	var outputFile *os.File
	writer := os.Stdout
	outputPath := scanOutput

	if scanFormat == "html" {
		// HTML format: write to file
		if outputPath == "" {
			outputPath = "report.html"
		}
		var err error
		outputFile, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf(msg.Errors.RenderReport, err)
		}
		defer outputFile.Close()
		writer = outputFile
	}

	// Render report
	r := reporter.New(scanFormat, writer)
	if err := r.Render(results); err != nil {
		return fmt.Errorf(msg.Errors.RenderReport, err)
	}

	// Print message for HTML output
	if scanFormat == "html" {
		fmt.Fprintf(os.Stdout, msg.Scan.ReportWritten+"\n", outputPath)
	}

	// Exit with non-zero if violations found
	if hasHighSeverity {
		os.Exit(2)
	}
	if hasViolations {
		os.Exit(1)
	}

	return nil
}

// collectTemplates recursively finds all supported template files in the given paths.
func collectTemplates(paths []string) ([]string, error) {
	var files []string
	seen := make(map[string]bool)

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}

		if !info.IsDir() {
			absPath, err := filepath.Abs(path)
			if err != nil {
				return nil, err
			}
			if !seen[absPath] {
				if isTemplateFile(absPath) {
					files = append(files, absPath)
					seen[absPath] = true
				}
			}
			continue
		}

		// Directory: walk recursively
		err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && isTemplateFile(p) {
				absPath, err := filepath.Abs(p)
				if err != nil {
					return err
				}
				if !seen[absPath] {
					files = append(files, absPath)
					seen[absPath] = true
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

func isTemplateFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".json" || ext == ".yaml" || ext == ".yml"
}

// parsePolicySpecs parses all policy specification strings.
func parsePolicySpecs(specs []string) ([]*PolicySpec, error) {
	if len(specs) == 0 {
		return nil, nil
	}

	result := make([]*PolicySpec, 0, len(specs))
	for _, spec := range specs {
		parsed, err := parsePolicySpec(spec)
		if err != nil {
			return nil, err
		}
		result = append(result, parsed)
	}
	return result, nil
}

// buildEvalOptions builds engine evaluation options from policy specs.
func buildEvalOptions(specs []*PolicySpec, msg *i18n.Messages) (*engine.EvalOptions, error) {
	opts := &engine.EvalOptions{
		PolicyPaths: []string{},
		RuleIDs:     []string{},
		PackIDs:     []string{},
		IDMapping:   make(map[string]string),
	}

	// If no specs provided, try using fallback loader (embedded + local)
	if len(specs) == 0 {
		policyLoader, err := policy.LoadWithFallback()
		if err == nil {
			opts.Modules = make(map[string]string)
			opts.LibModules = make(map[string]string)
			for _, rule := range policyLoader.GetAllRules() {
				opts.RuleIDs = append(opts.RuleIDs, rule.ID)
				if rule.Content != "" {
					opts.Modules[rule.FilePath] = rule.Content
				} else if rule.FilePath != "" {
					opts.PolicyPaths = append(opts.PolicyPaths, rule.FilePath)
				}
			}
			index := policyLoader.GetIndex()
			if index.LibModules != nil {
				for k, v := range index.LibModules {
					opts.LibModules[k] = v
				}
			}
			return opts, nil
		}
		// Fallback to default directory if loading fails
		defaultDir := policy.DefaultPolicyDir()
		if err := policy.ValidatePath(defaultDir); err != nil {
			return nil, fmt.Errorf(msg.Errors.PolicyDir+"\n"+msg.Errors.PolicyDirHint, err)
		}
		opts.PolicyPaths = []string{defaultDir}
		return opts, nil
	}

	// Load policy index for rule/pack ID resolution and helper loading
	var policyLoader *policy.Loader
	var err error
	policyLoader, err = policy.LoadWithFallback()
	if err != nil {
		// Log error but continue if only local files are provided
		// If ID specs are present, this will fail later anyway if they are not in local files
	}

	// Build ID mapping and populate LibModules
	if policyLoader != nil {
		opts.Modules = make(map[string]string)
		opts.LibModules = make(map[string]string)
		for _, rule := range policyLoader.GetAllRules() {
			shortID := extractShortRuleID(rule.ID)
			if shortID != rule.ID {
				opts.IDMapping[shortID] = rule.ID
			}
		}

		// Always populate LibModules from loader
		for k, v := range policyLoader.GetLibModules() {
			opts.LibModules[k] = v
		}
	}

	for _, spec := range specs {
		switch spec.Type {
		case "rule":
			if policyLoader != nil {
				if spec.IsPattern {
					// Handle wildcard pattern matching
					matchedRules := policyLoader.MatchRules(spec.Value)
					if len(matchedRules) == 0 {
						return nil, fmt.Errorf(msg.Errors.PolicyPatternNoMatch, spec.Value)
					}
					for _, rule := range matchedRules {
						opts.RuleIDs = append(opts.RuleIDs, rule.ID)
						// Add the rule's content for evaluation
						if rule.Content != "" {
							opts.Modules[rule.FilePath] = rule.Content
						} else if rule.FilePath != "" {
							opts.PolicyPaths = append(opts.PolicyPaths, rule.FilePath)
						}
					}
				} else {
					// Handle exact match (backward compatibility)
					rule := policyLoader.GetRule(spec.Value)
					if rule == nil {
						return nil, fmt.Errorf(msg.Errors.PolicyNotFound, spec.Value)
					}
					opts.RuleIDs = append(opts.RuleIDs, spec.Value)
					// Add the rule's content for evaluation
					if rule.Content != "" {
						opts.Modules[rule.FilePath] = rule.Content
					} else if rule.FilePath != "" {
						opts.PolicyPaths = append(opts.PolicyPaths, rule.FilePath)
					}
				}
			}
		case "pack":
			if policyLoader != nil {
				if spec.IsPattern {
					// Handle wildcard pattern matching
					matchedPacks := policyLoader.MatchPacks(spec.Value)
					if len(matchedPacks) == 0 {
						return nil, fmt.Errorf(msg.Errors.PolicyPatternNoMatch, spec.Value)
					}
					for _, pack := range matchedPacks {
						opts.PackIDs = append(opts.PackIDs, pack.ID)
						// Add all rule file contents for this pack
						for _, ruleID := range pack.RuleIDs {
							rule := policyLoader.GetRule(ruleID)
							if rule != nil {
								if rule.Content != "" {
									opts.Modules[rule.FilePath] = rule.Content
								} else if rule.FilePath != "" {
									opts.PolicyPaths = append(opts.PolicyPaths, rule.FilePath)
								}
							}
						}
					}
				} else {
					// Handle exact match (backward compatibility)
					pack := policyLoader.GetPack(spec.Value)
					if pack == nil {
						return nil, fmt.Errorf(msg.Errors.PolicyNotFound, spec.Value)
					}
					opts.PackIDs = append(opts.PackIDs, spec.Value)
					// Add all rule file contents for this pack
					for _, ruleID := range pack.RuleIDs {
						rule := policyLoader.GetRule(ruleID)
						if rule != nil {
							if rule.Content != "" {
								opts.Modules[rule.FilePath] = rule.Content
							} else if rule.FilePath != "" {
								opts.PolicyPaths = append(opts.PolicyPaths, rule.FilePath)
							}
						}
					}
				}
			}
		case "file", "dir":
			opts.PolicyPaths = append(opts.PolicyPaths, spec.Value)
		}
	}

	// If we have rule/pack IDs but no explicit file paths and no modules, use default policy dir
	if len(opts.PolicyPaths) == 0 && len(opts.Modules) == 0 && (len(opts.RuleIDs) > 0 || len(opts.PackIDs) > 0) {
		opts.PolicyPaths = []string{policy.DefaultPolicyDir()}
	}

	return opts, nil
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

// contains checks if a string slice contains a value.
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// formatAndPrintError formats and prints error messages with color support
func formatAndPrintError(templatePath string, err error, msg *i18n.Messages) {
	// Check if output is a TTY for color support
	isTTY := false
	if stat, err := os.Stderr.Stat(); err == nil {
		isTTY = (stat.Mode() & os.ModeCharDevice) != 0
	}

	// Try to extract FormattedAPIError from error chain using errors.As
	var formattedErr *ros.FormattedAPIError
	if errors.As(err, &formattedErr) {
		// Found FormattedAPIError in error chain
		if isTTY {
			// Format error with color - skip the prefix since we'll format it ourselves
			errorColor.Fprintf(os.Stderr, msg.Scan.SkippedFile+"\n", templatePath, "")
			fmt.Fprintf(os.Stderr, "  ")
			errorColor.Fprintf(os.Stderr, msg.Scan.StatusCode+"\n", formattedErr.StatusCode)
			fmt.Fprintf(os.Stderr, "  ")
			errorColor.Fprintf(os.Stderr, msg.Scan.Code+"\n", formattedErr.Code)
			fmt.Fprintf(os.Stderr, "  ")
			errorColor.Fprintf(os.Stderr, msg.Scan.Message+"\n", formattedErr.Message)
			if formattedErr.RequestID != "" {
				fmt.Fprintf(os.Stderr, "  ")
				dimColor.Fprintf(os.Stderr, msg.Scan.RequestID+"\n", formattedErr.RequestID)
			}
		} else {
			// No color support, use simple format
			fmt.Fprintf(os.Stderr, msg.Scan.SkippedFile+"\n", templatePath, formattedErr)
		}
	} else {
		// Fallback to simple error format
		if isTTY {
			errorColor.Fprintf(os.Stderr, msg.Scan.SkippedFile+"\n", templatePath, err)
		} else {
			fmt.Fprintf(os.Stderr, msg.Scan.SkippedFile+"\n", templatePath, err)
		}
	}
}

// loadTemplateWithMode loads a template using the specified mode (static or preview)
func loadTemplateWithMode(templatePath string, inputParams map[string]interface{}, mode string) (*yaml.Node, map[string]interface{}, error) {
	msg := i18n.Msg()

	// Detect template type - for now we only support ROS templates
	// In the future, this could be extended to support other IaC providers

	// Try to load template to check if it's a valid ROS template
	_, templateData, err := ros.LoadLocalTemplate(templatePath)
	if err != nil {
		return nil, nil, err
	}

	// Check if it's a ROS template
	if err := ros.ValidateROSTemplate(templateData); err != nil {
		// Not a ROS template, return error
		return nil, nil, fmt.Errorf("%s", msg.Errors.PreviewOnlyROSSupported)
	}

	// Use ROS provider
	var rosMode ros.Mode
	switch mode {
	case "static":
		rosMode = ros.ModeStatic
	case "preview":
		rosMode = ros.ModePreview
	default:
		return nil, nil, fmt.Errorf(msg.Errors.PreviewUnsupportedMode, mode)
	}

	return ros.Load(rosMode, templatePath, inputParams)
}
