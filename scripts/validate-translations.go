package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aliyun/infraguard/pkg/config"
	"github.com/aliyun/infraguard/pkg/i18n"
	"gopkg.in/yaml.v3"
)

// TranslationFile represents a language translation YAML file
type TranslationFile struct {
	Path string
	Lang string
	Keys map[string]interface{}
}

func main() {
	localesDir := "pkg/i18n/locales"

	// Validate language consistency between config and i18n
	if err := validateLanguageConsistency(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Language consistency check failed: %v\n", err)
		os.Exit(1)
	}

	// Load all translation files
	files, err := loadTranslationFiles(localesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading translation files: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "No translation files found in %s\n", localesDir)
		os.Exit(1)
	}

	// Use English as reference
	var reference *TranslationFile
	for _, f := range files {
		if f.Lang == "en" {
			reference = f
			break
		}
	}

	if reference == nil {
		fmt.Fprintf(os.Stderr, "English reference file not found\n")
		os.Exit(1)
	}

	// Validate all files against reference
	hasErrors := false
	for _, file := range files {
		if file.Lang == "en" {
			continue // Skip reference file
		}

		fmt.Printf("Validating %s.yaml...\n", file.Lang)

		missingKeys := findMissingKeys(reference.Keys, file.Keys, "")
		if len(missingKeys) > 0 {
			hasErrors = true
			fmt.Printf("  ❌ Missing keys in %s:\n", file.Lang)
			for _, key := range missingKeys {
				fmt.Printf("    - %s\n", key)
			}
		}

		extraKeys := findMissingKeys(file.Keys, reference.Keys, "")
		if len(extraKeys) > 0 {
			hasErrors = true
			fmt.Printf("  ⚠️  Extra keys in %s (not in reference):\n", file.Lang)
			for _, key := range extraKeys {
				fmt.Printf("    - %s\n", key)
			}
		}

		if len(missingKeys) == 0 && len(extraKeys) == 0 {
			fmt.Printf("  ✅ All keys present\n")
		}
	}

	// Validate policies translations
	fmt.Println("\nValidating policies translations...")
	policyErrors := validatePoliciesTranslations()
	if policyErrors {
		hasErrors = true
	}

	if hasErrors {
		fmt.Println("\n❌ Validation failed")
		os.Exit(1)
	}

	fmt.Println("\n✅ All translation files are valid")
}

func loadTranslationFiles(dir string) ([]*TranslationFile, error) {
	var files []*TranslationFile

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		lang := strings.TrimSuffix(entry.Name(), ".yaml")
		path := filepath.Join(dir, entry.Name())

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", path, err)
		}

		var keys map[string]interface{}
		if err := yaml.Unmarshal(data, &keys); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}

		files = append(files, &TranslationFile{
			Path: path,
			Lang: lang,
			Keys: keys,
		})
	}

	return files, nil
}

func findMissingKeys(reference, target map[string]interface{}, prefix string) []string {
	var missing []string

	for key, refValue := range reference {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		targetValue, exists := target[key]
		if !exists {
			missing = append(missing, fullKey)
			continue
		}

		// If the value is a nested map, recurse
		if refMap, ok := refValue.(map[string]interface{}); ok {
			if targetMap, ok := targetValue.(map[string]interface{}); ok {
				nestedMissing := findMissingKeys(refMap, targetMap, fullKey)
				missing = append(missing, nestedMissing...)
			} else {
				// Type mismatch
				missing = append(missing, fullKey)
			}
		}
	}

	return missing
}

// validateLanguageConsistency checks that config.ValidLangValues and i18n supported languages match exactly
func validateLanguageConsistency() error {
	configLangs := config.ValidLangValues
	i18nLangs := i18n.GetSupportedLanguages()

	// Create maps for efficient lookup
	configMap := make(map[string]bool)
	for _, lang := range configLangs {
		configMap[lang] = true
	}

	i18nMap := make(map[string]bool)
	for _, lang := range i18nLangs {
		i18nMap[lang] = true
	}

	// Find languages in config but not in i18n
	var missingInI18n []string
	for _, lang := range configLangs {
		if !i18nMap[lang] {
			missingInI18n = append(missingInI18n, lang)
		}
	}

	// Find languages in i18n but not in config
	var missingInConfig []string
	for _, lang := range i18nLangs {
		if !configMap[lang] {
			missingInConfig = append(missingInConfig, lang)
		}
	}

	if len(missingInI18n) > 0 || len(missingInConfig) > 0 {
		var issues []string
		if len(missingInI18n) > 0 {
			sort.Strings(missingInI18n)
			issues = append(issues, fmt.Sprintf("languages in config.ValidLangValues but not in i18n: %v", missingInI18n))
		}
		if len(missingInConfig) > 0 {
			sort.Strings(missingInConfig)
			issues = append(issues, fmt.Sprintf("languages in i18n but not in config.ValidLangValues: %v", missingInConfig))
		}
		return fmt.Errorf("language mismatch: %s", strings.Join(issues, "; "))
	}

	// Sort for display
	configSorted := make([]string, len(configLangs))
	copy(configSorted, configLangs)
	sort.Strings(configSorted)

	i18nSorted := make([]string, len(i18nLangs))
	copy(i18nSorted, i18nLangs)
	sort.Strings(i18nSorted)

	fmt.Println("✅ Language consistency check passed:")
	fmt.Printf("   Config languages: %v\n", configSorted)
	fmt.Printf("   i18n languages:   %v\n", i18nSorted)
	return nil
}

// PolicyMeta represents metadata extracted from rego files
type PolicyMeta struct {
	Type           string            // "rule" or "pack"
	File           string            // file path
	ID             string            // policy id
	Name           map[string]string // language -> translation
	Description    map[string]string // language -> translation
	Reason         map[string]string // language -> translation (only for rules)
	Recommendation map[string]string // language -> translation (only for rules)
}

// validatePoliciesTranslations validates i18n support in policy rego files
func validatePoliciesTranslations() bool {
	validLangs := make(map[string]bool)
	for _, lang := range config.ValidLangValues {
		validLangs[lang] = true
	}

	hasErrors := false

	// Check rules
	rulesDir := "policies/aliyun/rules"
	rules, err := scanPolicyFiles(rulesDir, "rule")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning rules: %v\n", err)
		return true
	}

	if len(rules) > 0 {
		fmt.Printf("\nChecking %d rule files...\n", len(rules))
		ruleErrorCount := 0
		for _, rule := range rules {
			ruleErrors := validatePolicyMeta(rule, validLangs, []string{"name", "description", "reason", "recommendation"})
			if ruleErrors {
				hasErrors = true
				ruleErrorCount++
			}
		}
		if ruleErrorCount == 0 {
			fmt.Printf("  ✅ All rule files have complete translations\n")
		} else {
			fmt.Printf("  ⚠️  %d rule files have missing translations\n", ruleErrorCount)
		}
	}

	// Check packs
	packsDir := "policies/aliyun/packs"
	packs, err := scanPolicyFiles(packsDir, "pack")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning packs: %v\n", err)
		return true
	}

	if len(packs) > 0 {
		fmt.Printf("\nChecking %d pack files...\n", len(packs))
		packErrorCount := 0
		for _, pack := range packs {
			packErrors := validatePolicyMeta(pack, validLangs, []string{"name", "description"})
			if packErrors {
				hasErrors = true
				packErrorCount++
			}
		}
		if packErrorCount == 0 {
			fmt.Printf("  ✅ All pack files have complete translations\n")
		} else {
			fmt.Printf("  ⚠️  %d pack files have missing translations\n", packErrorCount)
		}
	}

	return hasErrors
}

// validatePolicyMeta validates that a policy meta has all required language translations
func validatePolicyMeta(meta PolicyMeta, validLangs map[string]bool, requiredFields []string) bool {
	hasErrors := false
	fileDisplay := filepath.Base(meta.File)
	var fieldErrors []string

	for _, field := range requiredFields {
		var translations map[string]string
		switch field {
		case "name":
			translations = meta.Name
		case "description":
			translations = meta.Description
		case "reason":
			translations = meta.Reason
		case "recommendation":
			translations = meta.Recommendation
		default:
			continue
		}

		if translations == nil || len(translations) == 0 {
			fieldErrors = append(fieldErrors, fmt.Sprintf("    - %s: missing field", field))
			hasErrors = true
			continue
		}

		// Check for missing languages
		var missingLangs []string
		for lang := range validLangs {
			if _, exists := translations[lang]; !exists {
				missingLangs = append(missingLangs, lang)
			}
		}

		if len(missingLangs) > 0 {
			sort.Strings(missingLangs)
			fieldErrors = append(fieldErrors, fmt.Sprintf("    - %s missing languages: %v", field, missingLangs))
			hasErrors = true
		}

		// Check for invalid languages
		var invalidLangs []string
		for lang := range translations {
			if !validLangs[lang] {
				invalidLangs = append(invalidLangs, lang)
			}
		}

		if len(invalidLangs) > 0 {
			sort.Strings(invalidLangs)
			fieldErrors = append(fieldErrors, fmt.Sprintf("    - %s has invalid languages: %v", field, invalidLangs))
			hasErrors = true
		}
	}

	// Output errors grouped by file
	if len(fieldErrors) > 0 {
		fmt.Printf("  ❌ %s:\n", fileDisplay)
		for _, err := range fieldErrors {
			fmt.Println(err)
		}
	}

	return hasErrors
}

// scanPolicyFiles scans a directory for rego files and extracts metadata
func scanPolicyFiles(dir string, metaType string) ([]PolicyMeta, error) {
	var metas []PolicyMeta

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		meta, err := extractPolicyMeta(string(data), path, metaType)
		if err != nil {
			// Skip files that don't have the expected meta structure
			return nil
		}

		if meta != nil {
			metas = append(metas, *meta)
		}

		return nil
	})

	return metas, err
}

// extractPolicyMeta extracts metadata from rego file content
func extractPolicyMeta(content, filePath, metaType string) (*PolicyMeta, error) {
	var metaName string
	if metaType == "rule" {
		metaName = "rule_meta"
	} else {
		metaName = "pack_meta"
	}

	// Find the start of meta object: "meta_name := {"
	metaStartPattern := regexp.MustCompile(fmt.Sprintf(`%s\s*:=\s*\{`, regexp.QuoteMeta(metaName)))
	startMatch := metaStartPattern.FindStringIndex(content)
	if startMatch == nil {
		return nil, nil // No meta found, skip
	}

	// Find the matching closing brace by counting braces
	startPos := startMatch[1] - 1 // Position of opening brace
	braceCount := 0
	endPos := -1

	for i := startPos; i < len(content); i++ {
		char := content[i]
		if char == '{' {
			braceCount++
		} else if char == '}' {
			braceCount--
			if braceCount == 0 {
				endPos = i
				break
			}
		}
	}

	if endPos == -1 {
		return nil, nil // Could not find matching brace
	}

	metaContent := content[startPos+1 : endPos]

	meta := &PolicyMeta{
		Type:           metaType,
		File:           filePath,
		Name:           make(map[string]string),
		Description:    make(map[string]string),
		Reason:         make(map[string]string),
		Recommendation: make(map[string]string),
	}

	// Extract ID
	idPattern := regexp.MustCompile(`"id"\s*:\s*"([^"]+)"`)
	if idMatch := idPattern.FindStringSubmatch(metaContent); len(idMatch) > 1 {
		meta.ID = idMatch[1]
	}

	// Extract name translations
	meta.Name = extractI18nField(metaContent, "name")
	meta.Description = extractI18nField(metaContent, "description")
	if metaType == "rule" {
		meta.Reason = extractI18nField(metaContent, "reason")
		meta.Recommendation = extractI18nField(metaContent, "recommendation")
	}

	return meta, nil
}

// extractI18nField extracts i18n translations from a field in rego content
func extractI18nField(content, fieldName string) map[string]string {
	translations := make(map[string]string)

	// Pattern to match: "field_name": { ... }
	fieldStartPattern := regexp.MustCompile(fmt.Sprintf(`"%s"\s*:\s*\{`, regexp.QuoteMeta(fieldName)))
	startMatch := fieldStartPattern.FindStringIndex(content)
	if startMatch == nil {
		return translations
	}

	// Find the matching closing brace
	startPos := startMatch[1] - 1 // Position of opening brace
	braceCount := 0
	endPos := -1

	for i := startPos; i < len(content); i++ {
		char := content[i]
		if char == '{' {
			braceCount++
		} else if char == '}' {
			braceCount--
			if braceCount == 0 {
				endPos = i
				break
			}
		}
	}

	if endPos == -1 {
		return translations
	}

	fieldContent := content[startPos+1 : endPos]

	// Extract language -> value pairs: "lang": "value"
	// Handle both single-line and multi-line formats
	langPattern := regexp.MustCompile(`"([a-z]{2})"\s*:\s*"([^"]*)"`)
	langMatches := langPattern.FindAllStringSubmatch(fieldContent, -1)

	for _, match := range langMatches {
		if len(match) >= 3 {
			lang := match[1]
			value := match[2]
			translations[lang] = value
		}
	}

	return translations
}
