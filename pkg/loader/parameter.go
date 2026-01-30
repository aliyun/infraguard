// Package loader handles generic template input parsing.
// Provider-specific template loading and parameter resolution should be in the respective provider packages.
package loader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
	"gopkg.in/yaml.v3"
)

// ParseInputValues parses multiple input flag values into TemplateParams.
// Supports key=value, JSON string, and file paths (JSON/YAML/KV).
// This is a generic function that can be used by any IaC provider.
func ParseInputValues(inputs []string) (models.TemplateParams, error) {
	result := make(models.TemplateParams)

	for _, input := range inputs {
		params, err := parseInputValue(input)
		if err != nil {
			return nil, err
		}
		// Merge params, later ones override earlier ones
		for k, v := range params {
			result[k] = v
		}
	}

	return result, nil
}

func parseInputValue(input string) (models.TemplateParams, error) {
	// 1. Check if it's a file path
	if isFilePath(input) {
		return parseFile(input)
	}

	// 2. Try parsing as JSON
	if strings.HasPrefix(input, "{") {
		var params models.TemplateParams
		if err := json.Unmarshal([]byte(input), &params); err == nil {
			return params, nil
		}
		// If it starts with { but fails JSON parsing, it might be an invalid JSON
		// or a weirdly named key=value. We'll fall through to key=value.
	}

	// 3. Try parsing as key=value
	if strings.Contains(input, "=") {
		parts := strings.SplitN(input, "=", 2)
		return models.TemplateParams{parts[0]: parts[1]}, nil
	}

	return nil, fmt.Errorf(i18n.Msg().Errors.InvalidInput, input)
}

func isFilePath(input string) bool {
	// Check for path separators
	if strings.Contains(input, "/") || strings.Contains(input, "\\") {
		return true
	}
	// Check for common file extensions
	ext := strings.ToLower(filepath.Ext(input))
	switch ext {
	case ".json", ".yaml", ".yml", ".txt":
		return true
	}
	// Check if file exists
	if _, err := os.Stat(input); err == nil {
		return true
	}
	return false
}

func parseFile(path string) (models.TemplateParams, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(i18n.Msg().Errors.ReadInputFile, path, err)
	}

	ext := strings.ToLower(filepath.Ext(path))

	// Try JSON
	if ext == ".json" || (len(content) > 0 && content[0] == '{') {
		var params models.TemplateParams
		if err := json.Unmarshal(content, &params); err == nil {
			return params, nil
		}
		if ext == ".json" {
			return nil, fmt.Errorf(i18n.Msg().Errors.ParseInputFile, path, "invalid JSON.")
		}
	}

	// Try YAML
	if ext == ".yaml" || ext == ".yml" {
		var params models.TemplateParams
		if err := yaml.Unmarshal(content, &params); err == nil {
			return params, nil
		}
		return nil, fmt.Errorf(i18n.Msg().Errors.ParseInputFile, path, "invalid YAML.")
	}

	// Try KV format (multi-line)
	params := make(models.TemplateParams)
	lines := strings.Split(string(content), "\n")
	foundKV := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			params[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			foundKV = true
		}
	}

	if foundKV {
		return params, nil
	}

	// If everything fails and it was explicitly a YAML file, it should have been caught.
	// Last resort: try YAML anyway if no extension matched
	var finalParams models.TemplateParams
	if err := yaml.Unmarshal(content, &finalParams); err == nil {
		return finalParams, nil
	}

	return nil, fmt.Errorf(i18n.Msg().Errors.ParseInputFile, path, "unknown format.")
}
