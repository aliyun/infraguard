package loader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/fatih/color"
	"gopkg.in/yaml.v3"
)

// ParseInputValues parses multiple input flag values into TemplateParams.
// Supports key=value, JSON string, and file paths (JSON/YAML/KV).
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

// ValidateInputParameters validates that all provided input parameters are defined in the template's Parameters section.
// Returns an error if any undefined parameters are found.
func ValidateInputParameters(template map[string]interface{}, inputParams models.TemplateParams) error {
	// Extract parameter names from template Parameters section
	paramsDef, ok := template["Parameters"].(map[string]interface{})
	if !ok {
		// No Parameters section defined
		if len(inputParams) > 0 {
			// User provided input but template has no parameters
			paramNames := make([]string, 0, len(inputParams))
			for name := range inputParams {
				paramNames = append(paramNames, name)
			}
			// Highlight parameter names in the error message
			paramColor := color.New(color.FgYellow, color.Bold)
			highlightedParams := make([]string, len(paramNames))
			for i, param := range paramNames {
				highlightedParams[i] = paramColor.Sprint(param)
			}
			paramList := strings.Join(highlightedParams, ", ")
			return fmt.Errorf(i18n.Msg().Errors.NoParametersDefined, paramList)
		}
		// No parameters and no input - valid case
		return nil
	}

	// Build set of defined parameter names
	definedParams := make(map[string]bool)
	for paramName := range paramsDef {
		definedParams[paramName] = true
	}

	// Check for undefined parameters
	undefinedParams := make([]string, 0)
	for inputParam := range inputParams {
		if !definedParams[inputParam] {
			undefinedParams = append(undefinedParams, inputParam)
		}
	}

	// Return error if any undefined parameters found
	if len(undefinedParams) > 0 {
		// Highlight parameter names in the error message
		paramColor := color.New(color.FgYellow, color.Bold)
		highlightedParams := make([]string, len(undefinedParams))
		for i, param := range undefinedParams {
			highlightedParams[i] = paramColor.Sprint(param)
		}
		paramList := strings.Join(highlightedParams, ", ")
		return fmt.Errorf(i18n.Msg().Errors.UndefinedParameters, paramList)
	}

	return nil
}

// ResolveParameters resolves parameters in the template using provided input values and defaults.
func ResolveParameters(template map[string]interface{}, inputParams models.TemplateParams) (map[string]interface{}, error) {
	// 1. Extract Parameters definition
	paramsDef, ok := template["Parameters"].(map[string]interface{})
	if !ok {
		// No parameters defined, nothing to resolve (unless we want to support Ref to things not in Parameters?)
		// But according to design, we only resolve Ref if it exists in Parameters.
		return template, nil
	}

	// 2. Resolve final parameter values (CLI > Default)
	resolvedParams := make(map[string]interface{})
	for paramName, def := range paramsDef {
		paramDef, ok := def.(map[string]interface{})
		if !ok {
			continue
		}

		var val interface{}
		var found bool

		// Check CLI input first
		if inputVal, ok := inputParams[paramName]; ok {
			val = inputVal
			found = true
		} else if defaultVal, ok := paramDef["Default"]; ok {
			// Fallback to default
			val = defaultVal
			found = true
		}

		if found {
			// Type validation (Task 1.3.4)
			validatedVal, err := validateParamType(paramName, val, paramDef)
			if err != nil {
				return nil, err
			}
			resolvedParams[paramName] = validatedVal
		}
	}

	// 3. Resolve Ref in Resources
	resources, ok := template["Resources"].(map[string]interface{})
	if !ok {
		return template, nil
	}

	// Deep copy resources to avoid modifying the original data
	resolvedResources := deepCopyMap(resources)
	resolveRefs(resolvedResources, resolvedParams)

	// Create a new template map with resolved resources
	resolvedTemplate := make(map[string]interface{})
	for k, v := range template {
		if k == "Resources" {
			resolvedTemplate[k] = resolvedResources
		} else {
			resolvedTemplate[k] = v
		}
	}

	return resolvedTemplate, nil
}

func resolveRefs(data interface{}, params map[string]interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			if isRef(val, params) {
				v[key] = getRefValue(val, params)
			} else {
				resolveRefs(val, params)
			}
		}
	case []interface{}:
		for i, val := range v {
			if isRef(val, params) {
				v[i] = getRefValue(val, params)
			} else {
				resolveRefs(val, params)
			}
		}
	}
}

func isRef(data interface{}, params map[string]interface{}) bool {
	m, ok := data.(map[string]interface{})
	if !ok || len(m) != 1 {
		return false
	}
	refVal, ok := m["Ref"]
	if !ok {
		return false
	}
	refName, ok := refVal.(string)
	if !ok {
		return false
	}
	_, exists := params[refName]
	return exists
}

func getRefValue(data interface{}, params map[string]interface{}) interface{} {
	m := data.(map[string]interface{})
	refName := m["Ref"].(string)
	return params[refName]
}

func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range m {
		cp[k] = deepCopyValue(v)
	}
	return cp
}

func deepCopyValue(v interface{}) interface{} {
	switch v := v.(type) {
	case map[string]interface{}:
		return deepCopyMap(v)
	case []interface{}:
		cp := make([]interface{}, len(v))
		for i, val := range v {
			cp[i] = deepCopyValue(val)
		}
		return cp
	default:
		return v
	}
}

func validateParamType(name string, val interface{}, def map[string]interface{}) (interface{}, error) {
	// If value is nil (Default: null), skip type validation as it indicates optional parameter
	if val == nil {
		return nil, nil
	}

	typeName, _ := def["Type"].(string)
	if typeName == "" {
		return val, nil
	}

	switch typeName {
	case "String":
		return fmt.Sprintf("%v", val), nil
	case "Number":
		// Try to convert to float64 or int
		switch v := val.(type) {
		case int, int64, float64:
			return v, nil
		case string:
			var f float64
			if _, err := fmt.Sscanf(v, "%f", &f); err == nil {
				return f, nil
			}
			return nil, fmt.Errorf(i18n.Msg().Errors.ParameterTypeMismatch, name, val, typeName)
		default:
			return nil, fmt.Errorf(i18n.Msg().Errors.ParameterTypeMismatch, name, val, typeName)
		}
	case "Boolean":
		switch v := val.(type) {
		case bool:
			return v, nil
		case string:
			lower := strings.ToLower(v)
			if lower == "true" {
				return true, nil
			}
			if lower == "false" {
				return false, nil
			}
			return nil, fmt.Errorf(i18n.Msg().Errors.ParameterTypeMismatch, name, val, typeName)
		default:
			return nil, fmt.Errorf(i18n.Msg().Errors.ParameterTypeMismatch, name, val, typeName)
		}
	case "CommaDelimitedList":
		if s, ok := val.(string); ok {
			parts := strings.Split(s, ",")
			result := make([]interface{}, len(parts))
			for i, p := range parts {
				result[i] = strings.TrimSpace(p)
			}
			return result, nil
		}
		if l, ok := val.([]interface{}); ok {
			return l, nil
		}
		return nil, fmt.Errorf(i18n.Msg().Errors.ParameterTypeMismatch, name, val, typeName)
	case "Json":
		if s, ok := val.(string); ok {
			var m interface{}
			if err := json.Unmarshal([]byte(s), &m); err == nil {
				return m, nil
			}
			return nil, fmt.Errorf(i18n.Msg().Errors.ParameterTypeMismatch, name, val, typeName)
		}
		return val, nil
	}

	return val, nil
}
