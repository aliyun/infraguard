package ros

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
	"github.com/fatih/color"
)

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

// ResolveParameters resolves ROS template parameters using provided input values and defaults.
// Note: This function only handles parameter resolution (CLI inputs and defaults).
func ResolveParameters(template map[string]interface{}, inputParams models.TemplateParams) (map[string]interface{}, error) {
	// 1. Extract Parameters definition
	paramsDef, ok := template["Parameters"].(map[string]interface{})
	if !ok {
		// No parameters defined, nothing to resolve
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
			// Type validation
			validatedVal, err := validateParamType(paramName, val, paramDef)
			if err != nil {
				return nil, err
			}
			resolvedParams[paramName] = validatedVal
		}
	}

	// Store resolved parameters back in the template
	// (Function resolution will be handled separately in the resource processing stage)
	resolvedTemplate := make(map[string]interface{})
	for k, v := range template {
		resolvedTemplate[k] = v
	}

	// Update Parameters section with resolved values
	if len(resolvedParams) > 0 {
		updatedParamsDef := make(map[string]interface{})
		for paramName, paramDef := range paramsDef {
			if resolvedVal, ok := resolvedParams[paramName]; ok {
				// Update the parameter definition with the resolved value
				defCopy := make(map[string]interface{})
				if pd, ok := paramDef.(map[string]interface{}); ok {
					for k, v := range pd {
						defCopy[k] = v
					}
					defCopy["ResolvedValue"] = resolvedVal
				}
				updatedParamsDef[paramName] = defCopy
			} else {
				updatedParamsDef[paramName] = paramDef
			}
		}
		resolvedTemplate["Parameters"] = updatedParamsDef
	}

	return resolvedTemplate, nil
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
