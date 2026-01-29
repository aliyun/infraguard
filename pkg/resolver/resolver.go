// Package resolver handles ROS intrinsic function resolution.
package resolver

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// ResolveFunctions resolves ROS intrinsic functions in the template.
// It resolves functions that can be statically evaluated (Ref to parameters, Join, Sub, etc.)
// and leaves functions that require runtime information (GetAtt, GetAZs, conditional functions) unchanged.
func ResolveFunctions(template map[string]interface{}, params map[string]interface{}) map[string]interface{} {
	// Deep copy template to avoid modifying the original
	result := deepCopy(template).(map[string]interface{})

	// Extract resolved parameter values from the Parameters section
	resolvedParams := extractResolvedParams(result)

	// Merge with explicit params (for backward compatibility)
	allParams := make(map[string]interface{})
	for k, v := range params {
		allParams[k] = v
	}
	for k, v := range resolvedParams {
		if _, exists := allParams[k]; !exists {
			allParams[k] = v
		}
	}

	// Resolve functions in the template
	resolveValue(result, allParams, result)

	return result
}

// extractResolvedParams extracts resolved parameter values from the Parameters section
func extractResolvedParams(template map[string]interface{}) map[string]interface{} {
	params := make(map[string]interface{})

	if paramsSection, ok := template["Parameters"].(map[string]interface{}); ok {
		for paramName, paramDef := range paramsSection {
			if paramDefMap, ok := paramDef.(map[string]interface{}); ok {
				if resolvedVal, ok := paramDefMap["ResolvedValue"]; ok {
					params[paramName] = resolvedVal
				}
			}
		}
	}

	return params
}

// resolveValue recursively resolves functions in a value
func resolveValue(value interface{}, params map[string]interface{}, template map[string]interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		// Check if this is a function call
		if len(v) == 1 {
			for key, val := range v {
				if key == "Ref" {
					return resolveRef(val, params, template)
				} else if strings.HasPrefix(key, "Fn::") {
					return resolveFunction(key, val, params, template)
				}
			}
		}

		// Not a function, recurse into the map
		for key, val := range v {
			v[key] = resolveValue(val, params, template)
		}
		return v

	case []interface{}:
		// Recurse into array
		for i, val := range v {
			v[i] = resolveValue(val, params, template)
		}
		return v

	default:
		// Scalar value, return as-is
		return v
	}
}

// resolveRef resolves a Ref function
func resolveRef(refValue interface{}, params map[string]interface{}, template map[string]interface{}) interface{} {
	refName, ok := refValue.(string)
	if !ok {
		// Invalid Ref, return as-is
		return map[string]interface{}{"Ref": refValue}
	}

	// Check if it's a parameter reference
	if paramVal, exists := params[refName]; exists {
		return paramVal
	}

	// Check if it's a resource reference (keep as-is, will be handled by resource processing)
	if resources, ok := template["Resources"].(map[string]interface{}); ok {
		if _, exists := resources[refName]; exists {
			// Keep resource references unchanged
			return map[string]interface{}{"Ref": refName}
		}
	}

	// Unknown reference, keep as-is
	return map[string]interface{}{"Ref": refName}
}

// resolveFunction resolves a Fn::* function
func resolveFunction(funcName string, funcValue interface{}, params map[string]interface{}, template map[string]interface{}) interface{} {
	switch funcName {
	case "Fn::Join":
		return resolveFnJoin(funcValue, params, template)
	case "Fn::Sub":
		return resolveFnSub(funcValue, params, template)
	case "Fn::Base64Encode":
		return resolveFnBase64Encode(funcValue, params, template)
	case "Fn::Select":
		return resolveFnSelect(funcValue, params, template)
	case "Fn::Split":
		return resolveFnSplit(funcValue, params, template)

	default:
		// Unknown/UnSupport function, keep as-is
		return map[string]interface{}{funcName: funcValue}
	}
}

// resolveFnJoin resolves Fn::Join - joins a list of strings with a delimiter
func resolveFnJoin(value interface{}, params map[string]interface{}, template map[string]interface{}) interface{} {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		// Invalid format, return as-is
		return map[string]interface{}{"Fn::Join": value}
	}

	delimiter, ok := arr[0].(string)
	if !ok {
		// Delimiter is not a string, might need resolution
		delimiter = fmt.Sprintf("%v", resolveValue(arr[0], params, template))
	}

	parts, ok := arr[1].([]interface{})
	if !ok {
		// Invalid parts array, return as-is
		return map[string]interface{}{"Fn::Join": value}
	}

	// Resolve each part
	resolvedParts := make([]string, 0, len(parts))
	for _, part := range parts {
		resolved := resolveValue(part, params, template)

		// If the resolved value is still a function, we can't join it
		if isFunction(resolved) {
			// Return the original Join with partially resolved parts
			return map[string]interface{}{"Fn::Join": value}
		}

		resolvedParts = append(resolvedParts, fmt.Sprintf("%v", resolved))
	}

	return strings.Join(resolvedParts, delimiter)
}

// resolveFnSub resolves Fn::Sub - substitutes variables in a string
func resolveFnSub(value interface{}, params map[string]interface{}, template map[string]interface{}) interface{} {
	// Fn::Sub can be either a string or [string, {vars}]
	switch v := value.(type) {
	case string:
		// Simple format: Fn::Sub: "string with ${VarName}"
		return substituteVariables(v, params, template)

	case []interface{}:
		// Array format: Fn::Sub: ["string", {var: value}]
		if len(v) < 1 {
			return map[string]interface{}{"Fn::Sub": value}
		}

		str, ok := v[0].(string)
		if !ok {
			return map[string]interface{}{"Fn::Sub": value}
		}

		// Merge provided variables with params
		vars := make(map[string]interface{})
		for k, v := range params {
			vars[k] = v
		}

		if len(v) >= 2 {
			if varMap, ok := v[1].(map[string]interface{}); ok {
				for k, val := range varMap {
					vars[k] = resolveValue(val, params, template)
				}
			}
		}

		return substituteVariables(str, vars, template)

	default:
		return map[string]interface{}{"Fn::Sub": value}
	}
}

// substituteVariables substitutes ${VarName} patterns in a string
func substituteVariables(str string, vars map[string]interface{}, template map[string]interface{}) interface{} {
	// Pattern to match ${VarName} or ${!Literal}
	re := regexp.MustCompile(`\$\{(!?)([^}]+)\}`)

	// Check if all variables can be resolved
	canResolve := true
	result := re.ReplaceAllStringFunc(str, func(match string) string {
		matches := re.FindStringSubmatch(match)
		if len(matches) < 3 {
			return match
		}

		literal := matches[1]
		varName := matches[2]

		// Handle literal (${!Literal} -> ${Literal})
		if literal == "!" {
			return "${" + varName + "}"
		}

		// Try to resolve the variable
		if val, exists := vars[varName]; exists {
			return fmt.Sprintf("%v", val)
		}

		// Check for pseudo parameters (ALIYUN::StackId, ALIYUN::Region, etc.)
		if strings.HasPrefix(varName, "ALIYUN::") {
			// Cannot resolve pseudo parameters statically
			canResolve = false
			return match
		}

		// Check for resource attributes (Resource.Attribute)
		if strings.Contains(varName, ".") {
			// Cannot resolve resource attributes statically
			canResolve = false
			return match
		}

		// Unknown variable
		canResolve = false
		return match
	})

	if !canResolve {
		// Cannot fully resolve, return as-is
		return map[string]interface{}{"Fn::Sub": str}
	}

	return result
}

// resolveFnBase64Encode resolves Fn::Base64Encode
func resolveFnBase64Encode(value interface{}, params map[string]interface{}, template map[string]interface{}) interface{} {
	resolved := resolveValue(value, params, template)

	// If still a function, can't encode
	if isFunction(resolved) {
		return map[string]interface{}{"Fn::Base64Encode": value}
	}

	str := fmt.Sprintf("%v", resolved)
	return base64.StdEncoding.EncodeToString([]byte(str))
}

// resolveFnSelect resolves Fn::Select - selects an element from a list
func resolveFnSelect(value interface{}, params map[string]interface{}, template map[string]interface{}) interface{} {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return map[string]interface{}{"Fn::Select": value}
	}

	// Resolve the index
	indexResolved := resolveValue(arr[0], params, template)

	// Try to convert to int
	var index int
	switch v := indexResolved.(type) {
	case int:
		index = v
	case float64:
		index = int(v)
	case string:
		fmt.Sscanf(v, "%d", &index)
	default:
		return map[string]interface{}{"Fn::Select": value}
	}

	// Resolve the list
	listResolved := resolveValue(arr[1], params, template)
	list, ok := listResolved.([]interface{})
	if !ok {
		return map[string]interface{}{"Fn::Select": value}
	}

	// Check bounds
	if index < 0 || index >= len(list) {
		return map[string]interface{}{"Fn::Select": value}
	}

	return list[index]
}

// resolveFnSplit resolves Fn::Split - splits a string by delimiter
func resolveFnSplit(value interface{}, params map[string]interface{}, template map[string]interface{}) interface{} {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return map[string]interface{}{"Fn::Split": value}
	}

	delimiter, ok := arr[0].(string)
	if !ok {
		return map[string]interface{}{"Fn::Split": value}
	}

	resolved := resolveValue(arr[1], params, template)

	// If still a function, can't split
	if isFunction(resolved) {
		return map[string]interface{}{"Fn::Split": value}
	}

	str := fmt.Sprintf("%v", resolved)
	parts := strings.Split(str, delimiter)

	result := make([]interface{}, len(parts))
	for i, part := range parts {
		result[i] = part
	}

	return result
}

// isFunction checks if a value is a function call
func isFunction(value interface{}) bool {
	m, ok := value.(map[string]interface{})
	if !ok || len(m) != 1 {
		return false
	}

	for key := range m {
		return key == "Ref" || strings.HasPrefix(key, "Fn::")
	}

	return false
}

// deepCopy creates a deep copy of the value
func deepCopy(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		copy := make(map[string]interface{}, len(v))
		for key, val := range v {
			copy[key] = deepCopy(val)
		}
		return copy

	case []interface{}:
		copy := make([]interface{}, len(v))
		for i, val := range v {
			copy[i] = deepCopy(val)
		}
		return copy

	default:
		// Primitive types are copied by value
		return v
	}
}
