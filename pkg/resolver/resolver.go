package resolver

import (
	"strings"

	"github.com/aliyun/infraguard/pkg/resolver/funcs"
)

// ResolveFunctions resolves ROS intrinsic functions in the template.
// It resolves functions that can be statically evaluated (Ref to parameters, Join, Sub, etc.)
// and leaves functions that require runtime information (GetAtt, GetAZs, conditional functions) unchanged.
// Errors during resolution are logged but do not prevent the template from being returned.
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
	// In lenient mode, errors are ignored and original values are kept
	resolved, err := resolveValue(result, allParams, result)
	if err != nil {
		// Log error but continue with original template
		// In future, this could be controlled by a mode flag (strict vs lenient)
		return result
	}

	return resolved.(map[string]interface{})
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
func resolveValue(value interface{}, params map[string]interface{}, template map[string]interface{}) (interface{}, error) {
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
			resolved, err := resolveValue(val, params, template)
			if err != nil {
				return nil, err
			}
			v[key] = resolved
		}
		return v, nil

	case []interface{}:
		// Recurse into array
		for i, val := range v {
			resolved, err := resolveValue(val, params, template)
			if err != nil {
				return nil, err
			}
			v[i] = resolved
		}
		return v, nil

	default:
		// Scalar value, return as-is
		return v, nil
	}
}

// resolveRef resolves a Ref function
func resolveRef(refValue interface{}, params map[string]interface{}, template map[string]interface{}) (interface{}, error) {
	refName, ok := refValue.(string)
	if !ok {
		// Invalid Ref, return as-is (not an error, just can't resolve)
		return map[string]interface{}{"Ref": refValue}, nil
	}

	// Check if it's a parameter reference
	if paramVal, exists := params[refName]; exists {
		return paramVal, nil
	}

	// Check if it's a resource reference (keep as-is, will be handled by resource processing)
	if resources, ok := template["Resources"].(map[string]interface{}); ok {
		if _, exists := resources[refName]; exists {
			// Keep resource references unchanged
			return map[string]interface{}{"Ref": refName}, nil
		}
	}

	// Unknown reference, keep as-is (not an error, just can't resolve statically)
	return map[string]interface{}{"Ref": refName}, nil
}

// resolveFunction resolves a Fn::* function
func resolveFunction(funcName string, funcValue interface{}, params map[string]interface{}, template map[string]interface{}) (interface{}, error) {
	switch funcName {
	case "Fn::Join":
		return funcs.FnJoin(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Sub":
		return funcs.FnSub(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Base64Encode":
		return funcs.FnBase64Encode(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Base64Decode":
		return funcs.FnBase64Decode(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Select":
		return funcs.FnSelect(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Split":
		return funcs.FnSplit(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Str":
		return funcs.FnStr(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Indent":
		return funcs.FnIndent(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Replace":
		return funcs.FnReplace(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Index":
		return funcs.FnIndex(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Length":
		return funcs.FnLength(funcValue, params, template, resolveValue, isFunction)
	case "Fn::ListMerge":
		return funcs.FnListMerge(funcValue, params, template, resolveValue, isFunction)
	case "Fn::SelectMapList":
		return funcs.FnSelectMapList(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Add":
		return funcs.FnAdd(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Avg":
		return funcs.FnAvg(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Max":
		return funcs.FnMax(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Min":
		return funcs.FnMin(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Calculate":
		return funcs.FnCalculate(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Equals":
		return funcs.FnEquals(funcValue, params, template, resolveValue, isFunction)
	case "Fn::And":
		return funcs.FnAnd(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Or":
		return funcs.FnOr(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Not":
		return funcs.FnNot(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Contains":
		return funcs.FnContains(funcValue, params, template, resolveValue, isFunction)
	case "Fn::Any":
		return funcs.FnAny(funcValue, params, template, resolveValue, isFunction)
	case "Fn::EachMemberIn":
		return funcs.FnEachMemberIn(funcValue, params, template, resolveValue, isFunction)
	case "Fn::MatchPattern":
		return funcs.FnMatchPattern(funcValue, params, template, resolveValue, isFunction)
	case "Fn::If":
		return funcs.FnIf(funcValue, params, template, resolveValue, isFunction)
	case "Fn::FindInMap":
		return funcs.FnFindInMap(funcValue, params, template, resolveValue, isFunction)
	case "Fn::GetJsonValue":
		return funcs.FnGetJsonValue(funcValue, params, template, resolveValue, isFunction)
	case "Fn::MergeMapToList":
		return funcs.FnMergeMapToList(funcValue, params, template, resolveValue, isFunction)

	default:
		// Unknown/Unsupported function, keep as-is (not an error)
		return map[string]interface{}{funcName: funcValue}, nil
	}
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
