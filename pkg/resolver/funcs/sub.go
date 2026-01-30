package funcs

import (
	"fmt"
	"regexp"
	"strings"
)

// FnSub substitutes variables in a string
// Fn::Sub: "Hello ${Name}" => "Hello World" (if Name=World)
// Fn::Sub: ["Hello ${Name}", {"Name": "World"}] => "Hello World"
func FnSub(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	// Fn::Sub can be either a string or [string, {vars}]
	switch v := value.(type) {
	case string:
		// Simple format: Fn::Sub: "string with ${VarName}"
		return substituteVariables(v, params, template, resolveValue, isFunction)

	case []interface{}:
		// Array format: Fn::Sub: ["string", {var: value}]
		if len(v) < 1 {
			return nil, fmt.Errorf("Fn::Sub requires at least a string parameter")
		}

		strResolved, err := resolveValue(v[0], params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::Sub: error resolving string: %w", err)
		}

		// If still a function, can't substitute (not an error, just can't resolve statically)
		if isFunction(strResolved) {
			return map[string]interface{}{"Fn::Sub": value}, nil
		}

		str, ok := strResolved.(string)
		if !ok {
			return nil, fmt.Errorf("Fn::Sub: first parameter must be a string")
		}

		// Merge provided variables with params
		vars := make(map[string]interface{})
		for k, v := range params {
			vars[k] = v
		}

		if len(v) >= 2 {
			varMapResolved, err := resolveValue(v[1], params, template)
			if err != nil {
				return nil, fmt.Errorf("Fn::Sub: error resolving variables: %w", err)
			}

			// If still a function, can't substitute
			if isFunction(varMapResolved) {
				return map[string]interface{}{"Fn::Sub": value}, nil
			}

			if varMap, ok := varMapResolved.(map[string]interface{}); ok {
				for k, val := range varMap {
					resolved, err := resolveValue(val, params, template)
					if err != nil {
						return nil, fmt.Errorf("Fn::Sub: error resolving variable %s: %w", k, err)
					}
					vars[k] = resolved
				}
			}
		}

		return substituteVariables(str, vars, template, resolveValue, isFunction)

	default:
		return nil, fmt.Errorf("Fn::Sub requires a string or array parameter")
	}
}

// substituteVariables substitutes ${VarName} patterns in a string
func substituteVariables(str string, vars map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
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
		// Cannot fully resolve, return as-is (not an error, just can't resolve statically)
		return map[string]interface{}{"Fn::Sub": str}, nil
	}

	return result, nil
}
