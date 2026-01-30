package funcs

import (
	"fmt"
)

// FnIf performs conditional selection
// Fn::If: [conditionName, valueIfTrue, valueIfFalse]
// This function is used with Conditions section and should evaluate the condition
func FnIf(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 3 {
		return nil, fmt.Errorf("Fn::If requires an array of [condition, valueIfTrue, valueIfFalse]")
	}

	// First parameter is typically a condition name (string) or a boolean value
	conditionResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::If: error resolving condition: %w", err)
	}

	// If still a function, can't evaluate (not an error, just can't resolve statically)
	if isFunction(conditionResolved) {
		return map[string]interface{}{"Fn::If": value}, nil
	}

	var condition bool

	// Handle condition as a boolean or string reference
	switch v := conditionResolved.(type) {
	case bool:
		condition = v
	case string:
		// This is a condition name - look it up in params
		if condValue, exists := params[v]; exists {
			// Try to convert to boolean
			boolVal, err := ToBool(condValue)
			if err != nil {
				return nil, fmt.Errorf("Fn::If: condition %q: %w", v, err)
			}
			condition = boolVal
		} else {
			// Condition not found - keep as-is
			return map[string]interface{}{"Fn::If": value}, nil
		}
	default:
		// Try to convert to boolean
		boolVal, err := ToBool(conditionResolved)
		if err != nil {
			return nil, fmt.Errorf("Fn::If: condition must be a boolean or condition name, got %T", v)
		}
		condition = boolVal
	}

	// Select the appropriate value based on the condition
	if condition {
		result, err := resolveValue(arr[1], params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::If: error resolving true value: %w", err)
		}
		return result, nil
	} else {
		result, err := resolveValue(arr[2], params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::If: error resolving false value: %w", err)
		}
		return result, nil
	}
}
