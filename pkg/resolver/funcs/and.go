package funcs

import (
	"fmt"
)

// FnAnd performs logical AND on a list of boolean values
// Fn::And: [true, true, true] => true
// Fn::And: [true, false, true] => false
func FnAnd(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::And requires an array of boolean values")
	}

	if len(arr) == 0 {
		return nil, fmt.Errorf("Fn::And requires at least 1 value")
	}

	for _, item := range arr {
		// Resolve each value
		resolved, err := resolveValue(item, params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::And: error resolving value: %w", err)
		}

		// If still a function, can't evaluate (not an error, just can't resolve statically)
		if isFunction(resolved) {
			return map[string]interface{}{"Fn::And": value}, nil
		}

		// Convert to boolean
		boolVal, err := ToBool(resolved)
		if err != nil {
			return nil, fmt.Errorf("Fn::And: %w", err)
		}

		// Short-circuit: if any value is false, return false
		if !boolVal {
			return false, nil
		}
	}

	// All values are true
	return true, nil
}

// ToBool converts a value to boolean
func ToBool(value interface{}) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		// Common string to bool conversions
		switch v {
		case "true", "True", "TRUE", "1":
			return true, nil
		case "false", "False", "FALSE", "0", "":
			return false, nil
		default:
			return false, fmt.Errorf("cannot convert string %q to boolean", v)
		}
	case int:
		return v != 0, nil
	case float64:
		return v != 0, nil
	default:
		return false, fmt.Errorf("cannot convert %T to boolean", v)
	}
}
