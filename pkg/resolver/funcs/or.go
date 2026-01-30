package funcs

import (
	"fmt"
)

// FnOr performs logical OR on a list of boolean values
// Fn::Or: [false, true, false] => true
// Fn::Or: [false, false, false] => false
func FnOr(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::Or requires an array of boolean values")
	}

	if len(arr) == 0 {
		return nil, fmt.Errorf("Fn::Or requires at least 1 value")
	}

	for _, item := range arr {
		// Resolve each value
		resolved, err := resolveValue(item, params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::Or: error resolving value: %w", err)
		}

		// If still a function, can't evaluate (not an error, just can't resolve statically)
		if isFunction(resolved) {
			return map[string]interface{}{"Fn::Or": value}, nil
		}

		// Convert to boolean
		boolVal, err := ToBool(resolved)
		if err != nil {
			return nil, fmt.Errorf("Fn::Or: %w", err)
		}

		// Short-circuit: if any value is true, return true
		if boolVal {
			return true, nil
		}
	}

	// All values are false
	return false, nil
}
