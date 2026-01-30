package funcs

import (
	"fmt"
)

// FnAdd calculates the sum of numbers
// Fn::Add: [10, 20, 30] => 60
func FnAdd(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::Add requires an array of numbers")
	}

	if len(arr) < 2 {
		return nil, fmt.Errorf("Fn::Add requires at least 2 numbers")
	}

	var sum float64

	for _, item := range arr {
		// Resolve each value
		resolved, err := resolveValue(item, params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::Add: error resolving value: %w", err)
		}

		// If still a function, can't add (not an error, just can't resolve statically)
		if isFunction(resolved) {
			return map[string]interface{}{"Fn::Add": value}, nil
		}

		// Convert to number
		num, err := toFloat64(resolved)
		if err != nil {
			return nil, fmt.Errorf("Fn::Add: %w", err)
		}

		sum += num
	}

	// Return as int if it's a whole number
	if sum == float64(int(sum)) {
		return int(sum), nil
	}
	return sum, nil
}

// toFloat64 converts a value to float64
func toFloat64(value interface{}) (float64, error) {
	switch v := value.(type) {
	case int:
		return float64(v), nil
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case int32:
		return float64(v), nil
	default:
		return 0, fmt.Errorf("cannot convert %T to number", v)
	}
}
