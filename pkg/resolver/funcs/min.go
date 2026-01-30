package funcs

import (
	"fmt"
	"math"
)

// FnMin returns the minimum value from a list of numbers
// Fn::Min: [5, 10, 3] => 3
func FnMin(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::Min requires an array of numbers")
	}

	if len(arr) == 0 {
		return nil, fmt.Errorf("Fn::Min requires at least 1 number")
	}

	minVal := math.Inf(1)

	for _, item := range arr {
		// Resolve each value
		resolved, err := resolveValue(item, params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::Min: error resolving value: %w", err)
		}

		// If still a function, can't find min (not an error, just can't resolve statically)
		if isFunction(resolved) {
			return map[string]interface{}{"Fn::Min": value}, nil
		}

		// Convert to number
		num, err := toFloat64(resolved)
		if err != nil {
			return nil, fmt.Errorf("Fn::Min: %w", err)
		}

		if num < minVal {
			minVal = num
		}
	}

	// Return as int if it's a whole number
	if minVal == float64(int(minVal)) {
		return int(minVal), nil
	}
	return minVal, nil
}
