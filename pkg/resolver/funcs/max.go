package funcs

import (
	"fmt"
	"math"
)

// FnMax returns the maximum value from a list of numbers
// Fn::Max: [5, 10, 3] => 10
func FnMax(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::Max requires an array of numbers")
	}

	if len(arr) == 0 {
		return nil, fmt.Errorf("Fn::Max requires at least 1 number")
	}

	maxVal := math.Inf(-1)

	for _, item := range arr {
		// Resolve each value
		resolved, err := resolveValue(item, params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::Max: error resolving value: %w", err)
		}

		// If still a function, can't find max (not an error, just can't resolve statically)
		if isFunction(resolved) {
			return map[string]interface{}{"Fn::Max": value}, nil
		}

		// Convert to number
		num, err := toFloat64(resolved)
		if err != nil {
			return nil, fmt.Errorf("Fn::Max: %w", err)
		}

		if num > maxVal {
			maxVal = num
		}
	}

	// Return as int if it's a whole number
	if maxVal == float64(int(maxVal)) {
		return int(maxVal), nil
	}
	return maxVal, nil
}
