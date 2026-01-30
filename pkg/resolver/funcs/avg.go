package funcs

import (
	"fmt"
)

// FnAvg calculates the average of numbers
// Fn::Avg: [10, 20, 30] => 20
func FnAvg(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::Avg requires an array of numbers")
	}

	if len(arr) == 0 {
		return nil, fmt.Errorf("Fn::Avg requires at least 1 number")
	}

	var sum float64

	for _, item := range arr {
		// Resolve each value
		resolved, err := resolveValue(item, params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::Avg: error resolving value: %w", err)
		}

		// If still a function, can't calculate average (not an error, just can't resolve statically)
		if isFunction(resolved) {
			return map[string]interface{}{"Fn::Avg": value}, nil
		}

		// Convert to number
		num, err := toFloat64(resolved)
		if err != nil {
			return nil, fmt.Errorf("Fn::Avg: %w", err)
		}

		sum += num
	}

	avg := sum / float64(len(arr))

	// Return as int if it's a whole number
	if avg == float64(int(avg)) {
		return int(avg), nil
	}
	return avg, nil
}
