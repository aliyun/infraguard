package funcs

import (
	"fmt"
)

// FnLength calculates the length of a string or list
// Fn::Length: ["hello"] => 5
// Fn::Length: [[1, 2, 3]] => 3
func FnLength(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 1 {
		return nil, fmt.Errorf("Fn::Length requires an array with one element")
	}

	// Resolve the value
	resolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Length: error resolving value: %w", err)
	}

	// If still a function, can't calculate length (not an error, just can't resolve statically)
	if isFunction(resolved) {
		return map[string]interface{}{"Fn::Length": value}, nil
	}

	// Calculate length based on type
	switch v := resolved.(type) {
	case string:
		return len(v), nil
	case []interface{}:
		return len(v), nil
	default:
		return nil, fmt.Errorf("Fn::Length: value must be a string or list, got %T", v)
	}
}
