package funcs

import (
	"fmt"
)

// FnNot performs logical NOT on a boolean value
// Fn::Not: [true] => false
// Fn::Not: [false] => true
func FnNot(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 1 {
		return nil, fmt.Errorf("Fn::Not requires an array with one boolean value")
	}

	// Resolve the value
	resolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Not: error resolving value: %w", err)
	}

	// If still a function, can't evaluate (not an error, just can't resolve statically)
	if isFunction(resolved) {
		return map[string]interface{}{"Fn::Not": value}, nil
	}

	// Convert to boolean
	boolVal, err := ToBool(resolved)
	if err != nil {
		return nil, fmt.Errorf("Fn::Not: %w", err)
	}

	return !boolVal, nil
}
