package funcs

import (
	"fmt"
	"reflect"
)

// FnEquals checks if two values are equal
// Fn::Equals: [value1, value2] => true/false
func FnEquals(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("Fn::Equals requires an array of [value1, value2]")
	}

	// Resolve both values
	val1, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Equals: error resolving first value: %w", err)
	}

	val2, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Equals: error resolving second value: %w", err)
	}

	// If either value is still a function, can't compare (not an error, just can't resolve statically)
	if isFunction(val1) || isFunction(val2) {
		return map[string]interface{}{"Fn::Equals": value}, nil
	}

	// Deep equality check
	return reflect.DeepEqual(val1, val2), nil
}
