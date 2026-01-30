package funcs

import (
	"fmt"
)

// FnAny checks if any element in a list is truthy
// Fn::Any: [[false, true, false]] => true
// Fn::Any: [[false, false, false]] => false
func FnAny(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 1 {
		return nil, fmt.Errorf("Fn::Any requires an array with one list parameter")
	}

	// Resolve the list
	listResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Any: error resolving list: %w", err)
	}

	// If still a function, can't evaluate (not an error, just can't resolve statically)
	if isFunction(listResolved) {
		return map[string]interface{}{"Fn::Any": value}, nil
	}

	list, ok := listResolved.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::Any: parameter must be a list, got %T", listResolved)
	}

	// Check if any element is truthy
	for _, item := range list {
		boolVal, err := ToBool(item)
		if err != nil {
			return nil, fmt.Errorf("Fn::Any: %w", err)
		}

		if boolVal {
			return true, nil
		}
	}

	return false, nil
}
