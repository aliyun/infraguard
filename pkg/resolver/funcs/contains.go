package funcs

import (
	"fmt"
	"reflect"
)

// FnContains checks if a list contains a specific element
// Fn::Contains: [["a", "b", "c"], "b"] => true
// Fn::Contains: [["a", "b", "c"], "d"] => false
func FnContains(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("Fn::Contains requires an array of [list, element]")
	}

	// Resolve the list
	listResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Contains: error resolving list: %w", err)
	}

	// If still a function, can't check (not an error, just can't resolve statically)
	if isFunction(listResolved) {
		return map[string]interface{}{"Fn::Contains": value}, nil
	}

	list, ok := listResolved.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::Contains: first parameter must be a list, got %T", listResolved)
	}

	// Resolve the element to search for
	elementResolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Contains: error resolving element: %w", err)
	}

	// If still a function, can't check
	if isFunction(elementResolved) {
		return map[string]interface{}{"Fn::Contains": value}, nil
	}

	// Check if the element is in the list
	for _, item := range list {
		if reflect.DeepEqual(item, elementResolved) {
			return true, nil
		}
	}

	return false, nil
}
