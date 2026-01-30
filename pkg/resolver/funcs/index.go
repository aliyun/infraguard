package funcs

import (
	"fmt"
	"reflect"
)

// FnIndex finds the index of an element in a list
// Fn::Index: [["a", "b", "c"], "b"] => 1
func FnIndex(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("Fn::Index requires an array of [list, element]")
	}

	// Resolve the list
	listResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Index: error resolving list: %w", err)
	}

	// If still a function, can't find index (not an error, just can't resolve statically)
	if isFunction(listResolved) {
		return map[string]interface{}{"Fn::Index": value}, nil
	}

	list, ok := listResolved.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::Index: first parameter must be a list, got %T", listResolved)
	}

	// Resolve the element to search for
	elementResolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Index: error resolving element: %w", err)
	}

	// If still a function, can't find index
	if isFunction(elementResolved) {
		return map[string]interface{}{"Fn::Index": value}, nil
	}

	// Find the element in the list
	for i, item := range list {
		if reflect.DeepEqual(item, elementResolved) {
			return i, nil
		}
	}

	// Element not found - return -1 (following common convention)
	return -1, nil
}
