package funcs

import (
	"fmt"
	"reflect"
)

// FnEachMemberIn checks if each member of the first list is in the second list
// Fn::EachMemberIn: [["a", "b"], ["a", "b", "c"]] => true
// Fn::EachMemberIn: [["a", "d"], ["a", "b", "c"]] => false
func FnEachMemberIn(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("Fn::EachMemberIn requires an array of [list1, list2]")
	}

	// Resolve both lists
	list1Resolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::EachMemberIn: error resolving first list: %w", err)
	}

	list2Resolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::EachMemberIn: error resolving second list: %w", err)
	}

	// If either is still a function, can't check (not an error, just can't resolve statically)
	if isFunction(list1Resolved) || isFunction(list2Resolved) {
		return map[string]interface{}{"Fn::EachMemberIn": value}, nil
	}

	list1, ok := list1Resolved.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::EachMemberIn: first parameter must be a list, got %T", list1Resolved)
	}

	list2, ok := list2Resolved.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::EachMemberIn: second parameter must be a list, got %T", list2Resolved)
	}

	// Check if each member of list1 is in list2
	for _, member := range list1 {
		found := false
		for _, item := range list2 {
			if reflect.DeepEqual(member, item) {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}

	return true, nil
}
