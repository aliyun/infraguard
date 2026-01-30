package funcs

import (
	"fmt"
)

// FnListMerge merges multiple lists into one
// Fn::ListMerge: [["a", "b"], ["c", "d"]] => ["a", "b", "c", "d"]
func FnListMerge(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::ListMerge requires an array of lists")
	}

	result := make([]interface{}, 0)

	for _, item := range arr {
		// Resolve each list
		listResolved, err := resolveValue(item, params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::ListMerge: error resolving list: %w", err)
		}

		// If still a function, can't merge (not an error, just can't resolve statically)
		if isFunction(listResolved) {
			return map[string]interface{}{"Fn::ListMerge": value}, nil
		}

		list, ok := listResolved.([]interface{})
		if !ok {
			return nil, fmt.Errorf("Fn::ListMerge: each element must be a list, got %T", listResolved)
		}

		// Append all items from this list
		result = append(result, list...)
	}

	return result, nil
}
