package funcs

import (
	"fmt"
)

// FnSelect selects an element from a list
// Fn::Select: [0, ["a", "b", "c"]] => "a"
func FnSelect(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("Fn::Select requires an array of [index, list]")
	}

	// Resolve the index
	indexResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Select: error resolving index: %w", err)
	}

	// If still a function, can't select (not an error, just can't resolve statically)
	if isFunction(indexResolved) {
		return map[string]interface{}{"Fn::Select": value}, nil
	}

	// Try to convert to int
	var index int
	switch v := indexResolved.(type) {
	case int:
		index = v
	case float64:
		index = int(v)
	case string:
		_, err := fmt.Sscanf(v, "%d", &index)
		if err != nil {
			return nil, fmt.Errorf("Fn::Select: invalid index format: %s", v)
		}
	default:
		return nil, fmt.Errorf("Fn::Select: index must be a number, got %T", v)
	}

	// Resolve the list
	listResolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Select: error resolving list: %w", err)
	}

	// If still a function, can't select (not an error, just can't resolve statically)
	if isFunction(listResolved) {
		return map[string]interface{}{"Fn::Select": value}, nil
	}

	list, ok := listResolved.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::Select: second parameter must be a list")
	}

	// Check bounds
	if index < 0 || index >= len(list) {
		return nil, fmt.Errorf("Fn::Select: index %d out of bounds for list of length %d", index, len(list))
	}

	return list[index], nil
}
