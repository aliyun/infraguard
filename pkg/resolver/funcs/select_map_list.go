package funcs

import (
	"fmt"
)

// FnSelectMapList extracts a specific field from a list of maps
// Fn::SelectMapList: ["key", [{"key": "v1"}, {"key": "v2"}]] => ["v1", "v2"]
func FnSelectMapList(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("Fn::SelectMapList requires an array of [key, mapList]")
	}

	// First parameter is the key to extract
	keyResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::SelectMapList: error resolving key: %w", err)
	}

	key, ok := keyResolved.(string)
	if !ok {
		return nil, fmt.Errorf("Fn::SelectMapList: key must be a string, got %T", keyResolved)
	}

	// Second parameter is the list of maps
	listResolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::SelectMapList: error resolving map list: %w", err)
	}

	// If still a function, can't select (not an error, just can't resolve statically)
	if isFunction(listResolved) {
		return map[string]interface{}{"Fn::SelectMapList": value}, nil
	}

	mapList, ok := listResolved.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::SelectMapList: second parameter must be a list, got %T", listResolved)
	}

	// Extract the key from each map
	result := make([]interface{}, 0, len(mapList))
	for _, item := range mapList {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Fn::SelectMapList: each element in the list must be a map, got %T", item)
		}

		if val, exists := itemMap[key]; exists {
			result = append(result, val)
		} else {
			// If key doesn't exist, append nil
			result = append(result, nil)
		}
	}

	return result, nil
}
