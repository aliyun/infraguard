package funcs

import (
	"encoding/json"
	"fmt"
)

// FnFindInMap finds a value in a mapping
// Fn::FindInMap: [MapName, TopLevelKey, SecondLevelKey]
// Looks up template.Mappings[MapName][TopLevelKey][SecondLevelKey]
func FnFindInMap(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 3 {
		return nil, fmt.Errorf("Fn::FindInMap requires an array of [MapName, TopLevelKey, SecondLevelKey]")
	}

	// Resolve map name
	mapNameResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::FindInMap: error resolving map name: %w", err)
	}

	mapName, ok := mapNameResolved.(string)
	if !ok {
		return nil, fmt.Errorf("Fn::FindInMap: map name must be a string, got %T", mapNameResolved)
	}

	// Resolve top level key
	topKeyResolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::FindInMap: error resolving top level key: %w", err)
	}

	// If still a function, can't look up (not an error, just can't resolve statically)
	if isFunction(topKeyResolved) {
		return map[string]interface{}{"Fn::FindInMap": value}, nil
	}

	topKey := fmt.Sprintf("%v", topKeyResolved)

	// Resolve second level key
	secondKeyResolved, err := resolveValue(arr[2], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::FindInMap: error resolving second level key: %w", err)
	}

	// If still a function, can't look up
	if isFunction(secondKeyResolved) {
		return map[string]interface{}{"Fn::FindInMap": value}, nil
	}

	secondKey := fmt.Sprintf("%v", secondKeyResolved)

	// Look up in Mappings section
	mappings, ok := template["Mappings"].(map[string]interface{})
	if !ok {
		// No Mappings section, keep as-is
		return map[string]interface{}{"Fn::FindInMap": value}, nil
	}

	mapData, ok := mappings[mapName].(map[string]interface{})
	if !ok {
		// Map not found, keep as-is
		return map[string]interface{}{"Fn::FindInMap": value}, nil
	}

	topLevelData, ok := mapData[topKey].(map[string]interface{})
	if !ok {
		// Top level key not found, keep as-is
		return map[string]interface{}{"Fn::FindInMap": value}, nil
	}

	result, ok := topLevelData[secondKey]
	if !ok {
		// Second level key not found, keep as-is
		return map[string]interface{}{"Fn::FindInMap": value}, nil
	}

	return result, nil
}

// FnGetJsonValue extracts a value from a JSON string
// Fn::GetJsonValue: ["key", "{\"key\": \"value\"}"] => "value"
func FnGetJsonValue(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("Fn::GetJsonValue requires an array of [key, jsonString]")
	}

	// Resolve key
	keyResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::GetJsonValue: error resolving key: %w", err)
	}

	key, ok := keyResolved.(string)
	if !ok {
		return nil, fmt.Errorf("Fn::GetJsonValue: key must be a string, got %T", keyResolved)
	}

	// Resolve JSON string
	jsonStrResolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::GetJsonValue: error resolving JSON string: %w", err)
	}

	// If still a function, can't parse (not an error, just can't resolve statically)
	if isFunction(jsonStrResolved) {
		return map[string]interface{}{"Fn::GetJsonValue": value}, nil
	}

	jsonStr, ok := jsonStrResolved.(string)
	if !ok {
		return nil, fmt.Errorf("Fn::GetJsonValue: JSON string must be a string, got %T", jsonStrResolved)
	}

	// Parse JSON
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil, fmt.Errorf("Fn::GetJsonValue: invalid JSON: %w", err)
	}

	// Extract the key
	result, ok := data[key]
	if !ok {
		// Key not found, keep as-is
		return map[string]interface{}{"Fn::GetJsonValue": value}, nil
	}

	return result, nil
}

// FnMergeMapToList merges multiple maps into a list of maps
// Fn::MergeMapToList: [[{k1: v1}, {k2: v2}], [{k1: v3}, {k2: v4}]] => [{k1: v1, k2: v2}, {k1: v3, k2: v4}]
func FnMergeMapToList(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::MergeMapToList requires an array of map lists")
	}

	if len(arr) == 0 {
		return []interface{}{}, nil
	}

	// Resolve first list to determine the number of result items
	firstListResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::MergeMapToList: error resolving first list: %w", err)
	}

	// If still a function, can't merge (not an error, just can't resolve statically)
	if isFunction(firstListResolved) {
		return map[string]interface{}{"Fn::MergeMapToList": value}, nil
	}

	firstList, ok := firstListResolved.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::MergeMapToList: first element must be a list, got %T", firstListResolved)
	}

	numItems := len(firstList)
	result := make([]interface{}, numItems)

	// Initialize result with empty maps
	for i := range result {
		result[i] = make(map[string]interface{})
	}

	// Merge maps from each list
	for _, listItem := range arr {
		listResolved, err := resolveValue(listItem, params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::MergeMapToList: error resolving list: %w", err)
		}

		// If still a function, can't merge
		if isFunction(listResolved) {
			return map[string]interface{}{"Fn::MergeMapToList": value}, nil
		}

		list, ok := listResolved.([]interface{})
		if !ok {
			return nil, fmt.Errorf("Fn::MergeMapToList: each element must be a list, got %T", listResolved)
		}

		if len(list) != numItems {
			return nil, fmt.Errorf("Fn::MergeMapToList: all lists must have the same length")
		}

		// Merge maps at each position
		for i, item := range list {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("Fn::MergeMapToList: list items must be maps, got %T", item)
			}

			resultMap := result[i].(map[string]interface{})
			for k, v := range itemMap {
				resultMap[k] = v
			}
		}
	}

	return result, nil
}
