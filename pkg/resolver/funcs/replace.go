package funcs

import (
	"fmt"
	"strings"
)

// FnReplace replaces occurrences of strings
// Fn::Replace: [{"old": "new"}, "old text"] => "new text"
func FnReplace(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("Fn::Replace requires an array of [replacements, string]")
	}

	// First parameter should be a map of replacements
	replacementsResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Replace: error resolving replacements: %w", err)
	}

	replacements, ok := replacementsResolved.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Fn::Replace: replacements must be a map, got %T", replacementsResolved)
	}

	// Second parameter is the string to replace in
	strResolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Replace: error resolving string: %w", err)
	}

	// If still a function, can't replace (not an error, just can't resolve statically)
	if isFunction(strResolved) {
		return map[string]interface{}{"Fn::Replace": value}, nil
	}

	result := fmt.Sprintf("%v", strResolved)

	// Apply replacements
	for old, newVal := range replacements {
		newStr := fmt.Sprintf("%v", newVal)
		result = strings.ReplaceAll(result, old, newStr)
	}

	return result, nil
}
