package funcs

import (
	"fmt"
	"strings"
)

// FnSplit splits a string by delimiter
// Fn::Split: [",", "a,b,c"] => ["a", "b", "c"]
func FnSplit(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("Fn::Split requires an array of [delimiter, string]")
	}

	delimiterResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Split: error resolving delimiter: %w", err)
	}

	// If still a function, can't split (not an error, just can't resolve statically)
	if isFunction(delimiterResolved) {
		return map[string]interface{}{"Fn::Split": value}, nil
	}

	delimiter, ok := delimiterResolved.(string)
	if !ok {
		return nil, fmt.Errorf("Fn::Split: delimiter must be a string")
	}

	resolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Split: error resolving string: %w", err)
	}

	// If still a function, can't split (not an error, just can't resolve statically)
	if isFunction(resolved) {
		return map[string]interface{}{"Fn::Split": value}, nil
	}

	str := fmt.Sprintf("%v", resolved)
	parts := strings.Split(str, delimiter)

	result := make([]interface{}, len(parts))
	for i, part := range parts {
		result[i] = part
	}

	return result, nil
}
