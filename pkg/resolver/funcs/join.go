package funcs

import (
	"fmt"
	"strings"
)

// FnJoin joins a list of strings with a delimiter
// Fn::Join: [",", ["a", "b", "c"]] => "a,b,c"
func FnJoin(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		// Invalid format, return error
		return nil, fmt.Errorf("Fn::Join requires an array of [delimiter, parts]")
	}

	delimiterResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Join: error resolving delimiter: %w", err)
	}

	// If still a function, can't join (not an error, just can't resolve statically)
	if isFunction(delimiterResolved) {
		return map[string]interface{}{"Fn::Join": value}, nil
	}

	delimiter := fmt.Sprintf("%v", delimiterResolved)

	partsResolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Join: error resolving parts: %w", err)
	}

	// If still a function, can't join (not an error, just can't resolve statically)
	if isFunction(partsResolved) {
		return map[string]interface{}{"Fn::Join": value}, nil
	}

	parts, ok := partsResolved.([]interface{})
	if !ok {
		// Invalid parts array, return error
		return nil, fmt.Errorf("Fn::Join: parts must be an array")
	}

	// Resolve each part
	resolvedParts := make([]string, 0, len(parts))
	for _, part := range parts {
		resolved, err := resolveValue(part, params, template)
		if err != nil {
			return nil, fmt.Errorf("Fn::Join: error resolving part: %w", err)
		}

		// If the resolved value is still a function, we can't join it (not an error, just can't resolve statically)
		if isFunction(resolved) {
			// Return the original Join with partially resolved parts
			return map[string]interface{}{"Fn::Join": value}, nil
		}

		resolvedParts = append(resolvedParts, fmt.Sprintf("%v", resolved))
	}

	return strings.Join(resolvedParts, delimiter), nil
}
