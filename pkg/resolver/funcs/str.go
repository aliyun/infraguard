package funcs

import (
	"fmt"
)

// FnStr converts a number to a string
// Fn::Str: 42 => "42"
func FnStr(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	resolved, err := resolveValue(value, params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Str: error resolving value: %w", err)
	}

	// If still a function, can't convert (not an error, just can't resolve statically)
	if isFunction(resolved) {
		return map[string]interface{}{"Fn::Str": value}, nil
	}

	// Convert to string
	return fmt.Sprintf("%v", resolved), nil
}
