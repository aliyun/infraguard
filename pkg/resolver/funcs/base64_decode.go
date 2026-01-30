package funcs

import (
	"encoding/base64"
	"fmt"
)

// FnBase64Decode decodes a Base64-encoded string
// Fn::Base64Decode: "SGVsbG8gV29ybGQ=" => "Hello World"
func FnBase64Decode(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	resolved, err := resolveValue(value, params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Base64Decode: error resolving value: %w", err)
	}

	// If still a function, can't decode (not an error, just can't resolve statically)
	if isFunction(resolved) {
		return map[string]interface{}{"Fn::Base64Decode": value}, nil
	}

	str, ok := resolved.(string)
	if !ok {
		return nil, fmt.Errorf("Fn::Base64Decode: value must be a string, got %T", resolved)
	}

	decoded, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, fmt.Errorf("Fn::Base64Decode: invalid Base64 string: %w", err)
	}

	return string(decoded), nil
}
