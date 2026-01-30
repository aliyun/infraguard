package funcs

import (
	"encoding/base64"
	"fmt"
)

// FnBase64Encode encodes a string to Base64
// Fn::Base64Encode: "Hello World" => "SGVsbG8gV29ybGQ="
func FnBase64Encode(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	resolved, err := resolveValue(value, params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Base64Encode: error resolving value: %w", err)
	}

	// If still a function, can't encode (not an error, just can't resolve statically)
	if isFunction(resolved) {
		return map[string]interface{}{"Fn::Base64Encode": value}, nil
	}

	str := fmt.Sprintf("%v", resolved)
	return base64.StdEncoding.EncodeToString([]byte(str)), nil
}
