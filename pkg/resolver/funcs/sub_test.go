package funcs

import (
	"testing"
)

func TestFnSub(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		params   map[string]interface{}
		expected interface{}
		isMap    bool // If true, result should be kept as Fn::Sub
	}{
		{
			name:  "simple string substitution",
			input: "Hello ${Name}",
			params: map[string]interface{}{
				"Name": "World",
			},
			expected: "Hello World",
		},
		{
			name:  "multiple substitutions",
			input: "${Greeting} ${Name}!",
			params: map[string]interface{}{
				"Greeting": "Hi",
				"Name":     "Alice",
			},
			expected: "Hi Alice!",
		},
		{
			name: "array format with variables",
			input: []interface{}{
				"Hello ${Name}",
				map[string]interface{}{
					"Name": "Bob",
				},
			},
			expected: "Hello Bob",
		},
		{
			name: "array format merges with params",
			input: []interface{}{
				"${Env}-${App}",
				map[string]interface{}{
					"App": "web",
				},
			},
			params: map[string]interface{}{
				"Env": "prod",
			},
			expected: "prod-web",
		},
		{
			name:     "literal escape ${!Literal}",
			input:    "Path: ${!Literal}/data",
			params:   map[string]interface{}{},
			expected: "Path: ${Literal}/data",
		},
		{
			name:     "pseudo parameter cannot be resolved",
			input:    "Stack: ${ALIYUN::StackId}",
			params:   map[string]interface{}{},
			expected: map[string]interface{}{"Fn::Sub": "Stack: ${ALIYUN::StackId}"},
			isMap:    true,
		},
		{
			name:     "resource attribute cannot be resolved",
			input:    "ARN: ${MyResource.Arn}",
			params:   map[string]interface{}{},
			expected: map[string]interface{}{"Fn::Sub": "ARN: ${MyResource.Arn}"},
			isMap:    true,
		},
		{
			name:     "unknown variable cannot be resolved",
			input:    "Value: ${UnknownVar}",
			params:   map[string]interface{}{},
			expected: map[string]interface{}{"Fn::Sub": "Value: ${UnknownVar}"},
			isMap:    true,
		},
		{
			name:     "no variables",
			input:    "Plain text",
			params:   map[string]interface{}{},
			expected: "Plain text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnSub(tt.input, tt.params, nil, mockResolveValue, mockIsFunction)
			if err != nil {
				t.Errorf("FnSub() error = %v", err)
				return
			}

			if tt.isMap {
				resultMap, ok := result.(map[string]interface{})
				if !ok {
					t.Errorf("FnSub() expected to return map, got %T", result)
					return
				}
				expectedMap := tt.expected.(map[string]interface{})
				if resultMap["Fn::Sub"] != expectedMap["Fn::Sub"] {
					t.Errorf("FnSub() = %v, want %v", resultMap, expectedMap)
				}
			} else {
				if result != tt.expected {
					t.Errorf("FnSub() = %v, want %v", result, tt.expected)
				}
			}
		})
	}
}
