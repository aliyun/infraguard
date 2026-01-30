package funcs

import (
	"testing"
)

func TestFnStr(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "integer",
			input:    42,
			expected: "42",
		},
		{
			name:     "float",
			input:    3.14,
			expected: "3.14",
		},
		{
			name:     "string",
			input:    "test",
			expected: "test",
		},
		{
			name:     "boolean",
			input:    true,
			expected: "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnStr(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if err != nil {
				t.Errorf("FnStr() error = %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("FnStr() = %v, want %v", result, tt.expected)
			}
		})
	}
}
