package funcs

import (
	"testing"
)

func TestFnContains(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected bool
	}{
		{
			name:     "contains element",
			input:    []interface{}{[]interface{}{"a", "b", "c"}, "b"},
			expected: true,
		},
		{
			name:     "does not contain",
			input:    []interface{}{[]interface{}{"a", "b", "c"}, "d"},
			expected: false,
		},
		{
			name:     "empty list",
			input:    []interface{}{[]interface{}{}, "a"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnContains(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if err != nil {
				t.Errorf("FnContains() error = %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("FnContains() = %v, want %v", result, tt.expected)
			}
		})
	}
}
