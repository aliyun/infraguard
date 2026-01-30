package funcs

import (
	"testing"
)

func TestFnAny(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected bool
	}{
		{
			name:     "any true",
			input:    []interface{}{[]interface{}{false, true, false}},
			expected: true,
		},
		{
			name:     "all false",
			input:    []interface{}{[]interface{}{false, false, false}},
			expected: false,
		},
		{
			name:     "all true",
			input:    []interface{}{[]interface{}{true, true, true}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnAny(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if err != nil {
				t.Errorf("FnAny() error = %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("FnAny() = %v, want %v", result, tt.expected)
			}
		})
	}
}
