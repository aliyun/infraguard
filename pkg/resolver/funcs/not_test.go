package funcs

import (
	"testing"
)

func TestFnNot(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected bool
	}{
		{
			name:     "not true",
			input:    []interface{}{true},
			expected: false,
		},
		{
			name:     "not false",
			input:    []interface{}{false},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnNot(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if err != nil {
				t.Errorf("FnNot() error = %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("FnNot() = %v, want %v", result, tt.expected)
			}
		})
	}
}
