package funcs

import (
	"testing"
)

func TestFnEquals(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected bool
	}{
		{
			name:     "equal strings",
			input:    []interface{}{"hello", "hello"},
			expected: true,
		},
		{
			name:     "not equal strings",
			input:    []interface{}{"hello", "world"},
			expected: false,
		},
		{
			name:     "equal numbers",
			input:    []interface{}{42, 42},
			expected: true,
		},
		{
			name:     "equal booleans",
			input:    []interface{}{true, true},
			expected: true,
		},
		{
			name:     "not equal booleans",
			input:    []interface{}{true, false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnEquals(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if err != nil {
				t.Errorf("FnEquals() error = %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("FnEquals() = %v, want %v", result, tt.expected)
			}
		})
	}
}
