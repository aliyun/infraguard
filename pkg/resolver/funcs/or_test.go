package funcs

import (
	"testing"
)

func TestFnOr(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected bool
	}{
		{
			name:     "all false",
			input:    []interface{}{false, false, false},
			expected: false,
		},
		{
			name:     "one true",
			input:    []interface{}{false, true, false},
			expected: true,
		},
		{
			name:     "all true",
			input:    []interface{}{true, true, true},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnOr(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if err != nil {
				t.Errorf("FnOr() error = %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("FnOr() = %v, want %v", result, tt.expected)
			}
		})
	}
}
