package funcs

import (
	"testing"
)

func TestFnIf(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected interface{}
	}{
		{
			name:     "condition true",
			input:    []interface{}{true, "yes", "no"},
			expected: "yes",
		},
		{
			name:     "condition false",
			input:    []interface{}{false, "yes", "no"},
			expected: "no",
		},
		{
			name:     "numeric condition true",
			input:    []interface{}{1, "yes", "no"},
			expected: "yes",
		},
		{
			name:     "numeric condition false",
			input:    []interface{}{0, "yes", "no"},
			expected: "no",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnIf(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if err != nil {
				t.Errorf("FnIf() error = %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("FnIf() = %v, want %v", result, tt.expected)
			}
		})
	}
}
