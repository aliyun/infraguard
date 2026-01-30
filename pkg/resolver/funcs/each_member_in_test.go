package funcs

import (
	"testing"
)

func TestFnEachMemberIn(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected bool
	}{
		{
			name: "all members present",
			input: []interface{}{
				[]interface{}{"a", "b"},
				[]interface{}{"a", "b", "c"},
			},
			expected: true,
		},
		{
			name: "some members missing",
			input: []interface{}{
				[]interface{}{"a", "d"},
				[]interface{}{"a", "b", "c"},
			},
			expected: false,
		},
		{
			name: "empty first list",
			input: []interface{}{
				[]interface{}{},
				[]interface{}{"a", "b", "c"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnEachMemberIn(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if err != nil {
				t.Errorf("FnEachMemberIn() error = %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("FnEachMemberIn() = %v, want %v", result, tt.expected)
			}
		})
	}
}
