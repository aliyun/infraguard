package funcs

import (
	"testing"
)

func TestFnIndex(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected int
		wantErr  bool
	}{
		{
			name:     "find element",
			input:    []interface{}{[]interface{}{"a", "b", "c"}, "b"},
			expected: 1,
			wantErr:  false,
		},
		{
			name:     "element at start",
			input:    []interface{}{[]interface{}{"x", "y", "z"}, "x"},
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "element not found",
			input:    []interface{}{[]interface{}{"a", "b", "c"}, "d"},
			expected: -1,
			wantErr:  false,
		},
		{
			name:     "numeric element",
			input:    []interface{}{[]interface{}{1, 2, 3}, 2},
			expected: 1,
			wantErr:  false,
		},
		{
			name:    "invalid parameter count",
			input:   []interface{}{"list"},
			wantErr: true,
		},
		{
			name:    "first parameter not a list",
			input:   []interface{}{"not-a-list", "b"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnIndex(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnIndex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if idx, ok := result.(int); !ok || idx != tt.expected {
					t.Errorf("FnIndex() = %v, want %v", result, tt.expected)
				}
			}
		})
	}
}
