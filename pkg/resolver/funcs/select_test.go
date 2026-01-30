package funcs

import (
	"testing"
)

func TestFnSelect(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected interface{}
		wantErr  bool
	}{
		{
			name: "select first element",
			input: []interface{}{
				0,
				[]interface{}{"a", "b", "c"},
			},
			expected: "a",
			wantErr:  false,
		},
		{
			name: "select middle element",
			input: []interface{}{
				1,
				[]interface{}{"x", "y", "z"},
			},
			expected: "y",
			wantErr:  false,
		},
		{
			name: "select last element",
			input: []interface{}{
				2,
				[]interface{}{"foo", "bar", "baz"},
			},
			expected: "baz",
			wantErr:  false,
		},
		{
			name: "select with float index",
			input: []interface{}{
				1.0,
				[]interface{}{10, 20, 30},
			},
			expected: 20,
			wantErr:  false,
		},
		{
			name: "select with string index",
			input: []interface{}{
				"1",
				[]interface{}{"first", "second", "third"},
			},
			expected: "second",
			wantErr:  false,
		},
		{
			name: "index out of bounds (negative)",
			input: []interface{}{
				-1,
				[]interface{}{"a", "b", "c"},
			},
			wantErr: true,
		},
		{
			name: "index out of bounds (too large)",
			input: []interface{}{
				5,
				[]interface{}{"a", "b", "c"},
			},
			wantErr: true,
		},
		{
			name:    "invalid parameter count",
			input:   []interface{}{0},
			wantErr: true,
		},
		{
			name: "invalid list type",
			input: []interface{}{
				0,
				"not-a-list",
			},
			wantErr: true,
		},
		{
			name: "invalid index type",
			input: []interface{}{
				"invalid",
				[]interface{}{"a", "b"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnSelect(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnSelect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnSelect() = %v, want %v", result, tt.expected)
			}
		})
	}
}
