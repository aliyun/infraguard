package funcs

import (
	"testing"
)

func TestFnLength(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected int
		wantErr  bool
	}{
		{
			name:     "string length",
			input:    []interface{}{"hello"},
			expected: 5,
			wantErr:  false,
		},
		{
			name:     "list length",
			input:    []interface{}{[]interface{}{1, 2, 3}},
			expected: 3,
			wantErr:  false,
		},
		{
			name:     "empty string",
			input:    []interface{}{""},
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "empty list",
			input:    []interface{}{[]interface{}{}},
			expected: 0,
			wantErr:  false,
		},
		{
			name:    "invalid parameter count",
			input:   []interface{}{},
			wantErr: true,
		},
		{
			name:    "invalid type",
			input:   []interface{}{123},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnLength(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if length, ok := result.(int); !ok || length != tt.expected {
					t.Errorf("FnLength() = %v, want %v", result, tt.expected)
				}
			}
		})
	}
}
