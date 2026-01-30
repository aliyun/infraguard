package funcs

import (
	"testing"
)

func TestFnAnd(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected bool
		wantErr  bool
	}{
		{
			name:     "all true",
			input:    []interface{}{true, true, true},
			expected: true,
		},
		{
			name:     "one false",
			input:    []interface{}{true, false, true},
			expected: false,
		},
		{
			name:     "all false",
			input:    []interface{}{false, false, false},
			expected: false,
		},
		{
			name:     "with numbers",
			input:    []interface{}{1, 1, 1},
			expected: true,
		},
		{
			name:     "with zero",
			input:    []interface{}{1, 0, 1},
			expected: false,
		},
		{
			name:    "empty array",
			input:   []interface{}{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnAnd(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnAnd() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnAnd() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestToBool(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected bool
		wantErr  bool
	}{
		{name: "bool true", input: true, expected: true},
		{name: "bool false", input: false, expected: false},
		{name: "int non-zero", input: 42, expected: true},
		{name: "int zero", input: 0, expected: false},
		{name: "float non-zero", input: 3.14, expected: true},
		{name: "float zero", input: 0.0, expected: false},
		{name: "string true", input: "true", expected: true},
		{name: "string false", input: "false", expected: false},
		{name: "string empty", input: "", expected: false},
		{name: "string 1", input: "1", expected: true},
		{name: "string 0", input: "0", expected: false},
		{name: "invalid string", input: "maybe", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ToBool(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("toBool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("toBool() = %v, want %v", result, tt.expected)
			}
		})
	}
}
