package funcs

import (
	"testing"
)

func TestFnJoin(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected string
		wantErr  bool
	}{
		{
			name: "simple join",
			input: []interface{}{
				",",
				[]interface{}{"a", "b", "c"},
			},
			expected: "a,b,c",
			wantErr:  false,
		},
		{
			name: "join with dash",
			input: []interface{}{
				"-",
				[]interface{}{"part1", "part2", "part3"},
			},
			expected: "part1-part2-part3",
			wantErr:  false,
		},
		{
			name: "join with empty string",
			input: []interface{}{
				"",
				[]interface{}{"hello", "world"},
			},
			expected: "helloworld",
			wantErr:  false,
		},
		{
			name: "join with single element",
			input: []interface{}{
				",",
				[]interface{}{"single"},
			},
			expected: "single",
			wantErr:  false,
		},
		{
			name: "join with numbers",
			input: []interface{}{
				"-",
				[]interface{}{1, 2, 3},
			},
			expected: "1-2-3",
			wantErr:  false,
		},
		{
			name:    "invalid parameter count",
			input:   []interface{}{","},
			wantErr: true,
		},
		{
			name: "invalid parts type",
			input: []interface{}{
				",",
				"not-a-list",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnJoin(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnJoin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnJoin() = %v, want %v", result, tt.expected)
			}
		})
	}
}
