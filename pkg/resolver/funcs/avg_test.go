package funcs

import (
	"testing"
)

func TestFnAvg(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected interface{}
		wantErr  bool
	}{
		{
			name:     "three integers",
			input:    []interface{}{10, 20, 30},
			expected: 20,
			wantErr:  false,
		},
		{
			name:     "two floats",
			input:    []interface{}{10.0, 20.0},
			expected: 15,
			wantErr:  false,
		},
		{
			name:     "single number",
			input:    []interface{}{42},
			expected: 42,
			wantErr:  false,
		},
		{
			name:    "empty array",
			input:   []interface{}{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnAvg(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnAvg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnAvg() = %v, want %v", result, tt.expected)
			}
		})
	}
}
