package funcs

import (
	"testing"
)

func TestFnMax(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected interface{}
		wantErr  bool
	}{
		{
			name:     "positive integers",
			input:    []interface{}{5, 10, 3},
			expected: 10,
			wantErr:  false,
		},
		{
			name:     "with negative",
			input:    []interface{}{-5, 10, -3},
			expected: 10,
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
			result, err := FnMax(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnMax() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnMax() = %v, want %v", result, tt.expected)
			}
		})
	}
}
