package funcs

import (
	"testing"
)

func TestFnAdd(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected interface{}
		wantErr  bool
	}{
		{
			name:     "two integers",
			input:    []interface{}{10, 20},
			expected: 30,
			wantErr:  false,
		},
		{
			name:     "three integers",
			input:    []interface{}{10, 20, 30},
			expected: 60,
			wantErr:  false,
		},
		{
			name:     "with float",
			input:    []interface{}{10.5, 20.3},
			expected: 30.8,
			wantErr:  false,
		},
		{
			name:    "less than 2 numbers",
			input:   []interface{}{10},
			wantErr: true,
		},
		{
			name:    "non-numeric value",
			input:   []interface{}{10, "string"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnAdd(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnAdd() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnAdd() = %v, want %v", result, tt.expected)
			}
		})
	}
}
