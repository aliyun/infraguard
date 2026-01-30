package funcs

import (
	"testing"
)

func TestFnCalculate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected interface{}
		wantErr  bool
	}{
		{
			name:     "simple addition",
			input:    "1 + 2",
			expected: 3,
			wantErr:  false,
		},
		{
			name:     "operator precedence",
			input:    "1 + 2 * 3",
			expected: 7,
			wantErr:  false,
		},
		{
			name:     "power operator",
			input:    "2 ** 3",
			expected: 8,
			wantErr:  false,
		},
		{
			name:     "floor division",
			input:    "7 // 2",
			expected: 3,
			wantErr:  false,
		},
		{
			name:     "modulo",
			input:    "7 % 3",
			expected: 1,
			wantErr:  false,
		},
		{
			name:     "parentheses",
			input:    "(10 + 5) * 2",
			expected: 30,
			wantErr:  false,
		},
		{
			name:     "complex expression",
			input:    "(10 + 5) * 2 ** 2",
			expected: 60,
			wantErr:  false,
		},
		{
			name:     "negative numbers",
			input:    "-5 + 10",
			expected: 5,
			wantErr:  false,
		},
		{
			name:     "float division",
			input:    "10 / 4",
			expected: 2.5,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnCalculate(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnCalculate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnCalculate() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseExpression(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected float64
		wantErr  bool
	}{
		{
			name:     "precedence test",
			expr:     "2 + 3 * 4",
			expected: 14,
			wantErr:  false,
		},
		{
			name:     "power is right associative",
			expr:     "2 ** 3 ** 2",
			expected: 512, // 2 ** (3 ** 2) = 2 ** 9 = 512
			wantErr:  false,
		},
		{
			name:     "mixed operators",
			expr:     "10 + 20 / 5 - 3 * 2",
			expected: 8, // 10 + 4 - 6 = 8
			wantErr:  false,
		},
		{
			name:    "division by zero",
			expr:    "10 / 0",
			wantErr: true,
		},
		{
			name:    "missing closing paren",
			expr:    "(10 + 5",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseExpression(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseExpression() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("parseExpression() = %v, want %v", result, tt.expected)
			}
		})
	}
}
