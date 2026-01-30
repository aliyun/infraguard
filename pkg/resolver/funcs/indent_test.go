package funcs

import (
	"testing"
)

func TestFnIndent(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected string
		wantErr  bool
	}{
		{
			name:     "indent 2 spaces",
			input:    []interface{}{2, "line1\nline2"},
			expected: "  line1\n  line2",
			wantErr:  false,
		},
		{
			name:     "indent 4 spaces",
			input:    []interface{}{4, "hello"},
			expected: "    hello",
			wantErr:  false,
		},
		{
			name:    "invalid parameter count",
			input:   []interface{}{2},
			wantErr: true,
		},
		{
			name:    "non-numeric indent",
			input:   []interface{}{"two", "text"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnIndent(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnIndent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnIndent() = %q, want %q", result, tt.expected)
			}
		})
	}
}
