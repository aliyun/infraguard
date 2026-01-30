package funcs

import (
	"testing"
)

func TestFnReplace(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected string
		wantErr  bool
	}{
		{
			name: "simple replacement",
			input: []interface{}{
				map[string]interface{}{"old": "new"},
				"old text",
			},
			expected: "new text",
			wantErr:  false,
		},
		{
			name: "multiple replacements",
			input: []interface{}{
				map[string]interface{}{"foo": "bar", "baz": "qux"},
				"foo and baz",
			},
			expected: "bar and qux",
			wantErr:  false,
		},
		{
			name:    "invalid parameter count",
			input:   []interface{}{map[string]interface{}{}},
			wantErr: true,
		},
		{
			name:    "non-map replacements",
			input:   []interface{}{"invalid", "text"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnReplace(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnReplace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnReplace() = %v, want %v", result, tt.expected)
			}
		})
	}
}
