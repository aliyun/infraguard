package funcs

import (
	"testing"
)

func TestFnBase64Encode(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
		wantErr  bool
	}{
		{
			name:     "simple string",
			input:    "Hello World",
			expected: "SGVsbG8gV29ybGQ=",
			wantErr:  false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
			wantErr:  false,
		},
		{
			name:     "string with special characters",
			input:    "Hello\nWorld\t!",
			expected: "SGVsbG8KV29ybGQJIQ==",
			wantErr:  false,
		},
		{
			name:     "number",
			input:    123,
			expected: "MTIz",
			wantErr:  false,
		},
		{
			name:     "boolean",
			input:    true,
			expected: "dHJ1ZQ==",
			wantErr:  false,
		},
		{
			name:     "unicode string",
			input:    "你好世界",
			expected: "5L2g5aW95LiW55WM",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnBase64Encode(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnBase64Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnBase64Encode() = %v, want %v", result, tt.expected)
			}
		})
	}
}
