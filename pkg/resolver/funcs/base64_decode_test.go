package funcs

import (
	"testing"
)

func TestFnBase64Decode(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
		wantErr  bool
	}{
		{
			name:     "valid base64",
			input:    "SGVsbG8gV29ybGQ=",
			expected: "Hello World",
			wantErr:  false,
		},
		{
			name:    "invalid base64",
			input:   "invalid!!!",
			wantErr: true,
		},
		{
			name:    "not a string",
			input:   123,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnBase64Decode(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnBase64Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnBase64Decode() = %v, want %v", result, tt.expected)
			}
		})
	}
}
