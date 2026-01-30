package funcs

import (
	"testing"
)

func TestFnGetJsonValue(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected interface{}
		wantErr  bool
	}{
		{
			name:     "extract string value",
			input:    []interface{}{"key", `{"key": "value", "key2": 123}`},
			expected: "value",
		},
		{
			name:     "extract number value",
			input:    []interface{}{"key2", `{"key": "value", "key2": 123}`},
			expected: float64(123), // JSON numbers are float64
		},
		{
			name:    "invalid JSON",
			input:   []interface{}{"key", "invalid json"},
			wantErr: true,
		},
		{
			name:    "key not in JSON",
			input:   []interface{}{"nonexistent", `{"key": "value"}`},
			wantErr: false, // Returns as-is (wrapped)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnGetJsonValue(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnGetJsonValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.name != "key not in JSON" {
				if result != tt.expected {
					t.Errorf("FnGetJsonValue() = %v, want %v", result, tt.expected)
				}
			}
		})
	}
}
