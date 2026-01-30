package funcs

import (
	"testing"
)

func TestFnMatchPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected bool
		wantErr  bool
	}{
		{
			name:     "matches pattern",
			input:    []interface{}{"^hello.*", "hello world"},
			expected: true,
		},
		{
			name:     "does not match",
			input:    []interface{}{"^hello.*", "goodbye world"},
			expected: false,
		},
		{
			name:     "case sensitive",
			input:    []interface{}{"^Hello", "hello"},
			expected: false,
		},
		{
			name:    "invalid regex",
			input:   []interface{}{"[invalid", "test"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnMatchPattern(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnMatchPattern() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("FnMatchPattern() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Benchmark for regex caching
func BenchmarkFnMatchPattern(b *testing.B) {
	input := []interface{}{"^hello.*", "hello world"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = FnMatchPattern(input, nil, nil, mockResolveValue, mockIsFunction)
	}
}

func BenchmarkFnMatchPattern_DifferentPatterns(b *testing.B) {
	patterns := [][]interface{}{
		{"^hello.*", "hello world"},
		{"^test.*", "test string"},
		{"[0-9]+", "12345"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := patterns[i%len(patterns)]
		_, _ = FnMatchPattern(input, nil, nil, mockResolveValue, mockIsFunction)
	}
}
