package funcs

import (
	"reflect"
	"testing"
)

func TestFnSplit(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected []interface{}
		wantErr  bool
	}{
		{
			name: "split by comma",
			input: []interface{}{
				",",
				"a,b,c",
			},
			expected: []interface{}{"a", "b", "c"},
			wantErr:  false,
		},
		{
			name: "split by dash",
			input: []interface{}{
				"-",
				"part1-part2-part3",
			},
			expected: []interface{}{"part1", "part2", "part3"},
			wantErr:  false,
		},
		{
			name: "split by space",
			input: []interface{}{
				" ",
				"hello world test",
			},
			expected: []interface{}{"hello", "world", "test"},
			wantErr:  false,
		},
		{
			name: "split with no delimiter found",
			input: []interface{}{
				",",
				"no-comma-here",
			},
			expected: []interface{}{"no-comma-here"},
			wantErr:  false,
		},
		{
			name: "split empty string",
			input: []interface{}{
				",",
				"",
			},
			expected: []interface{}{""},
			wantErr:  false,
		},
		{
			name: "split with multiple consecutive delimiters",
			input: []interface{}{
				",",
				"a,,b,,,c",
			},
			expected: []interface{}{"a", "", "b", "", "", "c"},
			wantErr:  false,
		},
		{
			name: "split by newline",
			input: []interface{}{
				"\n",
				"line1\nline2\nline3",
			},
			expected: []interface{}{"line1", "line2", "line3"},
			wantErr:  false,
		},
		{
			name:    "invalid parameter count",
			input:   []interface{}{","},
			wantErr: true,
		},
		{
			name: "invalid delimiter type",
			input: []interface{}{
				123,
				"test",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnSplit(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnSplit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				resultList, ok := result.([]interface{})
				if !ok {
					t.Errorf("FnSplit() result is not a list, got %T", result)
					return
				}
				if !reflect.DeepEqual(resultList, tt.expected) {
					t.Errorf("FnSplit() = %v, want %v", resultList, tt.expected)
				}
			}
		})
	}
}
