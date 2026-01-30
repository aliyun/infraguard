package funcs

import (
	"testing"
)

func TestFnListMerge(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected []interface{}
		wantErr  bool
	}{
		{
			name: "merge two lists",
			input: []interface{}{
				[]interface{}{"a", "b"},
				[]interface{}{"c", "d"},
			},
			expected: []interface{}{"a", "b", "c", "d"},
			wantErr:  false,
		},
		{
			name: "merge three lists",
			input: []interface{}{
				[]interface{}{1, 2},
				[]interface{}{3},
				[]interface{}{4, 5},
			},
			expected: []interface{}{1, 2, 3, 4, 5},
			wantErr:  false,
		},
		{
			name:     "empty lists",
			input:    []interface{}{[]interface{}{}, []interface{}{}},
			expected: []interface{}{},
			wantErr:  false,
		},
		{
			name:    "non-list element",
			input:   []interface{}{[]interface{}{"a"}, "not-a-list"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnListMerge(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnListMerge() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				resultList, ok := result.([]interface{})
				if !ok {
					t.Errorf("FnListMerge() result is not a list")
					return
				}
				if len(resultList) != len(tt.expected) {
					t.Errorf("FnListMerge() length = %v, want %v", len(resultList), len(tt.expected))
					return
				}
				for i, v := range resultList {
					if v != tt.expected[i] {
						t.Errorf("FnListMerge()[%d] = %v, want %v", i, v, tt.expected[i])
					}
				}
			}
		})
	}
}
