package funcs

import (
	"testing"
)

func TestFnSelectMapList(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected []interface{}
		wantErr  bool
	}{
		{
			name: "extract key from maps",
			input: []interface{}{
				"key",
				[]interface{}{
					map[string]interface{}{"key": "v1"},
					map[string]interface{}{"key": "v2"},
				},
			},
			expected: []interface{}{"v1", "v2"},
			wantErr:  false,
		},
		{
			name: "missing key in some maps",
			input: []interface{}{
				"key",
				[]interface{}{
					map[string]interface{}{"key": "v1"},
					map[string]interface{}{"other": "v2"},
				},
			},
			expected: []interface{}{"v1", nil},
			wantErr:  false,
		},
		{
			name:    "invalid parameter count",
			input:   []interface{}{"key"},
			wantErr: true,
		},
		{
			name:    "key not a string",
			input:   []interface{}{123, []interface{}{}},
			wantErr: true,
		},
		{
			name:    "second parameter not a list",
			input:   []interface{}{"key", "not-a-list"},
			wantErr: true,
		},
		{
			name: "list contains non-map",
			input: []interface{}{
				"key",
				[]interface{}{
					map[string]interface{}{"key": "v1"},
					"not-a-map",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnSelectMapList(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnSelectMapList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				resultList, ok := result.([]interface{})
				if !ok {
					t.Errorf("FnSelectMapList() result is not a list")
					return
				}
				if len(resultList) != len(tt.expected) {
					t.Errorf("FnSelectMapList() length = %v, want %v", len(resultList), len(tt.expected))
					return
				}
				for i, v := range resultList {
					if v != tt.expected[i] {
						t.Errorf("FnSelectMapList()[%d] = %v, want %v", i, v, tt.expected[i])
					}
				}
			}
		})
	}
}
