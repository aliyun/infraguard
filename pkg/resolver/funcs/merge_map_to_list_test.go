package funcs

import (
	"testing"
)

func TestFnMergeMapToList(t *testing.T) {
	tests := []struct {
		name     string
		input    []interface{}
		expected []interface{}
		wantErr  bool
	}{
		{
			name: "merge two map lists",
			input: []interface{}{
				[]interface{}{
					map[string]interface{}{"k1": "v1"},
					map[string]interface{}{"k1": "v3"},
				},
				[]interface{}{
					map[string]interface{}{"k2": "v2"},
					map[string]interface{}{"k2": "v4"},
				},
			},
			expected: []interface{}{
				map[string]interface{}{"k1": "v1", "k2": "v2"},
				map[string]interface{}{"k1": "v3", "k2": "v4"},
			},
		},
		{
			name: "merge three map lists",
			input: []interface{}{
				[]interface{}{
					map[string]interface{}{"a": 1},
					map[string]interface{}{"a": 2},
				},
				[]interface{}{
					map[string]interface{}{"b": 3},
					map[string]interface{}{"b": 4},
				},
				[]interface{}{
					map[string]interface{}{"c": 5},
					map[string]interface{}{"c": 6},
				},
			},
			expected: []interface{}{
				map[string]interface{}{"a": 1, "b": 3, "c": 5},
				map[string]interface{}{"a": 2, "b": 4, "c": 6},
			},
		},
		{
			name: "unequal list lengths",
			input: []interface{}{
				[]interface{}{
					map[string]interface{}{"k1": "v1"},
				},
				[]interface{}{
					map[string]interface{}{"k2": "v2"},
					map[string]interface{}{"k2": "v3"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnMergeMapToList(tt.input, nil, nil, mockResolveValue, mockIsFunction)
			if (err != nil) != tt.wantErr {
				t.Errorf("FnMergeMapToList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				resultList, ok := result.([]interface{})
				if !ok {
					t.Fatalf("FnMergeMapToList() result is not a list")
				}

				if len(resultList) != len(tt.expected) {
					t.Errorf("FnMergeMapToList() length = %v, want %v", len(resultList), len(tt.expected))
					return
				}

				for i, expectedItem := range tt.expected {
					expectedMap := expectedItem.(map[string]interface{})
					resultMap, ok := resultList[i].(map[string]interface{})
					if !ok {
						t.Errorf("FnMergeMapToList()[%d] is not a map", i)
						continue
					}

					for k, v := range expectedMap {
						if resultMap[k] != v {
							t.Errorf("FnMergeMapToList()[%d][%q] = %v, want %v", i, k, resultMap[k], v)
						}
					}
				}
			}
		})
	}
}
