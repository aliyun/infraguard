package funcs

import (
	"testing"
)

func TestFnFindInMap(t *testing.T) {
	// Create a template with Mappings
	template := map[string]interface{}{
		"Mappings": map[string]interface{}{
			"RegionMap": map[string]interface{}{
				"cn-hangzhou": map[string]interface{}{
					"AMI": "ami-12345",
					"AZ":  "cn-hangzhou-a",
				},
				"cn-beijing": map[string]interface{}{
					"AMI": "ami-67890",
					"AZ":  "cn-beijing-a",
				},
			},
		},
	}

	tests := []struct {
		name     string
		input    []interface{}
		expected interface{}
		isMap    bool // If true, result should be kept as Fn::FindInMap
	}{
		{
			name:     "valid lookup",
			input:    []interface{}{"RegionMap", "cn-hangzhou", "AMI"},
			expected: "ami-12345",
		},
		{
			name:     "another valid lookup",
			input:    []interface{}{"RegionMap", "cn-beijing", "AZ"},
			expected: "cn-beijing-a",
		},
		{
			name:  "map not found",
			input: []interface{}{"NonExistentMap", "cn-hangzhou", "AMI"},
			isMap: true,
		},
		{
			name:  "top key not found",
			input: []interface{}{"RegionMap", "cn-shanghai", "AMI"},
			isMap: true,
		},
		{
			name:  "second key not found",
			input: []interface{}{"RegionMap", "cn-hangzhou", "NonExistent"},
			isMap: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FnFindInMap(tt.input, nil, template, mockResolveValue, mockIsFunction)
			if err != nil {
				t.Errorf("FnFindInMap() error = %v", err)
				return
			}

			if tt.isMap {
				// Should return as-is (wrapped)
				_, ok := result.(map[string]interface{})
				if !ok {
					t.Errorf("FnFindInMap() expected to return map, got %T", result)
				}
			} else {
				if result != tt.expected {
					t.Errorf("FnFindInMap() = %v, want %v", result, tt.expected)
				}
			}
		})
	}
}
