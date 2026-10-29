package template

import "testing"

func TestParameterAttributeTypeValidation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		value    interface{}
		expected string
		want     bool
	}{
		{"string", "text", "String", true}, {"wrong string", 1, "String", false},
		{"integer", uint64(3), "Integer", true}, {"integral JSON number", float64(3), "Integer", true}, {"fractional", 3.5, "Integer", false},
		{"number", float64(3.5), "Number", true}, {"wrong number", "3", "Number", false},
		{"boolean", true, "Boolean", true}, {"wrong boolean", 0, "Boolean", false},
		{"list", []interface{}{1}, "List", true}, {"wrong list", "x", "List", false},
		{"map", map[string]interface{}{"x": 1}, "Map", true}, {"string or map", map[string]interface{}{"x": 1}, "String/Map", true},
		{"wrong string or map", 1, "String/Map", false}, {"intrinsic", map[string]interface{}{"Ref": "Parameter"}, "Integer", true},
		{"unrestricted", nil, "any", true}, {"unknown expected type", nil, "FutureType", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsParamAttrTypeValid(tc.value, tc.expected); got != tc.want {
				t.Fatalf("%#v expected %s: %v", tc.value, tc.expected, got)
			}
		})
	}
}

func TestDescribeValueType(t *testing.T) {
	for _, tc := range []struct {
		value interface{}
		want  string
	}{
		{"x", "String"}, {int64(1), "Integer"}, {uint64(1), "Integer"}, {1.5, "Number"}, {true, "Boolean"},
		{[]interface{}{}, "List"}, {map[string]interface{}{}, "Map"}, {nil, "Unknown"},
	} {
		if got := DescribeValueType(tc.value); got != tc.want {
			t.Errorf("%T: got %s want %s", tc.value, got, tc.want)
		}
	}
}

func TestYAMLShortGetAttIncompleteReferences(t *testing.T) {
	pairs := collectYAMLShortTagGetAttPairs("Value: !GetAtt \nValue: !GetAtt Instance\nValue: !GetAtt Other.Id\n")
	if len(pairs) != 2 || pairs[0].resource != "Instance" || pairs[0].attribute != "" || pairs[1].resource != "Other" || pairs[1].attribute != "Id" {
		t.Fatalf("GetAtt pairs: %+v", pairs)
	}
}
