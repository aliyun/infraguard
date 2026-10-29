package ros

import (
	"reflect"
	"testing"
)

func TestResolveParameterTypes(t *testing.T) {
	cases := []struct {
		name, kind  string
		input, want interface{}
		fail        bool
	}{
		{"string", "String", 123, "123", false},
		{"number string", "Number", "12.5", float64(12.5), false},
		{"number native", "Number", int64(7), int64(7), false},
		{"number invalid", "Number", "abc", nil, true},
		{"number wrong type", "Number", true, nil, true},
		{"boolean string", "Boolean", "TRUE", true, false},
		{"boolean native", "Boolean", false, false, false},
		{"boolean invalid", "Boolean", "yes", nil, true},
		{"boolean wrong type", "Boolean", 1, nil, true},
		{"list string", "CommaDelimitedList", "a, b", []interface{}{"a", "b"}, false},
		{"list native", "CommaDelimitedList", []interface{}{1, 2}, []interface{}{1, 2}, false},
		{"list invalid", "CommaDelimitedList", 1, nil, true},
		{"JSON string", "Json", `{"x":1}`, map[string]interface{}{"x": float64(1)}, false},
		{"JSON native", "Json", map[string]interface{}{"x": 1}, map[string]interface{}{"x": 1}, false},
		{"JSON invalid", "Json", "{", nil, true},
		{"optional nil", "String", nil, nil, false},
		{"unknown type", "Custom", 123, 123, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := map[string]interface{}{"Type": tc.kind, "Default": "not-used"}
			template := map[string]interface{}{"Parameters": map[string]interface{}{"P": original}}
			got, err := ResolveParameters(template, map[string]interface{}{"P": tc.input})
			if (err != nil) != tc.fail {
				t.Fatalf("error: %v", err)
			}
			if tc.fail {
				return
			}
			resolved := got["Parameters"].(map[string]interface{})["P"].(map[string]interface{})
			if !reflect.DeepEqual(resolved["ResolvedValue"], tc.want) {
				t.Fatalf("resolved %#v, want %#v", resolved["ResolvedValue"], tc.want)
			}
			if _, changed := original["ResolvedValue"]; changed {
				t.Fatal("mutated original definition")
			}
		})
	}
	if err := ValidateInputParameters(map[string]interface{}{}, map[string]interface{}{"unexpected": 1}); err == nil {
		t.Fatal("input without parameter definition accepted")
	}
}
