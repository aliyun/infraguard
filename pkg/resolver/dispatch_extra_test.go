package resolver

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestResolveFunctionsDispatchesStaticIntrinsics(t *testing.T) {
	for _, tc := range []struct {
		name      string
		arg, want interface{}
	}{
		{"Fn::Add", []interface{}{map[string]interface{}{"Ref": "N"}, 3}, 5},
		{"Fn::Avg", []interface{}{2, 4}, 3}, {"Fn::Max", []interface{}{2, 7, 4}, 7}, {"Fn::Min", []interface{}{2, 7, 4}, 2},
		{"Fn::Calculate", "(2+3)*4", 20}, {"Fn::Not", []interface{}{true}, false},
		{"Fn::Contains", []interface{}{[]interface{}{"a", "b"}, "b"}, true},
		{"Fn::Any", []interface{}{[]interface{}{false, true}}, true},
		{"Fn::EachMemberIn", []interface{}{[]interface{}{"a"}, []interface{}{"a", "b"}}, true},
		{"Fn::MatchPattern", []interface{}{`^a`, "abc"}, true},
		{"Fn::Unsupported", "value", map[string]interface{}{"Fn::Unsupported": "value"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]interface{}{"Value": map[string]interface{}{tc.name: tc.arg}}
			before, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			got := ResolveFunctions(input, map[string]interface{}{"N": 2})
			if !reflect.DeepEqual(got["Value"], tc.want) {
				t.Fatalf("value=%#v want=%#v", got["Value"], tc.want)
			}
			after, err := json.Marshal(input)
			if err != nil || string(after) != string(before) {
				t.Fatalf("input mutated: %s (before %s, error %v)", after, before, err)
			}
		})
	}
}
