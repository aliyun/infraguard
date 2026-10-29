package funcs

import (
	"errors"
	"reflect"
	"testing"
)

func TestFindInMapResolutionFailuresAndDeferredReferences(t *testing.T) {
	sentinel := errors.New("resolution failed")
	resolve := func(v interface{}, _ map[string]interface{}, _ map[string]interface{}) (interface{}, error) {
		if v == "error" {
			return nil, sentinel
		}
		return v, nil
	}
	isFunction := func(v interface{}) bool { _, ok := v.(map[string]interface{}); return ok }
	for _, tc := range []struct {
		name      string
		args      interface{}
		wantError bool
		deferred  bool
	}{
		{"not array", "invalid", true, false}, {"short array", []interface{}{"map"}, true, false},
		{"map resolution", []interface{}{"error", "key", "field"}, true, false}, {"map type", []interface{}{42, "key", "field"}, true, false},
		{"top resolution", []interface{}{"map", "error", "field"}, true, false}, {"second resolution", []interface{}{"map", "key", "error"}, true, false},
		{"top unresolved", []interface{}{"map", map[string]interface{}{"Ref": "p"}, "field"}, false, true},
		{"second unresolved", []interface{}{"map", "key", map[string]interface{}{"Ref": "p"}}, false, true},
		{"missing mappings", []interface{}{"map", "key", "field"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FnFindInMap(tc.args, nil, nil, resolve, isFunction)
			if (err != nil) != tc.wantError {
				t.Fatalf("result=%v error=%v", got, err)
			}
			if tc.deferred && !reflect.DeepEqual(got, map[string]interface{}{"Fn::FindInMap": tc.args}) {
				t.Fatalf("deferred result: %#v", got)
			}
			if (tc.name == "map resolution" || tc.name == "top resolution" || tc.name == "second resolution") && !errors.Is(err, sentinel) {
				t.Fatalf("wrapped error: %v", err)
			}
		})
	}
}

func TestGetJSONValueFailureAndDeferredCases(t *testing.T) {
	sentinel := errors.New("resolution failed")
	resolve := func(v interface{}, _ map[string]interface{}, _ map[string]interface{}) (interface{}, error) {
		if v == "error" {
			return nil, sentinel
		}
		return v, nil
	}
	isFunction := func(v interface{}) bool { _, ok := v.(map[string]interface{}); return ok }
	for _, tc := range []struct {
		name                string
		args                interface{}
		wantError, deferred bool
	}{
		{"not array", "bad", true, false}, {"wrong arity", []interface{}{"key"}, true, false},
		{"key resolution", []interface{}{"error", "{}"}, true, false}, {"key type", []interface{}{5, "{}"}, true, false},
		{"json resolution", []interface{}{"key", "error"}, true, false}, {"json type", []interface{}{"key", 5}, true, false},
		{"deferred", []interface{}{"key", map[string]interface{}{"Ref": "input"}}, false, true},
		{"missing key", []interface{}{"key", `{"other":1}`}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FnGetJsonValue(tc.args, nil, nil, resolve, isFunction)
			if (err != nil) != tc.wantError {
				t.Fatalf("result=%v error=%v", got, err)
			}
			if tc.deferred && !reflect.DeepEqual(got, map[string]interface{}{"Fn::GetJsonValue": tc.args}) {
				t.Fatalf("deferred: %#v", got)
			}
			if (tc.name == "key resolution" || tc.name == "json resolution") && !errors.Is(err, sentinel) {
				t.Fatalf("wrapped error: %v", err)
			}
		})
	}
}

func TestMergeMapToListInvalidAndDeferredCases(t *testing.T) {
	sentinel := errors.New("resolution failed")
	resolve := func(v interface{}, _ map[string]interface{}, _ map[string]interface{}) (interface{}, error) {
		if v == "error" {
			return nil, sentinel
		}
		return v, nil
	}
	isFunction := func(v interface{}) bool { _, ok := v.(map[string]interface{}); return ok }
	for _, tc := range []struct {
		name                string
		args                interface{}
		wantError, deferred bool
	}{
		{"not array", "bad", true, false}, {"first resolution", []interface{}{"error"}, true, false},
		{"first type", []interface{}{42}, true, false}, {"list type", []interface{}{[]interface{}{map[string]interface{}{"a": 1}}, 42}, true, false},
		{"list resolution", []interface{}{[]interface{}{map[string]interface{}{"a": 1}}, "error"}, true, false},
		{"item type", []interface{}{[]interface{}{42}}, true, false},
		{"first unresolved", []interface{}{map[string]interface{}{"Ref": "list"}}, false, true},
		{"second unresolved", []interface{}{[]interface{}{map[string]interface{}{"a": 1}}, map[string]interface{}{"Ref": "list"}}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FnMergeMapToList(tc.args, nil, nil, resolve, isFunction)
			if (err != nil) != tc.wantError {
				t.Fatalf("result=%v error=%v", got, err)
			}
			if tc.deferred && !reflect.DeepEqual(got, map[string]interface{}{"Fn::MergeMapToList": tc.args}) {
				t.Fatalf("deferred: %#v", got)
			}
			if (tc.name == "first resolution" || tc.name == "list resolution") && !errors.Is(err, sentinel) {
				t.Fatalf("wrapped error: %v", err)
			}
		})
	}
}
