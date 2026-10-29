package funcs

import (
	"errors"
	"reflect"
	"testing"
)

type intrinsicFunc func(interface{}, map[string]interface{}, map[string]interface{}, func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), func(interface{}) bool) (interface{}, error)

func TestIntrinsicFunctionsPropagateErrorsAndPreserveDeferredValues(t *testing.T) {
	unresolved := map[string]interface{}{"Ref": "unavailable"}
	for _, tc := range []struct {
		name  string
		fn    intrinsicFunc
		value interface{}
	}{
		{"Fn::And", FnAnd, []interface{}{unresolved}}, {"Fn::Or", FnOr, []interface{}{unresolved}},
		{"Fn::Not", FnNot, []interface{}{unresolved}}, {"Fn::Equals", FnEquals, []interface{}{unresolved, "other"}},
		{"Fn::If", FnIf, []interface{}{unresolved, "yes", "no"}}, {"Fn::Any", FnAny, []interface{}{unresolved}},
		{"Fn::Contains", FnContains, []interface{}{unresolved, "item"}}, {"Fn::Join", FnJoin, []interface{}{unresolved, []interface{}{"x"}}},
		{"Fn::Split", FnSplit, []interface{}{unresolved, "x,y"}}, {"Fn::Sub", FnSub, []interface{}{unresolved}},
		{"Fn::Avg", FnAvg, []interface{}{unresolved}}, {"Fn::Max", FnMax, []interface{}{unresolved}}, {"Fn::Min", FnMin, []interface{}{unresolved}},
		{"Fn::Str", FnStr, unresolved}, {"Fn::Base64Encode", FnBase64Encode, unresolved},
		{"Fn::Base64Decode", FnBase64Decode, unresolved}, {"Fn::EachMemberIn", FnEachMemberIn, []interface{}{unresolved, []interface{}{"x"}}},
		{"Fn::Index", FnIndex, []interface{}{unresolved, "x"}}, {"Fn::ListMerge", FnListMerge, []interface{}{unresolved}},
		{"Fn::Select", FnSelect, []interface{}{unresolved, []interface{}{"x"}}}, {"Fn::SelectMapList", FnSelectMapList, []interface{}{"key", unresolved}},
		{"Fn::Length", FnLength, []interface{}{unresolved}}, {"Fn::Indent", FnIndent, []interface{}{2, unresolved}},
		{"Fn::Replace", FnReplace, []interface{}{map[string]interface{}{"a": "b"}, unresolved}}, {"Fn::MatchPattern", FnMatchPattern, []interface{}{"a", unresolved}},
		{"Fn::Add", FnAdd, []interface{}{unresolved, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isFunction := func(v interface{}) bool { m, ok := v.(map[string]interface{}); return ok && m["Ref"] != nil }
			identity := func(v interface{}, _ map[string]interface{}, _ map[string]interface{}) (interface{}, error) {
				return v, nil
			}
			got, err := tc.fn(tc.value, nil, nil, identity, isFunction)
			if err != nil || !reflect.DeepEqual(got, map[string]interface{}{tc.name: tc.value}) {
				t.Fatalf("deferred result=%#v err=%v", got, err)
			}
			sentinel := errors.New("resolution failed")
			failed := func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error) {
				return nil, sentinel
			}
			if _, err := tc.fn(tc.value, nil, nil, failed, isFunction); !errors.Is(err, sentinel) {
				t.Fatalf("wrapped error=%v", err)
			}
		})
	}
}

func TestIntrinsicFunctionsRejectInvalidArguments(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fn    intrinsicFunc
		value interface{}
	}{
		{"Fn::And", FnAnd, []interface{}{}}, {"Fn::Or", FnOr, []interface{}{}},
		{"Fn::Not", FnNot, []interface{}{true, false}}, {"Fn::Equals", FnEquals, []interface{}{1}},
		{"Fn::If", FnIf, []interface{}{true, "yes"}}, {"Fn::Any", FnAny, []interface{}{42}},
		{"Fn::Contains", FnContains, []interface{}{42, "item"}}, {"Fn::Join", FnJoin, []interface{}{",", 42}},
		{"Fn::Split", FnSplit, []interface{}{42, "a,b"}}, {"Fn::Sub", FnSub, []interface{}{}},
		{"Fn::Avg", FnAvg, []interface{}{}}, {"Fn::Max", FnMax, []interface{}{}}, {"Fn::Min", FnMin, []interface{}{}},
		{"Fn::EachMemberIn", FnEachMemberIn, []interface{}{1}}, {"Fn::Index", FnIndex, []interface{}{1}},
		{"Fn::ListMerge", FnListMerge, 1}, {"Fn::Select", FnSelect, []interface{}{1}},
		{"Fn::SelectMapList", FnSelectMapList, []interface{}{1}}, {"Fn::Length", FnLength, []interface{}{}},
		{"Fn::Indent", FnIndent, []interface{}{1}}, {"Fn::Replace", FnReplace, []interface{}{1}},
		{"Fn::MatchPattern", FnMatchPattern, []interface{}{1}}, {"Fn::Add", FnAdd, []interface{}{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := func(v interface{}, _ map[string]interface{}, _ map[string]interface{}) (interface{}, error) {
				return v, nil
			}
			if _, err := tc.fn(tc.value, nil, nil, identity, func(interface{}) bool { return false }); err == nil {
				t.Fatalf("invalid argument %#v accepted", tc.value)
			}
		})
	}
}

func TestLogicalAndNumericFunctionsRejectIncompatibleValues(t *testing.T) {
	identity := func(v interface{}, _ map[string]interface{}, _ map[string]interface{}) (interface{}, error) {
		return v, nil
	}
	for _, tc := range []struct {
		name  string
		fn    intrinsicFunc
		value interface{}
	}{
		{"And", FnAnd, []interface{}{"not-bool"}}, {"Or", FnOr, []interface{}{"not-bool"}},
		{"Not", FnNot, []interface{}{"not-bool"}}, {"Any", FnAny, []interface{}{[]interface{}{"not-bool"}}},
		{"Avg", FnAvg, []interface{}{"not-number"}}, {"Max", FnMax, []interface{}{"not-number"}},
		{"Min", FnMin, []interface{}{"not-number"}}, {"Add", FnAdd, []interface{}{1, "not-number"}},
		{"If", FnIf, []interface{}{struct{}{}, "yes", "no"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.fn(tc.value, nil, nil, identity, func(interface{}) bool { return false }); err == nil {
				t.Fatalf("incompatible value %#v accepted", tc.value)
			}
		})
	}
}

func TestIfResolvesOnlySelectedBranch(t *testing.T) {
	sentinel := errors.New("selected branch failed")
	calls := []interface{}{}
	resolve := func(v interface{}, _ map[string]interface{}, _ map[string]interface{}) (interface{}, error) {
		calls = append(calls, v)
		if v == "fail" {
			return nil, sentinel
		}
		return v, nil
	}
	isFunction := func(interface{}) bool { return false }
	for _, tc := range []struct {
		name           string
		args           []interface{}
		params         map[string]interface{}
		want           interface{}
		fail, deferred bool
	}{
		{"true skips false", []interface{}{true, "yes", "fail"}, nil, "yes", false, false},
		{"false skips true", []interface{}{false, "fail", "no"}, nil, "no", false, false},
		{"named condition", []interface{}{"Enabled", "yes", "no"}, map[string]interface{}{"Enabled": "true"}, "yes", false, false},
		{"unknown condition", []interface{}{"Missing", "yes", "no"}, nil, nil, false, true},
		{"selected error", []interface{}{false, "yes", "fail"}, nil, nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls = nil
			got, err := FnIf(tc.args, tc.params, nil, resolve, isFunction)
			if tc.fail {
				if !errors.Is(err, sentinel) {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.deferred {
				if !reflect.DeepEqual(got, map[string]interface{}{"Fn::If": tc.args}) || len(calls) != 1 {
					t.Fatalf("deferred=%#v calls=%v", got, calls)
				}
				return
			}
			if got != tc.want || len(calls) != 2 {
				t.Fatalf("result=%v calls=%v", got, calls)
			}
		})
	}
}

func TestSubstitutionPropagatesVariableResolutionErrors(t *testing.T) {
	sentinel := errors.New("variable resolution failed")
	resolve := func(v interface{}, _ map[string]interface{}, _ map[string]interface{}) (interface{}, error) {
		if s, ok := v.(string); ok && s == "fail" {
			return nil, sentinel
		}
		return v, nil
	}
	isFunction := func(v interface{}) bool { m, ok := v.(map[string]interface{}); return ok && m["Ref"] != nil }
	for _, value := range []interface{}{
		[]interface{}{"template", "fail"},
		[]interface{}{"${Name}", map[string]interface{}{"Name": "fail"}},
	} {
		if _, err := FnSub(value, nil, nil, resolve, isFunction); !errors.Is(err, sentinel) {
			t.Errorf("input=%#v error=%v", value, err)
		}
	}
	if _, err := FnSub([]interface{}{42}, nil, nil, resolve, isFunction); err == nil {
		t.Fatal("non-string template accepted")
	}
	unresolved := map[string]interface{}{"Ref": "vars"}
	input := []interface{}{"${Name}", unresolved}
	got, err := FnSub(input, nil, nil, resolve, isFunction)
	if err != nil || !reflect.DeepEqual(got, map[string]interface{}{"Fn::Sub": input}) {
		t.Fatalf("deferred=%#v err=%v", got, err)
	}
}

func TestIntrinsicFunctionsPropagateLaterArgumentErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fn     intrinsicFunc
		value  interface{}
		failAt int
	}{
		{"Equals", FnEquals, []interface{}{1, 2}, 2}, {"Contains", FnContains, []interface{}{[]interface{}{1}, 1}, 2},
		{"EachMemberIn", FnEachMemberIn, []interface{}{[]interface{}{1}, []interface{}{1}}, 2},
		{"Index", FnIndex, []interface{}{[]interface{}{1}, 1}, 2}, {"Join parts", FnJoin, []interface{}{",", []interface{}{"x"}}, 2},
		{"Join item", FnJoin, []interface{}{",", []interface{}{"x"}}, 3}, {"Split", FnSplit, []interface{}{",", "x"}, 2},
		{"Select", FnSelect, []interface{}{0, []interface{}{"x"}}, 2}, {"SelectMapList", FnSelectMapList, []interface{}{"key", []interface{}{}}, 2},
		{"Indent", FnIndent, []interface{}{2, "text"}, 2}, {"Replace", FnReplace, []interface{}{map[string]interface{}{"a": "b"}, "text"}, 2},
		{"MatchPattern", FnMatchPattern, []interface{}{"a", "text"}, 2}, {"Sub variables", FnSub, []interface{}{"text", map[string]interface{}{}}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sentinel := errors.New("later argument failed")
			calls := 0
			resolve := func(v interface{}, _ map[string]interface{}, _ map[string]interface{}) (interface{}, error) {
				calls++
				if calls == tc.failAt {
					return nil, sentinel
				}
				return v, nil
			}
			if _, err := tc.fn(tc.value, nil, nil, resolve, func(interface{}) bool { return false }); !errors.Is(err, sentinel) {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestJoinDefersUnresolvedParts(t *testing.T) {
	unresolved := map[string]interface{}{"Ref": "Missing"}
	identity := func(v interface{}, _ map[string]interface{}, _ map[string]interface{}) (interface{}, error) {
		return v, nil
	}
	isFunction := func(v interface{}) bool { m, ok := v.(map[string]interface{}); return ok && m["Ref"] != nil }
	for _, args := range [][]interface{}{{",", unresolved}, {",", []interface{}{"first", unresolved}}} {
		got, err := FnJoin(args, nil, nil, identity, isFunction)
		if err != nil || !reflect.DeepEqual(got, map[string]interface{}{"Fn::Join": args}) {
			t.Fatalf("unresolved join: %#v %v", got, err)
		}
	}
	if _, err := FnSub(42, nil, nil, identity, isFunction); err == nil {
		t.Fatal("Fn::Sub accepted a number")
	}
}
