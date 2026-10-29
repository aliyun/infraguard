package funcs

import (
	"errors"
	"reflect"
	"testing"
)

func TestCalculateExpressionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		expr    string
		want    float64
		invalid bool
	}{
		{"+(-2) + .5", -1.5, false}, {"-7 // 2", -4, false}, {"2 ** 3 ** 2", 512, false},
		{"", 0, true}, {"-", 0, true}, {"2+", 0, true}, {"2**", 0, true}, {"(2+)", 0, true},
		{"2//0", 0, true}, {"2%0", 0, true}, {"1.2.3", 0, true}, {"2 trailing", 0, true},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			got, err := parseExpression(tc.expr)
			if (err != nil) != tc.invalid || (!tc.invalid && got != tc.want) {
				t.Fatalf("got=%v err=%v want=%v", got, err, tc.want)
			}
		})
	}
}

func TestCalculateDeferredAndResolutionErrors(t *testing.T) {
	sentinel := errors.New("resolution failed")
	resolve := func(v interface{}, _ map[string]interface{}, _ map[string]interface{}) (interface{}, error) {
		if v == "error" {
			return nil, sentinel
		}
		return v, nil
	}
	isFunction := func(v interface{}) bool { _, ok := v.(map[string]interface{}); return ok }
	for _, value := range []interface{}{map[string]interface{}{"Ref": "expression"}, "2/0", "unknown + 2"} {
		got, err := FnCalculate(value, nil, nil, resolve, isFunction)
		if err != nil || !reflect.DeepEqual(got, map[string]interface{}{"Fn::Calculate": value}) {
			t.Errorf("%v: got=%#v err=%v", value, got, err)
		}
	}
	if _, err := FnCalculate("error", nil, nil, resolve, isFunction); !errors.Is(err, sentinel) {
		t.Fatalf("resolution error: %v", err)
	}
	if _, err := FnCalculate(123, nil, nil, resolve, isFunction); err == nil {
		t.Fatal("non-string expression accepted")
	}
}
