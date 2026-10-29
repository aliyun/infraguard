package engine

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
)

func TestParseResultsSkipsMalformedValues(t *testing.T) {
	results := rego.ResultSet{{Expressions: []*rego.ExpressionValue{
		{Value: nil},
		{Value: []interface{}{map[string]interface{}{"id": "first", "resource_id": "one"}, make(chan int), "invalid"}},
		{Value: map[string]interface{}{"id": "second", "resource_id": "two"}},
	}}}
	got, err := parseResults(results)
	if err != nil || len(got) != 2 || got[0].ID != "first" || got[1].ID != "second" {
		t.Fatalf("violations=%+v err=%v", got, err)
	}
}

func TestParseRulesCountHandlesResultShapes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		results rego.ResultSet
		want    int
	}{
		{"empty", nil, 0},
		{"list", rego.ResultSet{{Expressions: []*rego.ExpressionValue{{Value: []interface{}{"one", "two"}}}}}, 2},
		{"set map", rego.ResultSet{{Expressions: []*rego.ExpressionValue{{Value: map[string]interface{}{"one": true, "two": true, "three": true}}}}}, 3},
		{"unsupported", rego.ResultSet{{Expressions: []*rego.ExpressionValue{{Value: "unsupported"}}}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRulesCount(tc.results); got != tc.want {
				t.Fatalf("count=%d want=%d", got, tc.want)
			}
		})
	}
}

func TestEvaluateMapsAndFiltersRuleIDs(t *testing.T) {
	modules := map[string]string{
		"alpha.rego": `package infraguard.rules.test.alpha
import rego.v1
rule_meta := {"id":"alpha"}
deny contains {"id":"alpha", "resource_id":"one", "meta":{"severity":"high", "reason":"alpha"}} if { true }`,
		"beta.rego": `package infraguard.rules.test.beta
import rego.v1
rule_meta := {"id":"beta"}
deny contains {"id":"beta", "resource_id":"two", "meta":{"severity":"low", "reason":"beta"}} if { true }`,
	}
	opts := &EvalOptions{Modules: modules, IDMapping: map[string]string{"alpha": "rule:aliyun:alpha", "beta": "rule:aliyun:beta"}}
	all, err := EvaluateWithOpts(opts, map[string]interface{}{})
	if err != nil || len(all.Violations) != 2 || all.TotalRulesCount != 2 {
		t.Fatalf("all=%+v err=%v", all, err)
	}
	opts.RuleIDs = []string{"rule:aliyun:alpha"}
	selected, err := EvaluateWithOpts(opts, map[string]interface{}{})
	if err != nil || len(selected.Violations) != 1 || selected.Violations[0].ID != "rule:aliyun:alpha" || selected.TotalRulesCount != 1 {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
}
