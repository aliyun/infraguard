package resolver

import (
	"strings"
	"testing"
)

func TestConditionResolutionRejectsInvalidAndUnresolvedExpressions(t *testing.T) {
	for _, tc := range []struct {
		name string
		expr interface{}
		want string
	}{
		{"invalid function", map[string]interface{}{"Fn::Equals": []interface{}{1}}, "error resolving condition"},
		{"unknown reference", map[string]interface{}{"Ref": "Missing"}, "cannot be statically evaluated"},
		{"not boolean", "not-a-boolean", "cannot convert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveConditions(map[string]interface{}{"Conditions": map[string]interface{}{"Check": tc.expr}}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "Check") {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if got, err := resolveConditions(map[string]interface{}{}, nil); err != nil || len(got) != 0 {
		t.Fatalf("empty conditions=%v err=%v", got, err)
	}
}

func TestConditionGraphFindsNestedDependencies(t *testing.T) {
	conditions := map[string]interface{}{
		"Base":   true,
		"Other":  false,
		"Nested": map[string]interface{}{"Fn::If": []interface{}{"Base", map[string]interface{}{"Condition": "Other"}, false}},
	}
	graph := buildConditionGraph(conditions)
	sorted, err := topologicalSort(graph)
	if err != nil {
		t.Fatal(err)
	}
	positions := map[string]int{}
	for i, name := range sorted {
		positions[name] = i
	}
	if len(sorted) != 3 || positions["Base"] >= positions["Nested"] || positions["Other"] >= positions["Nested"] {
		t.Fatalf("order=%v graph=%+v", sorted, graph)
	}
}

func TestConditionalEntriesWithMissingOrMalformedConditions(t *testing.T) {
	for _, apply := range []struct {
		name string
		fn   func(map[string]interface{}, map[string]bool)
	}{{"Resources", applyConditionsToResources}, {"Outputs", applyConditionsToOutputs}} {
		entries := map[string]interface{}{
			"malformed":    "value",
			"badCondition": map[string]interface{}{"Condition": 3},
			"unknown":      map[string]interface{}{"Condition": "Missing"},
			"false":        map[string]interface{}{"Condition": "Off"},
			"true":         map[string]interface{}{"Condition": "On"},
		}
		apply.fn(map[string]interface{}{apply.name: entries}, map[string]bool{"Off": false, "On": true})
		if _, ok := entries["unknown"]; ok {
			t.Errorf("%s unknown condition remained", apply.name)
		}
		if _, ok := entries["false"]; ok {
			t.Errorf("%s false condition remained", apply.name)
		}
		for _, key := range []string{"true", "malformed", "badCondition"} {
			if _, ok := entries[key]; !ok {
				t.Errorf("%s unexpectedly removed %s", apply.name, key)
			}
		}
	}
	refs := findConditionReferences(map[string]interface{}{"one": map[string]interface{}{"Condition": "Enabled"}, "two": []interface{}{"Other"}}, map[string]interface{}{"Enabled": true, "Other": false})
	if len(refs) != 2 {
		t.Fatalf("nested map references: %v", refs)
	}
}

func TestResolveConditionsPreservesUnresolvableConditions(t *testing.T) {
	input := map[string]interface{}{"Conditions": map[string]interface{}{"Broken": map[string]interface{}{"Fn::Equals": []interface{}{1}}}, "Parameters": map[string]interface{}{}, "Resources": map[string]interface{}{}}
	output := ResolveConditionsAndFunctions(input, map[string]interface{}{"Provided": "value"})
	if _, ok := output["Conditions"]; !ok {
		t.Fatal("unresolvable conditions removed")
	}
}
