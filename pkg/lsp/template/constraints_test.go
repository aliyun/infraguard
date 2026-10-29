package template

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/lsp/schema"
)

func TestResourceConstraintDiagnostics(t *testing.T) {
	min, max, minLen, maxLen := 2.0, 10.0, 3, 8
	sf := schema.SchemaFile{ResourceTypes: map[string]*schema.ResourceType{"ALIYUN::TEST::Thing": {Properties: map[string]*schema.Property{
		"Mode":  {Type: "String", Constraints: &schema.Constraint{AllowedValues: []interface{}{"good", "safe"}}},
		"Count": {Type: "Integer", Constraints: &schema.Constraint{MinValue: &min, MaxValue: &max}},
		"Name":  {Type: "String", Constraints: &schema.Constraint{MinLength: &minLen, MaxLength: &maxLen, AllowedPattern: "[a-z]+"}},
	}}}}
	b, err := json.Marshal(sf)
	if err != nil {
		t.Fatal(err)
	}
	registry := &schema.Registry{}
	if err := registry.LoadFromData(b); err != nil {
		t.Fatal(err)
	}
	provider := &ROSTemplateProvider{}
	for _, tc := range []struct {
		name, content string
		yaml          bool
		valid         bool
	}{
		{"invalid YAML", "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  Item:\n    Type: ALIYUN::TEST::Thing\n    Properties:\n      Mode: bad\n      Count: 100\n      Name: A\n", true, false},
		{"invalid JSON", `{"ROSTemplateFormatVersion":"2015-09-01","Resources":{"Item":{"Type":"ALIYUN::TEST::Thing","Properties":{"Mode":"bad","Count":100,"Name":"A"}}}}`, false, false},
		{"valid YAML", "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  Item:\n    Type: ALIYUN::TEST::Thing\n    Properties:\n      Mode: good\n      Count: 5\n      Name: valid\n", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := provider.Validate(ValidationContext{Content: tc.content, IsYAML: tc.yaml, Registry: registry})
			if tc.valid {
				if len(diags) != 0 {
					t.Fatalf("valid template: %+v", diags)
				}
				return
			}
			found := map[string]int{}
			for _, d := range diags {
				for _, key := range []string{"Mode", "Count", "Name"} {
					if strings.Contains(d.Message, key) {
						found[key]++
					}
				}
			}
			if found["Mode"] != 1 || found["Count"] != 1 || found["Name"] != 2 {
				t.Fatalf("constraint diagnostics: %+v", diags)
			}
		})
	}
}

func TestConstraintDocumentationBounds(t *testing.T) {
	min, max := 2.0, 10.0
	minLen, maxLen := 3, 8
	for _, tc := range []struct {
		name       string
		constraint schema.Constraint
		want       []string
	}{
		{"all", schema.Constraint{AllowedValues: []interface{}{"a", "b"}, AllowedPattern: "[a-z]+", MinValue: &min, MaxValue: &max, MinLength: &minLen, MaxLength: &maxLen}, []string{"`a`, `b`", "`[a-z]+`", "[2, 10]", "[3, 8]"}},
		{"minimum", schema.Constraint{MinValue: &min, MinLength: &minLen}, []string{"[2, ∞)", "[3, ∞)"}},
		{"maximum", schema.Constraint{MaxValue: &max, MaxLength: &maxLen}, []string{"(-∞, 10]", "[0, 8]"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := formatConstraintDoc(&tc.constraint)
			for _, want := range tc.want {
				if !strings.Contains(doc, want) {
					t.Errorf("documentation %q lacks %q", doc, want)
				}
			}
		})
	}
}

func TestNumericConstraintConversion(t *testing.T) {
	values := []interface{}{float64(7), float32(7), int(7), int8(7), int16(7), int32(7), int64(7), uint(7), uint8(7), uint16(7), uint32(7), uint64(7)}
	for _, v := range values {
		if got, ok := toFloat64Val(v); !ok || got != 7 {
			t.Errorf("%T %v: got %v, %v", v, v, got, ok)
		}
	}
	for _, v := range []interface{}{nil, "7", true} {
		if got, ok := toFloat64Val(v); ok {
			t.Errorf("%T %v unexpectedly converted to %v", v, v, got)
		}
	}
}

func TestConstraintFormattingAndUnknownTypes(t *testing.T) {
	fractional := 1.5
	if got := formatOptionalNum(&fractional); got != "1.5" {
		t.Fatalf("fractional bound: %q", got)
	}
	if !isTypeCompatible(123, "custom-provider-type") {
		t.Fatal("unknown provider type should not be rejected")
	}
	if got := findClosestMatch("instancE", map[string]bool{"Instance": true}); got != "Instance" {
		t.Fatalf("case-insensitive suggestion: %q", got)
	}
}
