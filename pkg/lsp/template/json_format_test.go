package template

import (
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/lsp/protocol"
)

func TestJSONTypeValueCompletionEdits(t *testing.T) {
	handler := &jsonFormatHandler{}
	for _, tc := range []struct{ line, want string }{
		{`  "Type": "Str",`, `String",`}, {`  "Type": "Str"`, `String"`}, {`  "Type": "Str`, `String`},
	} {
		start := strings.Index(tc.line, "Str")
		ctx := CompletionContext{Content: tc.line, Line: 0, Col: len(tc.line)}
		analysis := &AnalysisContext{ValueStartCol: start}
		var param, local protocol.CompletionItem
		handler.BuildParameterTypeValueSnippet(&param, "String", analysis, ctx)
		handler.BuildLocalsTypeValueSnippet(&local, "String", analysis, ctx)
		for _, item := range []protocol.CompletionItem{param, local} {
			if item.TextEdit == nil || item.TextEdit.NewText != tc.want || item.TextEdit.Range.Start.Character != start {
				t.Fatalf("%q: %+v", tc.line, item)
			}
		}
	}
}

func TestJSONFormatLocationsAndExtraction(t *testing.T) {
	content := "{\n  \"Mappings\": {\n    \"Regions\": {}\n  },\n  \"Locals\": {\n    \"Cache\": {}\n  },\n  \"Resources\": {\n    \"Instance\": {\n      \"Type\": \"ALIYUN::ECS::Instance\"\n    }\n  }\n}"
	h := &jsonFormatHandler{}
	if got := h.FindKeyLine(content, "Resources"); got != 7 {
		t.Fatalf("resource key line %d", got)
	}
	for _, tc := range []struct {
		name string
		got  protocol.Range
		line int
	}{
		{"mapping", h.FindMappingsRange(content, "Regions"), 2}, {"local", h.FindLocalsRange(content, "Cache"), 5}, {"type", h.FindResourceTypeRange(content, "Instance"), 9},
	} {
		if tc.got.Start.Line != tc.line || tc.got.End.Character <= tc.got.Start.Character {
			t.Errorf("%s range: %+v", tc.name, tc.got)
		}
	}
	if got := h.ExtractKeyFromLine(`"Fn::GetAtt": ["Thing", "Id"]`); got != "Fn::GetAtt" {
		t.Fatalf("key: %q", got)
	}
	if got := h.ExtractValueFromLine(`"Type": "ALIYUN::ECS::Instance",`); got != "ALIYUN::ECS::Instance" {
		t.Fatalf("value: %q", got)
	}
	if got := h.ExtractValueFromLine(`"Type"`); got != "" {
		t.Fatalf("invalid value: %q", got)
	}
}

func TestJSONParameterCompletionContexts(t *testing.T) {
	content := "{\n  \"Parameters\": {\n    \"Existing\": {\n      \"Type\": \"String\"\n    },\n    \"Current\": {\n      \"Type\": \"Str\",\n      \"AssociationProperty\": \"ALIYUN::ACR\",\n      \"AssociationPropertyMetadata\": {\n        \"RegionId\": \"${Ex}\",\n        \"Sta\": \"\"\n      }\n    }\n  }\n}"
	lines := strings.Split(content, "\n")
	registry := newTestRegistry()
	if err := registry.LoadAssociationProperties(); err != nil {
		t.Fatal(err)
	}
	provider := &ROSTemplateProvider{}
	for _, tc := range []struct {
		name   string
		line   int
		prefix string
		want   ContextType
		label  string
	}{
		{"parameter type", 6, "Str", ContextParameterTypeValue, "String"},
		{"association property", 7, "ALIYUN::ACR", ContextAssociationPropertyValue, "ALIYUN::ACR::Namespace::Name"},
		{"metadata reference", 9, "Ex", ContextAssociationPropertyMetadataParamRef, "Existing"},
		{"metadata key", 10, "Sta", ContextAssociationPropertyMetadataKey, "Visible"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			col := strings.Index(lines[tc.line], tc.prefix) + len(tc.prefix)
			got := AnalyzePosition(content, tc.line, col, false)
			if got.Type != tc.want || got.Prefix != tc.prefix {
				t.Fatalf("context %+v", got)
			}
			items := provider.Complete(CompletionContext{Content: content, Line: tc.line, Col: col, IsYAML: false, Registry: registry})
			found := false
			for _, item := range items {
				if item.Label == tc.label {
					found = true
				}
			}
			if !found {
				t.Fatalf("completion %q not found: %+v", tc.label, items)
			}
		})
	}
}

func TestJSONLocalTypeCompletion(t *testing.T) {
	registry := newTestRegistry()
	provider := &ROSTemplateProvider{}
	for _, tc := range []struct{ prefix, want string }{{"Ma", "Macro"}, {"DATASOURCE::VPC", "DATASOURCE::VPC::Vpcs"}} {
		content := "{\n  \"Locals\": {\n    \"Example\": {\n      \"Type\": \"" + tc.prefix + "\"\n    }\n  }\n}"
		line := strings.Split(content, "\n")[3]
		col := strings.Index(line, tc.prefix) + len(tc.prefix)
		context := AnalyzePosition(content, 3, col, false)
		if context.Type != ContextLocalsTypeValue || context.Prefix != tc.prefix {
			t.Fatalf("context: %+v", context)
		}
		items := provider.Complete(CompletionContext{Content: content, Line: 3, Col: col, Registry: registry})
		found := false
		for _, item := range items {
			if item.Label == tc.want {
				found = item.TextEdit != nil && strings.HasPrefix(item.TextEdit.NewText, tc.want)
			}
		}
		if !found {
			t.Fatalf("completion %q: %+v", tc.want, items)
		}
	}
}

func TestJSONGetAttRanges(t *testing.T) {
	cases := []struct {
		name, content          string
		resourceLine, attrLine int
	}{
		{"inline", `{"Fn::GetAtt": ["Instance", "InstanceId"]}`, 0, 0},
		{"multiline", "{\n  \"Fn::GetAtt\": [\n    \"Instance\",\n    \"InstanceId\"\n  ]\n}", 2, 3},
	}
	h := &jsonFormatHandler{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(tc.content, "\n")
			resource := h.FindGetAttResourceRange(tc.content, "Instance")
			attr := h.FindGetAttAttributeRange(tc.content, "Instance", "InstanceId")
			if resource.Start.Line != tc.resourceLine || resource.Start.Character != strings.Index(lines[tc.resourceLine], `"Instance"`)+1 || resource.End.Character-resource.Start.Character != len("Instance") {
				t.Fatalf("resource range %+v", resource)
			}
			if attr.Start.Line != tc.attrLine || attr.Start.Character != strings.Index(lines[tc.attrLine], `"InstanceId"`)+1 || attr.End.Character-attr.Start.Character != len("InstanceId") {
				t.Fatalf("attribute range %+v", attr)
			}
			if got := h.FindGetAttAttributeRange(tc.content, "Other", "InstanceId"); got != (protocol.Range{}) {
				t.Fatalf("unmatched resource: %+v", got)
			}
		})
	}
}

func TestJSONGetAttRangesDistinguishResourceAndAttribute(t *testing.T) {
	content := "{\n  \"First\": {\"Fn::GetAtt\": [\"Other\", \"Target\"]},\n  \"Second\": {\"Fn::GetAtt\": [\"Target\", \"Id\"]},\n  \"Third\": {\"Fn::GetAtt\": [\"Instance\",\n    \"InstanceId\"\n  ]}\n}"
	h := &jsonFormatHandler{}
	lines := strings.Split(content, "\n")
	resource := h.FindGetAttResourceRange(content, "Target")
	if resource.Start.Line != 2 || lines[2][resource.Start.Character:resource.End.Character] != "Target" {
		t.Fatalf("resource matched another attribute: %+v", resource)
	}
	if got := h.FindGetAttResourceRange(content, "InstanceId"); got != (protocol.Range{}) {
		t.Fatalf("attribute matched as resource: %+v", got)
	}
	attr := h.FindGetAttAttributeRange(content, "Instance", "InstanceId")
	if attr.Start.Line != 4 || lines[4][attr.Start.Character:attr.End.Character] != "InstanceId" {
		t.Fatalf("attribute after inline resource: %+v", attr)
	}
}

func TestJSONResourceBlockSnippets(t *testing.T) {
	handler := &jsonFormatHandler{}
	registry := newTestRegistry()
	for _, block := range []string{"Type", "Properties", "Metadata", "DependsOn", "DeletionPolicy", "Condition", "Count", "Custom"} {
		for _, line := range []string{`  "Par`, `  `} {
			ctx := CompletionContext{Content: line, Line: 0, Col: len(line), Registry: registry}
			var item protocol.CompletionItem
			handler.BuildResourceBlockSnippet(&item, block, &AnalysisContext{ResourceTypeName: "ALIYUN::ECS::Instance"}, ctx)
			text := item.InsertText
			if item.TextEdit != nil {
				text = item.TextEdit.NewText
			}
			if !strings.Contains(text, block) {
				t.Errorf("%s snippet on %q: %+v", block, line, item)
			}
			if block == "Properties" && (!strings.Contains(text, "InstanceType") || !strings.Contains(text, "ImageId")) {
				t.Errorf("missing required properties: %s", text)
			}
		}
	}
}

func TestJSONParameterPropertySnippets(t *testing.T) {
	handler := &jsonFormatHandler{}
	for _, tc := range []struct{ name, expected string }{
		{"AllowedValues", `[\n`},
		{"Description", `"en"`},
		{"ConstraintDescription", `"zh-cn"`},
		{"Label", `"en"`},
		{"Placeholder", `"zh-cn"`},
		{"AssociationPropertyMetadata", `{$`},
		{"Type", `"$0"`},
		{"Default", `"$0"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected := strings.ReplaceAll(tc.expected, `\n`, "\n")
			if tc.name == "AssociationPropertyMetadata" {
				expected = "$0"
			}
			for _, line := range []string{`  "Par`, `  `} {
				var item protocol.CompletionItem
				handler.BuildParameterPropertySnippet(&item, ROSParameterProperty{Name: tc.name}, CompletionContext{Content: line, Col: len(line)})
				text := item.InsertText
				if item.TextEdit != nil {
					text = item.TextEdit.NewText
				}
				if !strings.Contains(text, tc.name) || !strings.Contains(text, expected) || item.InsertTextFormat != protocol.InsertTextFormatSnippet {
					t.Fatalf("line %q: %+v", line, item)
				}
			}
		})
	}
}

func TestJSONTypeCompletionWithoutRequiredPropertiesKeepsComma(t *testing.T) {
	line := `"Type": "ALIYUN::ECS::",`
	analysis := &AnalysisContext{ValueStartCol: strings.Index(line, "ALIYUN")}
	ctx := CompletionContext{Content: line, Line: 0, Col: len(line), Registry: newTestRegistry()}
	var item protocol.CompletionItem
	(&jsonFormatHandler{}).BuildTypeCompletion(&item, "ALIYUN::ECS::VPC", analysis, ctx, []string{line}, false)
	if item.TextEdit == nil || item.TextEdit.NewText != `ALIYUN::ECS::VPC",` {
		t.Fatalf("completion lost closing quote or comma: %+v", item)
	}
}

func TestJSONGetAttRangesIgnoreUnrelatedArrayElements(t *testing.T) {
	content := "{\n  \"Fn::GetAtt\": [\n    \"Instance\",\n    \"InstanceId\"\n  ],\n  \"Other\": [\n    \"Unrelated\",\n    \"Name\"\n  ]\n}"
	if got := findGetAttResourceRangeJSON(content, "InstanceId"); !isZeroRange(got) {
		t.Fatalf("attribute mistaken for resource: %+v", got)
	}
	if got := findGetAttResourceRangeJSON(content, "Unrelated"); !isZeroRange(got) {
		t.Fatalf("unrelated list mistaken for GetAtt: %+v", got)
	}
	if got := findGetAttAttributeRangeJSON(content, "Unrelated", "Name"); !isZeroRange(got) {
		t.Fatalf("unrelated attribute: %+v", got)
	}
	if got := findGetAttAttributeRangeJSON(content, "Instance", "Missing"); !isZeroRange(got) {
		t.Fatalf("missing attribute range: %+v", got)
	}
}

func TestJSONGetAttDiagnosticsAcrossArrayLayouts(t *testing.T) {
	for _, tc := range []struct {
		name, expression string
	}{
		{"nested", `{"Fn::Join":["",[{"Fn::GetAtt":["Missing","Id"]},{"Fn::GetAtt":["Instance","InvalidAttribute"]}]]}`},
		{"same line", `[{"Fn::GetAtt":["Other","Id"]},{"Fn::GetAtt":["Missing","Id"]},{"Fn::GetAtt":["Instance","InvalidAttribute"]}]`},
		{"multiline", "{\"Fn::Join\":[\"\",[\n{\"Fn::GetAtt\":\n[\n\"Missing\",\n\"Id\"]},\n{\"Fn::GetAtt\":[\"Instance\",\n\"InvalidAttribute\"]}]]}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := `{"ROSTemplateFormatVersion":"2015-09-01","Resources":{"Instance":{"Type":"ALIYUN::ECS::Instance"}},"Outputs":{"Result":{"Value":` + tc.expression + `}}}`
			if pt := ParseJSON(content); pt.Err != nil {
				t.Fatal(pt.Err)
			}
			lines := strings.Split(content, "\n")
			diags := (&ROSTemplateProvider{}).Validate(ValidationContext{Content: content, Registry: newTestRegistry()})
			for _, target := range []string{"Missing", "InvalidAttribute"} {
				found := false
				for _, diag := range diags {
					if strings.Contains(diag.Message, target) {
						r := diag.Range
						if lines[r.Start.Line][r.Start.Character:r.End.Character] != target {
							t.Fatalf("wrong diagnostic range: %+v", diag)
						}
						found = true
					}
				}
				if !found {
					t.Errorf("missing diagnostic for %s: %+v", target, diags)
				}
			}
		})
	}
}
