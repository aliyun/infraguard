package template

import (
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/lsp/protocol"
)

func TestNestedPropertiesAndAttributeCompletions(t *testing.T) {
	provider := &ROSTemplateProvider{}
	registry := newTestRegistry()
	cases := []struct {
		name, content string
		yaml          bool
	}{
		{"YAML", "Resources:\n  Instance:\n    Type: ALIYUN::ECS::Instance\n", true},
		{"JSON", `{"Resources":{"Instance":{"Type":"ALIYUN::ECS::Instance"}}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := CompletionContext{Content: tc.content, Line: 0, Col: 0, IsYAML: tc.yaml, Registry: registry}
			handler := getFormatHandler(tc.yaml)
			has := func(items []protocol.CompletionItem, label string) bool {
				for _, item := range items {
					if item.Label == label {
						return true
					}
				}
				return false
			}
			analysis := &AnalysisContext{ResourceTypeName: "ALIYUN::ECS::SecurityGroup", PropertyPath: []string{"SecurityGroupIngress"}, ExistingKeys: []string{"PortRange"}, Prefix: "not-a-function"}
			items := provider.completePropertyValue(analysis, handler, ctx)
			if !has(items, "IpProtocol") || !has(items, "NicType") || has(items, "PortRange") {
				t.Fatalf("nested completions: %+v", items)
			}
			for _, item := range items {
				if item.Label == "IpProtocol" && (item.Documentation == nil || !strings.Contains(item.Documentation.Value, "Allowed Values") || !strings.Contains(item.Documentation.Value, "tcp")) {
					t.Fatalf("missing constraint documentation: %+v", item)
				}
			}
			attrs := provider.completeGetAttAttribute(&AnalysisContext{GetAttResourceName: "Instance", Prefix: "inst"}, handler, ctx)
			if !has(attrs, "InstanceId") {
				t.Fatalf("attribute completion: %+v", attrs)
			}
			if got := provider.completeGetAttAttribute(&AnalysisContext{GetAttResourceName: "Missing"}, handler, ctx); len(got) != 0 {
				t.Fatalf("unknown resource: %+v", got)
			}
		})
	}
}

func TestTypeCompletionAddsRequiredProperties(t *testing.T) {
	registry := newTestRegistry()
	for _, tc := range []struct {
		name, content string
		yaml          bool
		start         int
	}{
		{"YAML", "Resources:\n  Instance:\n    Type: ALIYUN::ECS\n", true, 10},
		{"JSON", "{\n  \"Instance\": {\n    \"Type\": \"ALIYUN::ECS\"\n  }\n}", false, 13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(tc.content, "\n")
			ctx := CompletionContext{Content: tc.content, Line: 2, Col: len(lines[2]), IsYAML: tc.yaml, Registry: registry}
			handler := getFormatHandler(tc.yaml)
			analysis := &AnalysisContext{ValueStartCol: tc.start}
			var item protocol.CompletionItem
			handler.BuildTypeCompletion(&item, "ALIYUN::ECS::Instance", analysis, ctx, lines, false)
			if item.TextEdit == nil || !strings.Contains(item.TextEdit.NewText, "InstanceType") || !strings.Contains(item.TextEdit.NewText, "ImageId") {
				t.Fatalf("missing required properties: %+v", item)
			}
			var existing protocol.CompletionItem
			handler.BuildTypeCompletion(&existing, "ALIYUN::ECS::Instance", analysis, ctx, lines, true)
			if existing.TextEdit == nil || strings.Contains(existing.TextEdit.NewText, "Properties") {
				t.Fatalf("duplicate properties: %+v", existing)
			}
		})
	}
}

func TestGetAttAttributeCompletionFromEditorPosition(t *testing.T) {
	content := "Resources:\n  Instance:\n    Type: ALIYUN::ECS::Instance\nOutputs:\n  Id:\n    Value: !GetAtt Instance.InstanceId\n"
	line := strings.Split(content, "\n")[5]
	col := strings.Index(line, "InstanceId") + len("Ins")
	ctx := CompletionContext{Content: content, Line: 5, Col: col, IsYAML: true, Registry: newTestRegistry()}
	items := (&ROSTemplateProvider{}).Complete(ctx)
	for _, item := range items {
		if item.Label == "InstanceId" {
			return
		}
	}
	t.Fatalf("missing attribute completion: %+v; context %+v", items, AnalyzePosition(content, 5, col, true))
}

func TestReferenceCompletionsFilterByPrefixAndScope(t *testing.T) {
	content := `Parameters:
  AlphaParameter: {Type: String}
  BetaParameter: {Type: String}
Locals:
  AlphaLocal: {Value: value}
  BetaLocal: {Value: value}
Resources:
  AlphaInstance: {Type: ALIYUN::ECS::Instance}
  BetaInstance: {Type: ALIYUN::ECS::Instance}
`
	provider := &ROSTemplateProvider{}
	ctx := CompletionContext{Content: content, IsYAML: true, Registry: newTestRegistry()}
	h := getFormatHandler(true)
	refs := provider.completeRefValue(&AnalysisContext{Prefix: "ALP", ResourceName: "AlphaInstance"}, h, ctx)
	labels := make(map[string]bool)
	for _, item := range refs {
		labels[item.Label] = true
	}
	if len(labels) != 2 || !labels["AlphaParameter"] || !labels["AlphaLocal"] {
		t.Fatalf("reference completions: %+v", refs)
	}
	resources := provider.completeGetAttResource(&AnalysisContext{Prefix: "alp"}, h, ctx)
	if len(resources) != 1 || resources[0].Label != "AlphaInstance" {
		t.Fatalf("resource completions: %+v", resources)
	}
	if got := provider.completeGetAttAttribute(&AnalysisContext{GetAttResourceName: "AlphaInstance", Prefix: "not-present"}, h, ctx); len(got) != 0 {
		t.Fatalf("unmatched attributes: %+v", got)
	}
	if got := provider.completeGetAttAttribute(&AnalysisContext{}, h, ctx); len(got) != 0 {
		t.Fatalf("attributes without a resource: %+v", got)
	}
	if got := provider.completeResourceProperties(&AnalysisContext{ResourceTypeName: "unknown"}, h, ctx); len(got) != 0 {
		t.Fatalf("properties for unknown type: %+v", got)
	}
	if got := provider.completeTopLevel(&AnalysisContext{Prefix: "map"}, h, ctx); len(got) != 1 || got[0].Label != "Mappings" {
		t.Fatalf("top-level prefix: %+v", got)
	}
}

func TestMissingParameterTypeCompletionIsMarkedRequired(t *testing.T) {
	ctx := CompletionContext{Content: "Parameters:\n  Name:\n    Ty", Line: 2, Col: 6, IsYAML: true}
	items := (&ROSTemplateProvider{}).completeParameterProperties(&AnalysisContext{Prefix: "ty"}, getFormatHandler(true), ctx)
	if len(items) != 1 || items[0].Label != "Type" || !strings.HasSuffix(items[0].Detail, "*") || items[0].Documentation == nil || !strings.Contains(items[0].Documentation.Value, "Required:** Yes") {
		t.Fatalf("required parameter type: %+v", items)
	}
	if got := (&ROSTemplateProvider{}).completeParameterProperties(&AnalysisContext{Prefix: "ty", ExistingKeys: []string{"Type"}}, getFormatHandler(true), ctx); len(got) != 0 {
		t.Fatalf("already present type suggested: %+v", got)
	}
}

func TestTopLevelSnippetsForBothFormats(t *testing.T) {
	for _, yaml := range []bool{true, false} {
		for _, block := range []string{"ROSTemplateFormatVersion", "Description", "Parameters", "Locals", "Resources", "Outputs", "Conditions", "Mappings", "Custom"} {
			var item protocol.CompletionItem
			getFormatHandler(yaml).BuildTopLevelSnippet(&item, block, CompletionContext{Content: "  ", Line: 0, Col: 2, IsYAML: yaml})
			text := item.InsertText
			if item.TextEdit != nil {
				text = item.TextEdit.NewText
			}
			if !strings.Contains(text, block) {
				t.Errorf("yaml=%v %s snippet: %+v", yaml, block, item)
			}
			if block == "ROSTemplateFormatVersion" {
				if !strings.Contains(text, "2015-09-01") || item.InsertTextFormat == protocol.InsertTextFormatSnippet {
					t.Errorf("yaml=%v version snippet: %+v", yaml, item)
				}
			} else if item.InsertTextFormat != protocol.InsertTextFormatSnippet || (!strings.Contains(text, "$0") && !strings.Contains(text, "${0:")) {
				t.Errorf("yaml=%v %s should be an editable snippet: %+v", yaml, block, item)
			}
		}
	}
}

func TestCompletionFiltersLocalsMappingsAndUnknownResourceAttributes(t *testing.T) {
	provider := &ROSTemplateProvider{}
	handler := getFormatHandler(true)
	ctx := CompletionContext{Content: "Mappings:\n  Regions:\n    East:\n      Image: x\nResources:\n  Vpc:\n    Type: ALIYUN::ECS::VPC\n", Registry: newTestRegistry(), IsYAML: true}
	locals := provider.completeLocalsProperties(&AnalysisContext{Prefix: "Ty"}, handler, ctx)
	if len(locals) != 1 || locals[0].Label != "Type" {
		t.Fatalf("locals prefix: %+v", locals)
	}
	maps := provider.completeFindInMapMapName(&AnalysisContext{Prefix: "missing"}, handler, ctx)
	if len(maps) != 0 {
		t.Fatalf("unmatched map names: %+v", maps)
	}
	if got := provider.completeResourceProperties(&AnalysisContext{}, handler, ctx); got != nil {
		t.Fatalf("properties without type: %+v", got)
	}
	if got := provider.completeGetAttAttribute(&AnalysisContext{GetAttResourceName: "Vpc"}, handler, ctx); got != nil {
		t.Fatalf("attributes on resource without schema attributes: %+v", got)
	}
}
