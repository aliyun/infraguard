package template

import (
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/lsp/protocol"
)

func TestAssociationMetadataDiagnostics(t *testing.T) {
	registry := newTestRegistry()
	if err := registry.LoadAssociationProperties(); err != nil {
		t.Fatal(err)
	}
	provider := &ROSTemplateProvider{}
	cases := []struct {
		name, content string
		yaml          bool
	}{
		{"YAML", `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  Existing:
    Type: String
  Repository:
    Type: String
    AssociationProperty: ALIYUN::ACR::Namespace::Name
    AssociationPropertyMetadata:
      Status: 42
      RegionId: ${Missing}
      Visible:
        Fn::Equals: ["${Existing}", "${Other}"]
`, true},
		{"JSON", `{"ROSTemplateFormatVersion":"2015-09-01", "Parameters": {
  "Existing": {"Type":"String"},
  "Repository": {"Type":"String", "AssociationProperty":"ALIYUN::ACR::Namespace::Name", "AssociationPropertyMetadata": {
    "Status": 42,
    "RegionId": "${Missing}",
    "Visible": {"Fn::Equals": ["${Existing}", "${Other}"]}
  }}
}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diags := provider.Validate(ValidationContext{Content: tc.content, IsYAML: tc.yaml, Registry: registry})
			found := map[string]bool{}
			for _, d := range diags {
				for _, s := range []string{"Status", "Missing", "Other", "Existing"} {
					if strings.Contains(d.Message, s) {
						found[s] = true
					}
				}
			}
			if !found["Status"] || !found["Missing"] || !found["Other"] || found["Existing"] {
				t.Fatalf("diagnostics: %+v", diags)
			}
		})
	}
}

func TestROSTemplateDetection(t *testing.T) {
	provider := &ROSTemplateProvider{}
	for _, tc := range []struct {
		filename, content string
		want              bool
	}{
		{"template.ros.yaml", "", true}, {"template.ros.yml", "", true}, {"template.ros.json", "", true},
		{"template.yaml", "ROSTemplateFormatVersion: 2015", true}, {"other.yaml", "Resources: {}", false},
	} {
		if got := provider.Detect([]byte(tc.content), tc.filename); got != tc.want {
			t.Errorf("detect %+v = %v", tc, got)
		}
	}
}

func TestAssociationAndMappingCompletions(t *testing.T) {
	registry := newTestRegistry()
	if err := registry.LoadAssociationProperties(); err != nil {
		t.Fatal(err)
	}
	provider := &ROSTemplateProvider{}
	for _, tc := range []struct {
		name, content string
		yaml          bool
	}{
		{"YAML", "ROSTemplateFormatVersion: '2015-09-01'\nParameters:\n  Existing:\n    Type: String\n  Current:\n    Type: String\nMappings:\n  Regions:\n    East:\n      Image: a\n    West:\n      Image: b\n", true},
		{"JSON", `{"ROSTemplateFormatVersion":"2015-09-01", "Parameters":{"Existing":{"Type":"String"},"Current":{"Type":"String"}}, "Mappings":{"Regions":{"East":{"Image":"a"},"West":{"Image":"b"}}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := getFormatHandler(tc.yaml)
			ctx := CompletionContext{Content: tc.content, Line: 0, Col: 0, IsYAML: tc.yaml, Registry: registry}
			has := func(items []protocol.CompletionItem, label string) bool {
				for _, item := range items {
					if item.Label == label {
						return true
					}
				}
				return false
			}
			types := provider.completeAssociationPropertyValue(&AnalysisContext{Prefix: "acr::namespace"}, handler, ctx)
			if !has(types, "ALIYUN::ACR::Namespace::Name") {
				t.Fatalf("association values: %+v", types)
			}
			metadata := provider.completeAssociationPropertyMetadataKey(&AnalysisContext{ResourceTypeName: "ALIYUN::ACR::Namespace::Name", ExistingKeys: []string{"RegionId"}}, handler, ctx)
			if !has(metadata, "Status") || !has(metadata, "Visible") || has(metadata, "RegionId") {
				t.Fatalf("metadata keys: %+v", metadata)
			}
			refs := provider.completeAssociationPropertyMetadataParamRef(&AnalysisContext{CurrentParamName: "Current"}, handler, ctx)
			if !has(refs, "Existing") || has(refs, "Current") {
				t.Fatalf("parameter refs: %+v", refs)
			}
			if !has(provider.completeFindInMapMapName(&AnalysisContext{Prefix: "reg"}, handler, ctx), "Regions") {
				t.Fatal("mapping completion missing Regions")
			}
			if !has(provider.completeFindInMapFirstKey(&AnalysisContext{FindInMapMapName: "Regions", Prefix: "ea"}, handler, ctx), "East") {
				t.Fatal("mapping key completion missing East")
			}
			if !has(provider.completeFindInMapSecondKey(&AnalysisContext{FindInMapMapName: "Regions", FindInMapFirstKey: "East"}, handler, ctx), "Image") {
				t.Fatal("mapping value completion missing Image")
			}
		})
	}
}

func TestYAMLMetadataParameterReferenceCompletion(t *testing.T) {
	content := `Parameters:
  Existing:
    Type: String
  Current:
    Type: String
    AssociationProperty: ALIYUN::ACR::Namespace::Name
    AssociationPropertyMetadata:
      RegionId: "${Ex}"
      Nested:
        Value: "${Ex}"
    Description: "${Ex}"
`
	lines := strings.Split(content, "\n")
	registry := newTestRegistry()
	for _, line := range []int{7, 9} {
		t.Run(lines[line], func(t *testing.T) {
			col := strings.Index(lines[line], "${Ex}") + 4
			analysis := AnalyzePosition(content, line, col, true)
			if analysis.Type != ContextAssociationPropertyMetadataParamRef || analysis.CurrentParamName != "Current" || analysis.Prefix != "Ex" {
				t.Fatalf("analysis: %+v", analysis)
			}
			items := (&ROSTemplateProvider{}).Complete(CompletionContext{Content: content, Line: line, Col: col, IsYAML: true, Registry: registry})
			found := false
			for _, item := range items {
				if item.Label == "Existing" {
					found = true
				}
				if item.Label == "Current" {
					t.Errorf("current parameter suggested: %+v", item)
				}
			}
			if !found {
				t.Fatalf("missing Existing completion: %+v", items)
			}
		})
	}
	emptyContent := strings.Replace(content, `${Ex}`, `${}`, 1)
	emptyLines := strings.Split(emptyContent, "\n")
	emptyCol := strings.Index(emptyLines[7], `${}`) + 2
	items := (&ROSTemplateProvider{}).Complete(CompletionContext{Content: emptyContent, Line: 7, Col: emptyCol, IsYAML: true, Registry: registry})
	foundExisting := false
	for _, item := range items {
		if item.Label == "Existing" {
			foundExisting = true
		}
		if item.Label == "Current" {
			t.Errorf("current parameter suggested: %+v", item)
		}
	}
	if !foundExisting {
		t.Fatalf("missing Existing completion: %+v", items)
	}
	col := strings.Index(lines[10], "${Ex}") + 4
	if got := AnalyzePosition(content, 10, col, true); got.Type == ContextAssociationPropertyMetadataParamRef {
		t.Fatalf("non-metadata value matched: %+v", got)
	}
	line := `      RegionId: "${Existing}" tail`
	if got := checkParamRefInLine(line, len(line)); got != nil {
		t.Fatalf("cursor past closing brace matched: %+v", got)
	}
}

func TestConditionDiagnosticsSkipMalformedEntries(t *testing.T) {
	content := "Conditions:\n  Known: !Equals [a, a]\nResources:\n  Invalid: text\n  Malformed:\n    Type: ALIYUN::ECS::VPC\n    Condition: 5\n  Missing:\n    Type: ALIYUN::ECS::VPC\n    Condition: Absent\nOutputs:\n  Broken: text\n"
	handler := getFormatHandler(true)
	ctx := ValidationContext{Content: content, IsYAML: true, Registry: newTestRegistry()}
	diags := (&ROSTemplateProvider{}).validateConditionRefs(handler.ParseTemplate(content), handler, ctx)
	if len(diags) != 1 || !strings.Contains(diags[0].Message, "Absent") {
		t.Fatalf("condition diagnostics: %+v", diags)
	}
}
