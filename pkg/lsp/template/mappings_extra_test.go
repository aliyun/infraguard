package template

import (
	"strings"
	"testing"
)

func TestMappingValidationAndCompletion(t *testing.T) {
	p := &ROSTemplateProvider{}
	for _, tc := range []struct {
		name, content string
		yaml          bool
	}{
		{"yaml", "Mappings:\n  Regions:\n    East:\n      Image: a\n    West:\n      Size: b\n  Scalar: nope\n  BadNested:\n    Invalid: nope\n", true},
		{"json", `{"Mappings":{"Regions":{"East":{"Image":"a"},"West":{"Size":"b"}},"Scalar":"nope","BadNested":{"Invalid":"nope"}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := getFormatHandler(tc.yaml)
			ctx := ValidationContext{Content: tc.content, IsYAML: tc.yaml}
			diags := p.validateMappings(h.ParseTemplate(tc.content), h, ctx)
			if len(diags) != 2 {
				t.Fatalf("expected two invalid mapping diagnostics, got %+v", diags)
			}
			messages := diags[0].Message + diags[1].Message
			if !strings.Contains(messages, "Scalar") || !strings.Contains(messages, "BadNested.Invalid") {
				t.Fatalf("unexpected diagnostics: %+v", diags)
			}
			completion := CompletionContext{Content: tc.content, IsYAML: tc.yaml}
			first := p.completeFindInMapFirstKey(&AnalysisContext{FindInMapMapName: "Regions", Prefix: "ea"}, h, completion)
			if len(first) != 1 || first[0].Label != "East" {
				t.Fatalf("first keys: %+v", first)
			}
			second := p.completeFindInMapSecondKey(&AnalysisContext{FindInMapMapName: "Regions", FindInMapFirstKey: "East"}, h, completion)
			if len(second) != 1 || second[0].Label != "Image" || !strings.Contains(second[0].Detail, "Regions.East") {
				t.Fatalf("second keys: %+v", second)
			}
			dynamic := p.completeFindInMapSecondKey(&AnalysisContext{FindInMapMapName: "Regions", FindInMapFirstKey: "dynamic"}, h, completion)
			if len(dynamic) != 2 || dynamic[0].Label != "Image" || dynamic[1].Label != "Size" {
				t.Fatalf("dynamic keys: %+v", dynamic)
			}
		})
	}
}

func TestMappingValueOffersIntrinsicCompletions(t *testing.T) {
	p := &ROSTemplateProvider{}
	for _, tc := range []struct {
		name, content string
		yaml          bool
		line          int
		want          string
	}{
		{"YAML", "Mappings:\n  Region:\n    East:\n      Image: \n", true, 3, "!Ref"},
		{"JSON", "{\n  \"Mappings\": {\n    \"Region\": {\n      \"East\": {\n        \"Image\": \"\"\n      }\n    }\n  }\n}", false, 4, "Ref"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(tc.content, "\n")
			col := len(lines[tc.line])
			if !tc.yaml {
				col--
			}
			ctx := CompletionContext{Content: tc.content, Line: tc.line, Col: col, IsYAML: tc.yaml, Registry: newTestRegistry()}
			items := p.Complete(ctx)
			for _, item := range items {
				if item.Label == tc.want {
					return
				}
			}
			t.Fatalf("missing %q in %+v, analysis=%+v", tc.want, items, AnalyzePosition(tc.content, tc.line, col, tc.yaml))
		})
	}
}

func TestFindInMapCompletionsFromEditorPosition(t *testing.T) {
	for _, tc := range []struct {
		name, content, marker, want string
		yaml                        bool
	}{
		{"yaml map", "Mappings:\n  Regions:\n    East:\n      Image: image\nOutputs:\n  Result:\n    Value: !FindInMap [Regions, East, Image]\n", "Reg", "Regions", true},
		{"yaml first key", "Mappings:\n  Regions:\n    East:\n      Image: image\nOutputs:\n  Result:\n    Value: !FindInMap [Regions, East, Image]\n", "Ea", "East", true},
		{"json map", "{\n  \"Mappings\": {\n    \"Regions\": {\"East\": {\"Image\": \"image\"}}\n  },\n  \"Outputs\": {\n    \"Result\": {\n      \"Value\": {\"Fn::FindInMap\": [\"Regions\", \"East\", \"Image\"]}\n    }\n  }\n}", "Reg", "Regions", false},
		{"json first key", "{\n  \"Mappings\": {\n    \"Regions\": {\"East\": {\"Image\": \"image\"}}\n  },\n  \"Outputs\": {\n    \"Result\": {\n      \"Value\": {\"Fn::FindInMap\": [\"Regions\", \"East\", \"Image\"]}\n    }\n  }\n}", "Ea", "East", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(tc.content, "\n")
			line := 6
			col := strings.Index(lines[line], tc.marker) + len(tc.marker)
			ctx := CompletionContext{Content: tc.content, Line: line, Col: col, IsYAML: tc.yaml, Registry: newTestRegistry()}
			items := (&ROSTemplateProvider{}).Complete(ctx)
			for _, item := range items {
				if item.Label == tc.want {
					return
				}
			}
			t.Fatalf("missing %q in %+v; context %+v", tc.want, items, AnalyzePosition(tc.content, line, col, tc.yaml))
		})
	}
}
