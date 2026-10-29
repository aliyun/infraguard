package template

import (
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/lsp/protocol"
)

func TestYAMLResourceSnippetsAndRanges(t *testing.T) {
	h := &yamlFormatHandler{}
	registry := newTestRegistry()
	for _, tc := range []struct{ block, want string }{{"Type", "Type:"}, {"Metadata", "Metadata:"}, {"Properties", "InstanceType:"}, {"Condition", "Condition:"}} {
		var item protocol.CompletionItem
		h.BuildResourceBlockSnippet(&item, tc.block, &AnalysisContext{ResourceTypeName: "ALIYUN::ECS::Instance"}, CompletionContext{Registry: registry})
		if !strings.Contains(item.InsertText, tc.want) {
			t.Errorf("%s snippet: %q", tc.block, item.InsertText)
		}
	}
	if got := buildYAMLPropertiesSnippet("", nil); got != "Properties:\n  $0" {
		t.Fatalf("default snippet: %q", got)
	}
	content := "Mappings:\n  Regions:\n    East: {}\nResources:\n  Instance:\n    Type: ALIYUN::ECS::Instance # comment\n"
	typ := h.FindResourceTypeRange(content, "Instance")
	mapping := h.FindMappingsRange(content, "Regions")
	lines := strings.Split(content, "\n")
	if typ.Start.Line != 5 || lines[5][typ.Start.Character:typ.End.Character] != "ALIYUN::ECS::Instance" {
		t.Fatalf("type range %+v", typ)
	}
	if mapping.Start.Line != 1 || lines[1][mapping.Start.Character:mapping.End.Character] != "Regions" {
		t.Fatalf("mapping range %+v", mapping)
	}
}

func TestYAMLGetAttRanges(t *testing.T) {
	cases := []struct {
		name, content     string
		resLine, attrLine int
	}{
		{"short", "Value: !GetAtt Instance.InstanceId", 0, 0},
		{"list", "Fn::GetAtt:\n  - Instance\n  - InstanceId", 1, 2},
	}
	h := &yamlFormatHandler{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(tc.content, "\n")
			res := h.FindGetAttResourceRange(tc.content, "Instance")
			attr := h.FindGetAttAttributeRange(tc.content, "Instance", "InstanceId")
			if res.Start.Line != tc.resLine || lines[res.Start.Line][res.Start.Character:res.End.Character] != "Instance" {
				t.Fatalf("resource range %+v", res)
			}
			if attr.Start.Line != tc.attrLine || lines[attr.Start.Line][attr.Start.Character:attr.End.Character] != "InstanceId" {
				t.Fatalf("attribute range %+v", attr)
			}
			if got := h.FindGetAttAttributeRange(tc.content, "Missing", "InstanceId"); got != (protocol.Range{}) {
				t.Fatalf("unexpected match %+v", got)
			}
		})
	}
}

func TestYAMLGetAttRangesIgnoreUnrelatedListsAndHandleInlineForm(t *testing.T) {
	content := "Other:\n  - Missing\nValue:\n  Fn::GetAtt:\n    - Missing\n    - Id\n"
	lines := strings.Split(content, "\n")
	h := &yamlFormatHandler{}
	resource := h.FindGetAttResourceRange(content, "Missing")
	if resource.Start.Line != 4 || lines[4][resource.Start.Character:resource.End.Character] != "Missing" {
		t.Fatalf("resource matched an unrelated list: %+v", resource)
	}
	inline := "Value:\n  Fn::GetAtt: [Missing, Id]\n"
	line := strings.Split(inline, "\n")[1]
	resource = h.FindGetAttResourceRange(inline, "Missing")
	if resource.Start.Line != 1 || line[resource.Start.Character:resource.End.Character] != "Missing" {
		t.Fatalf("inline resource: %+v", resource)
	}
	attr := h.FindGetAttAttributeRange(inline, "Missing", "Id")
	if attr.Start.Line != 1 || line[attr.Start.Character:attr.End.Character] != "Id" {
		t.Fatalf("inline attribute: %+v", attr)
	}
	quoted := "Value:\n  Fn::GetAtt: ['Missing', \"Id\"]\n"
	line = strings.Split(quoted, "\n")[1]
	resource = h.FindGetAttResourceRange(quoted, "Missing")
	attr = h.FindGetAttAttributeRange(quoted, "Missing", "Id")
	if resource.Start.Line != 1 || line[resource.Start.Character:resource.End.Character] != "Missing" || attr.Start.Line != 1 || line[attr.Start.Character:attr.End.Character] != "Id" {
		t.Fatalf("quoted inline ranges: %+v %+v", resource, attr)
	}
	if got := h.FindGetAttResourceRange("Other:\n  - Missing\n", "Missing"); got != (protocol.Range{}) {
		t.Fatalf("unrelated list matched: %+v", got)
	}
	list := "Fn::GetAtt:\n  - 'Missing' # resource\n  - \"Id\" # attribute\n"
	listLines := strings.Split(list, "\n")
	resource = h.FindGetAttResourceRange(list, "Missing")
	attr = h.FindGetAttAttributeRange(list, "Missing", "Id")
	if resource.Start.Line != 1 || listLines[1][resource.Start.Character:resource.End.Character] != "Missing" || attr.Start.Line != 2 || listLines[2][attr.Start.Character:attr.End.Character] != "Id" {
		t.Fatalf("quoted list ranges: %+v %+v", resource, attr)
	}
}

func TestYAMLInlineGetAttReportsUndefinedResourceAtValue(t *testing.T) {
	content := "ROSTemplateFormatVersion: '2015-09-01'\nResources: {}\nOutputs:\n  Result:\n    Value:\n      Fn::GetAtt: [Missing, Id]\n"
	lines := strings.Split(content, "\n")
	diags := (&ROSTemplateProvider{}).Validate(ValidationContext{Content: content, IsYAML: true, Registry: newTestRegistry()})
	for _, diag := range diags {
		if strings.Contains(diag.Message, "Missing") {
			if diag.Range.Start.Line != 5 || lines[5][diag.Range.Start.Character:diag.Range.End.Character] != "Missing" {
				t.Fatalf("undefined resource range: %+v", diag)
			}
			return
		}
	}
	t.Fatalf("missing undefined resource diagnostic: %+v", diags)
}

func TestYAMLInlineGetAttReportsInvalidAttributeAtValue(t *testing.T) {
	content := "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  Example:\n    Type: ALIYUN::ECS::Instance\nOutputs:\n  Result:\n    Value:\n      Fn::GetAtt: [Example, NotAnAttribute]\n"
	lines := strings.Split(content, "\n")
	diags := (&ROSTemplateProvider{}).Validate(ValidationContext{Content: content, IsYAML: true, Registry: newTestRegistry()})
	for _, diag := range diags {
		if strings.Contains(diag.Message, "NotAnAttribute") {
			if diag.Range.Start.Line != 7 || lines[7][diag.Range.Start.Character:diag.Range.End.Character] != "NotAnAttribute" {
				t.Fatalf("invalid attribute range: %+v", diag)
			}
			return
		}
	}
	t.Fatalf("missing invalid attribute diagnostic: %+v", diags)
}

func TestYAMLInlineGetAttRejectsIncompleteValues(t *testing.T) {
	for _, line := range []string{
		"Value: other", "# Fn::GetAtt: [A, B]", "Fn::GetAtt: A", "Fn::GetAtt: [A,", "Fn::GetAtt: [A]", "Fn::GetAtt: [, B]", "Fn::GetAtt: [A, ]",
	} {
		if _, _, _, _, ok := yamlInlineGetAttPositions(line); ok {
			t.Errorf("incomplete GetAtt accepted: %q", line)
		}
	}
	lines := []string{"Fn::GetAtt:", "  # comment", "", "  - Resource", "  - Attribute"}
	if !isFirstGetAttListItem(lines, 3) || isFirstGetAttListItem(lines, 4) || isFirstGetAttListItem([]string{"  - unrelated"}, 0) {
		t.Fatal("GetAtt list position classification")
	}
}

func TestYAMLResourcePropertyValueRanges(t *testing.T) {
	content := `Resources:
  Instance:
    Type: ALIYUN::ECS::Instance
    Properties:
      ImageId: image-123
      Nested:
        # nested comment
        Ref: Name
      Empty:
      Last: value
  Other:
    Properties:
      ImageId: wrong
`
	lines := strings.Split(content, "\n")
	for _, tc := range []struct {
		prop string
		line int
		text string
	}{
		{"ImageId", 4, "image-123"}, {"Nested", 7, "Ref: Name"}, {"Empty", 1, "Instance"}, {"Missing", 1, "Instance"},
	} {
		t.Run(tc.prop, func(t *testing.T) {
			got := findResourcePropertyValueRangeYAML(content, "Instance", tc.prop)
			if got.Start.Line != tc.line || lines[got.Start.Line][got.Start.Character:got.End.Character] != tc.text {
				t.Fatalf("range: %+v", got)
			}
		})
	}
	if got := findResourcePropertyValueRangeYAML(content, "Absent", "ImageId"); got != (protocol.Range{}) {
		t.Fatalf("missing resource range: %+v", got)
	}
}

func TestYAMLPropertiesSnippetWithoutRequiredProperties(t *testing.T) {
	if got := buildYAMLPropertiesSnippet("ALIYUN::ECS::VPC", newTestRegistry()); got != "Properties:\n  $0" {
		t.Fatalf("optional-only properties: %q", got)
	}
}

func TestYAMLGetAttRangeForBareResource(t *testing.T) {
	content := "Outputs:\n  Name:\n    Fn::GetAtt: Instance\n"
	got := findGetAttResourceRangeYAML(content, "Instance")
	if got.Start.Line != 2 || got.End.Character-got.Start.Character != len("Instance") {
		t.Fatalf("bare resource range: %+v", got)
	}
}

func TestYAMLGetAttDiagnosticsAcrossListLayouts(t *testing.T) {
	for _, layout := range []struct{ name, value string }{
		{"indentless", "      Fn::GetAtt:\n      # list items may have the same indentation as the key\n      - RESOURCE\n      - ATTRIBUTE\n"},
		{"list mapping", "      Fn::Join:\n        - ''\n        -\n          - Fn::GetAtt:\n              - RESOURCE\n              - ATTRIBUTE\n          - '.example'\n"},
		{"nested list mapping", "      Fn::Join:\n        - ''\n        - - Fn::GetAtt:\n              - RESOURCE\n              - ATTRIBUTE\n          - '.example'\n"},
		{"quoted key", "      'Fn::GetAtt' : # resource attribute pair\n      - RESOURCE\n      - ATTRIBUTE\n"},
		{"quoted list mapping", "      Fn::Join:\n        - ''\n        - - \"Fn::GetAtt\":\n              - RESOURCE\n              - ATTRIBUTE\n          - '.example'\n"},
	} {
		for _, tc := range []struct{ resource, attribute, target string }{
			{"Missing", "InstanceId", "Missing"},
			{"Instance", "InvalidAttribute", "InvalidAttribute"},
		} {
			t.Run(layout.name+"/"+tc.target, func(t *testing.T) {
				value := strings.NewReplacer("RESOURCE", tc.resource, "ATTRIBUTE", tc.attribute).Replace(layout.value)
				content := "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  Instance:\n    Type: ALIYUN::ECS::Instance\nOutputs:\n  Result:\n    Value:\n" + value
				if pt := ParseYAML(content); pt.Err != nil {
					t.Fatal(pt.Err)
				}
				lines := strings.Split(content, "\n")
				diags := (&ROSTemplateProvider{}).Validate(ValidationContext{Content: content, IsYAML: true, Registry: newTestRegistry()})
				for _, diag := range diags {
					if strings.Contains(diag.Message, tc.target) {
						r := diag.Range
						if lines[r.Start.Line][r.Start.Character:r.End.Character] != tc.target {
							t.Fatalf("wrong diagnostic range: %+v", diag)
						}
						return
					}
				}
				t.Fatalf("missing diagnostic for %s: %+v", tc.target, diags)
			})
		}
	}
}
