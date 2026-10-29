package template

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/lsp/protocol"
)

func TestGetAttAttributeDiagnosticsDeduplicateAndRespectSchema(t *testing.T) {
	content := `Resources:
  Instance:
    Type: ALIYUN::ECS::Instance
  NoType: {}
  UnknownType:
    Type: ALIYUN::TEST::Unknown
Outputs:
  First:
    Value: !GetAtt Instance.NotAnAttribute
  Duplicate:
    Value: !GetAtt Instance.NotAnAttribute
  Untyped:
    Value: !GetAtt NoType.NotAnAttribute
  Unknown:
    Value: !GetAtt UnknownType.NotAnAttribute
  MissingResource:
    Value: !GetAtt Missing.NotAnAttribute
`
	h := getFormatHandler(true)
	pt := h.ParseTemplate(content)
	p := &ROSTemplateProvider{}
	ctx := ValidationContext{Content: content, IsYAML: true, Registry: newTestRegistry()}
	got := p.validateGetAttAttributes(pt, h, ctx)
	if len(got) != 1 || !strings.Contains(got[0].Message, "NotAnAttribute") || !strings.Contains(got[0].Message, "Instance") {
		t.Fatalf("attribute diagnostics: %+v", got)
	}
	ctx.Registry = nil
	if got := p.validateGetAttAttributes(pt, h, ctx); len(got) != 0 {
		t.Fatalf("diagnostics without schema: %+v", got)
	}
}

func TestResourceValidationMissingTypeAndProperties(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		yaml          bool
	}{
		{"YAML", "Resources:\n  NoType:\n    Properties: {}\n  Unknown:\n    Type: ALIYUN::TEST::Unknown\n  NoProps:\n    Type: ALIYUN::ECS::Instance\n  BadProps:\n    Type: ALIYUN::ECS::Instance\n    Properties:\n      ImageId: image\n      InstanceType: 42\n  Intrinsic:\n    Type: ALIYUN::ECS::Instance\n    Properties:\n      ImageId: {Ref: Image}\n      InstanceType: ecs.g6.large\n", true},
		{"JSON", `{"Resources":{"NoType":{"Properties":{}},"Unknown":{"Type":"ALIYUN::TEST::Unknown"},"NoProps":{"Type":"ALIYUN::ECS::Instance"},"BadProps":{"Type":"ALIYUN::ECS::Instance","Properties":{"ImageId":"image","InstanceType":42}},"Intrinsic":{"Type":"ALIYUN::ECS::Instance","Properties":{"ImageId":{"Ref":"Image"},"InstanceType":"ecs.g6.large"}}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &ROSTemplateProvider{}
			h := getFormatHandler(tc.yaml)
			diags := p.validateResources(h.ParseTemplate(tc.content), h, ValidationContext{Content: tc.content, IsYAML: tc.yaml, Registry: newTestRegistry()})
			if len(diags) != 5 {
				t.Fatalf("expected 5 diagnostics: %+v", diags)
			}
			has := func(parts ...string) bool {
				for _, d := range diags {
					ok := true
					for _, part := range parts {
						ok = ok && strings.Contains(d.Message, part)
					}
					if ok {
						return true
					}
				}
				return false
			}
			for _, parts := range [][]string{{"NoType"}, {"ALIYUN::TEST::Unknown"}, {"NoProps", "ImageId"}, {"NoProps", "InstanceType"}, {"BadProps", "InstanceType"}} {
				if !has(parts...) {
					t.Errorf("missing %v in %+v", parts, diags)
				}
			}
			for _, d := range diags {
				if strings.Contains(d.Message, "NoType") && d.Severity != protocol.DiagnosticSeverityError {
					t.Errorf("missing type severity: %+v", d)
				}
				if strings.Contains(d.Message, "Intrinsic") {
					t.Errorf("intrinsic should be accepted: %+v", d)
				}
			}
		})
	}
}

func TestLocalValueAndDatasourceValidation(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		yaml          bool
	}{
		{"YAML", "Locals:\n  Default: {}\n  EvalLocal:\n    Type: Eval\n  Datasource:\n    Type: DATASOURCE::VPC::Vpcs\n  GoodMacro:\n    Value: result\n  GoodDatasource:\n    Type: DATASOURCE::VPC::Vpcs\n    Properties: {}\n  Invalid: value\n", true},
		{"JSON", `{"Locals":{"Default":{},"EvalLocal":{"Type":"Eval"},"Datasource":{"Type":"DATASOURCE::VPC::Vpcs"},"GoodMacro":{"Value":"result"},"GoodDatasource":{"Type":"DATASOURCE::VPC::Vpcs","Properties":{}},"Invalid":"value"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := getFormatHandler(tc.yaml)
			got := (&ROSTemplateProvider{}).validateLocals(h.ParseTemplate(tc.content), h, ValidationContext{Content: tc.content, IsYAML: tc.yaml})
			if len(got) != 3 {
				t.Fatalf("diagnostics: %+v", got)
			}
			messages := ""
			for _, d := range got {
				messages += d.Message + "\n"
			}
			for _, name := range []string{"Default", "EvalLocal", "Datasource"} {
				if !strings.Contains(messages, name) {
					t.Errorf("missing %s: %s", name, messages)
				}
			}
			if strings.Contains(messages, "GoodMacro") || strings.Contains(messages, "GoodDatasource") {
				t.Fatalf("valid local flagged: %s", messages)
			}
		})
	}
}

func TestCollectNestedGetAttReferences(t *testing.T) {
	input := []interface{}{
		map[string]interface{}{"Fn::GetAtt": []interface{}{"First", "Id"}},
		map[string]interface{}{"child": map[string]interface{}{"Fn::GetAtt": "Second.Name"}},
		map[string]interface{}{"Fn::GetAtt": []interface{}{"Third"}},
		map[string]interface{}{"Fn::GetAtt": []interface{}{42, "ignored"}},
		map[string]interface{}{"Fn::GetAtt": ""},
	}
	got := collectGetAttPairs(input)
	want := []getAttPair{{resource: "First", attribute: "Id"}, {resource: "Second", attribute: "Name"}, {resource: "Third"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pairs=%+v want=%+v", got, want)
	}
}
