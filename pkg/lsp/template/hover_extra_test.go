package template

import (
	"strings"
	"testing"
)

func TestResourcePropertyHover(t *testing.T) {
	registry := newTestRegistry()
	provider := &ROSTemplateProvider{}
	for _, tc := range []struct {
		name, content string
		line, col     int
		yaml          bool
	}{
		{"YAML", "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  Example:\n    Type: ALIYUN::ECS::Instance\n    Properties:\n      InstanceType: ecs.g6.large\n", 5, 10, true},
		{"JSON", "{\n  \"ROSTemplateFormatVersion\": \"2015-09-01\",\n  \"Resources\": {\n    \"Example\": {\n      \"Type\": \"ALIYUN::ECS::Instance\",\n      \"Properties\": {\n        \"InstanceType\": \"ecs.g6.large\"\n      }\n    }\n  }\n}", 6, 12, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := provider.Hover(HoverContext{Content: tc.content, Line: tc.line, Col: tc.col, IsYAML: tc.yaml, Registry: registry})
			if got == nil || !strings.Contains(got.Contents, "InstanceType") || !strings.Contains(got.Contents, "instance type") {
				t.Fatalf("hover: %+v", got)
			}
		})
	}
}

func TestHoverIntrinsicAndResourceBlock(t *testing.T) {
	provider := &ROSTemplateProvider{}
	yaml := getFormatHandler(true)
	json := getFormatHandler(false)
	for _, tc := range []struct {
		line    string
		handler FormatHandler
	}{{"DependsOn: Other", yaml}, {`"DependsOn": "Other"`, json}} {
		got := provider.hoverResourceBlock(tc.line, tc.handler)
		if got == nil || !strings.Contains(got.Contents, "DependsOn") {
			t.Fatalf("resource block hover: %+v", got)
		}
	}
	if got := provider.hoverResourceBlock("Unknown: x", yaml); got != nil {
		t.Fatalf("unknown block hover: %+v", got)
	}
	if got := provider.hoverIntrinsicFunction("Value: !Join [',', [a, b]]"); got == nil || !strings.Contains(got.Contents, "Fn::Join") {
		t.Fatalf("intrinsic hover: %+v", got)
	}
	if got := provider.hoverIntrinsicFunction("hello: world"); got != nil {
		t.Fatalf("unexpected hover: %+v", got)
	}
}

func TestHoverAssociationAndMapping(t *testing.T) {
	registry := newTestRegistry()
	if err := registry.LoadAssociationProperties(); err != nil {
		t.Fatal(err)
	}
	provider := &ROSTemplateProvider{}
	for _, tc := range []struct {
		line    string
		handler FormatHandler
	}{
		{"AssociationProperty: ALIYUN::ACR::Namespace::Name", getFormatHandler(true)},
		{`"AssociationProperty": "ALIYUN::ACR::Namespace::Name"`, getFormatHandler(false)},
	} {
		got := provider.hoverAssociationPropertyValue(tc.line, tc.handler, HoverContext{Registry: registry})
		if got == nil || !strings.Contains(got.Contents, "Namespace") || !strings.Contains(got.Contents, "Status") {
			t.Fatalf("association hover: %+v", got)
		}
	}
	if got := provider.hoverAssociationPropertyValue("AssociationProperty: unknown", getFormatHandler(true), HoverContext{Registry: registry}); got != nil {
		t.Fatalf("unknown association: %+v", got)
	}
	if got := provider.hoverMappingsBlock("Regions:", getFormatHandler(true)); got == nil || !strings.Contains(got.Contents, "Regions") {
		t.Fatalf("mapping hover: %+v", got)
	}
}

func TestGetAttAttributeHoverFormats(t *testing.T) {
	registry := newTestRegistry()
	provider := &ROSTemplateProvider{}
	for _, tc := range []struct {
		name, content string
		yaml          bool
		line          int
	}{
		{"YAML short", "Resources:\n  Instance:\n    Type: ALIYUN::ECS::Instance\nOutputs:\n  Id:\n    Value: !GetAtt Instance.InstanceId\n", true, 5},
		{"YAML list", "Resources:\n  Instance:\n    Type: ALIYUN::ECS::Instance\nOutputs:\n  Id:\n    Value:\n      Fn::GetAtt:\n        - Instance\n        - InstanceId\n", true, 8},
		{"JSON inline", "{\n  \"Resources\": {\"Instance\": {\"Type\": \"ALIYUN::ECS::Instance\"}},\n  \"Outputs\": {\"Id\": {\"Value\": {\"Fn::GetAtt\": [\"Instance\", \"InstanceId\"]}}}\n}", false, 2},
		{"JSON list", "{\n  \"Resources\": {\"Instance\": {\"Type\": \"ALIYUN::ECS::Instance\"}},\n  \"Outputs\": {\"Id\": {\"Value\": {\"Fn::GetAtt\": [\n    \"Instance\",\n    \"InstanceId\"\n  ]}}}\n}", false, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := HoverContext{Content: tc.content, Line: tc.line, IsYAML: tc.yaml, Registry: registry}
			got := provider.hoverGetAttAttribute(&AnalysisContext{GetAttResourceName: "Instance"}, getFormatHandler(tc.yaml), ctx)
			if got == nil || !strings.Contains(got.Contents, "InstanceId") || !strings.Contains(got.Contents, "The instance ID") {
				t.Fatalf("hover: %+v", got)
			}
			if provider.hoverGetAttAttribute(&AnalysisContext{GetAttResourceName: "Missing"}, getFormatHandler(tc.yaml), ctx) != nil {
				t.Fatal("unknown resource has hover")
			}
		})
	}
}

func TestNestedPropertyAndLocalTypeHover(t *testing.T) {
	provider := &ROSTemplateProvider{}
	ctx := HoverContext{Registry: newTestRegistry()}
	for _, tc := range []struct {
		name, line string
		yaml       bool
	}{
		{"YAML", "IpProtocol: tcp", true}, {"JSON", `"IpProtocol": "tcp"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := getFormatHandler(tc.yaml)
			analysis := &AnalysisContext{ResourceTypeName: "ALIYUN::ECS::SecurityGroup", PropertyName: "SecurityGroupIngress", PropertyPath: []string{"SecurityGroupIngress"}}
			hover := provider.hoverResourceProperty(tc.line, handler, analysis, ctx)
			if hover == nil || !strings.Contains(hover.Contents, "IP protocol") || !strings.Contains(hover.Contents, "tcp") {
				t.Fatalf("nested hover: %+v", hover)
			}
			value := provider.hoverPropertyValue(tc.line, handler, analysis, ctx)
			if value == nil || !strings.Contains(value.Contents, "IP protocol") {
				t.Fatalf("value hover: %+v", value)
			}
			fallback := provider.hoverPropertyValue("Unknown: value", handler, analysis, ctx)
			if fallback == nil || !strings.Contains(fallback.Contents, "Ingress rules") {
				t.Fatalf("parent hover: %+v", fallback)
			}
		})
	}
	for _, tc := range []struct{ line, want string }{{"Type: DATASOURCE::VPC::Vpcs", "Datasource resource type"}, {"Type: Macro", "Macro"}} {
		got := provider.hoverLocalsTypeValue(tc.line, getFormatHandler(true))
		if got == nil || !strings.Contains(got.Contents, tc.want) {
			t.Errorf("%s: %+v", tc.line, got)
		}
	}
	if got := provider.hoverLocalsTypeValue("Type: unknown", getFormatHandler(true)); got != nil {
		t.Fatalf("unknown local type: %+v", got)
	}
}

func TestHoverFromEditorPosition(t *testing.T) {
	registry := newTestRegistry()
	if err := registry.LoadAssociationProperties(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, content, marker, want string
		line                        int
	}{
		{"resource block", "Resources:\n  Example:\n    Type: ALIYUN::ECS::Instance\n    DependsOn: Other\n", "DependsOn", "DependsOn", 3},
		{"association", "Parameters:\n  Name:\n    Type: String\n    AssociationProperty: ALIYUN::ACR::Namespace::Name\n", "ALIYUN::ACR", "Namespace", 3},
		{"mapping", "Mappings:\n  Regions:\n    East:\n      Image: image\n", "Regions", "Regions", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := strings.Split(tc.content, "\n")[tc.line]
			col := strings.Index(line, tc.marker) + len(tc.marker)
			ctx := HoverContext{Content: tc.content, Line: tc.line, Col: col, IsYAML: true, Registry: registry}
			got := (&ROSTemplateProvider{}).Hover(ctx)
			if got == nil || !strings.Contains(got.Contents, tc.want) {
				t.Fatalf("hover: %+v; context %+v", got, AnalyzePosition(tc.content, tc.line, col, true))
			}
		})
	}
	if got := (&ROSTemplateProvider{}).Hover(HoverContext{Content: "Resources:", Line: 1, IsYAML: true, Registry: registry}); got != nil {
		t.Fatalf("hover outside document: %+v", got)
	}
}

func TestHoverUnknownValues(t *testing.T) {
	provider := &ROSTemplateProvider{}
	handler := getFormatHandler(true)
	ctx := HoverContext{Registry: newTestRegistry()}
	if got := provider.hoverTopLevel("Unknown: value", handler); got != nil {
		t.Fatalf("unknown top-level key: %+v", got)
	}
	for _, line := range []string{"Type:", "Type: Unknown::Type"} {
		if got := provider.hoverResourceType(line, handler, ctx); got != nil {
			t.Fatalf("unknown resource type %q: %+v", line, got)
		}
	}
	for _, line := range []string{"Unknown: value", "Missing: value"} {
		if got := provider.hoverParameterProperty(line, handler); got != nil {
			t.Fatalf("unknown parameter property: %+v", got)
		}
	}
	if got := provider.hoverLocalsProperty("Unknown: value", handler); got != nil {
		t.Fatalf("unknown locals property: %+v", got)
	}
	if got := provider.hoverParameterTypeValue("Type: Unknown", handler); got != nil {
		t.Fatalf("unknown parameter type: %+v", got)
	}
	if got := provider.hoverMappingsBlock("", handler); got != nil {
		t.Fatalf("unknown mapping block: %+v", got)
	}
	if got := provider.hoverResourceProperty("Name: value", handler, &AnalysisContext{}, ctx); got != nil {
		t.Fatalf("property without resource type: %+v", got)
	}
	analysis := &AnalysisContext{ResourceTypeName: "ALIYUN::ECS::Instance", PropertyPath: []string{"Unknown"}}
	if got := provider.hoverPropertyValue("Name: value", handler, analysis, ctx); got != nil {
		t.Fatalf("unknown property value: %+v", got)
	}
	if got := provider.hoverGetAttAttribute(&AnalysisContext{}, handler, ctx); got != nil {
		t.Fatalf("GetAtt without resource: %+v", got)
	}
	ctx.Content = "Resources:\n  Instance:\n    Type: ALIYUN::ECS::Instance\n"
	analysis.GetAttResourceName = "Instance"
	ctx.Line = -1
	if got := provider.hoverGetAttAttribute(analysis, handler, ctx); got != nil {
		t.Fatalf("GetAtt invalid line: %+v", got)
	}
}
