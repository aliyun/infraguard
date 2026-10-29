package template

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestJSONAnalyzerHelpers(t *testing.T) {
	lines := []string{"{", `  "Type": "String",`, `  "Default": "hello",`, `  "Required": true`, "}"}
	if got := findJSONSiblingValue(lines, 2, `"Type"`); got != "String" {
		t.Fatalf("preceding sibling: %q", got)
	}
	if got := findJSONSiblingValue(lines, 1, `"Default"`); got != "hello" {
		t.Fatalf("following sibling: %q", got)
	}
	if got := findJSONSiblingValue(lines, 2, `"Missing"`); got != "" {
		t.Fatalf("unexpected sibling: %q", got)
	}
	if got := findJSONExistingKeysInObject(lines, 2, 0); !reflect.DeepEqual(got, []string{"Type", "Required"}) {
		t.Fatalf("object keys: %v", got)
	}
	if got := ExtractJSONTypeValue(lines[1]); got != "String" {
		t.Fatalf("type: %q", got)
	}
	for _, line := range []string{`"Other": "x"`, `"Type"`, `"Type": 3`, `"Type": "open`} {
		if got := ExtractJSONTypeValue(line); got != "" {
			t.Errorf("invalid type %q: %q", line, got)
		}
	}
	for _, tc := range []struct {
		line         string
		end          int
		quote, comma bool
	}{{`abc",`, 5, true, true}, {`abc"  }`, 4, true, false}, {`abc`, 3, false, false}} {
		end, quote, comma := FindJSONValueEnd(tc.line, 0)
		if end != tc.end || quote != tc.quote || comma != tc.comma {
			t.Errorf("value %q: %d %v %v", tc.line, end, quote, comma)
		}
	}
	if extractQuotedValue(` "value", `) != "value" || extractQuotedValue("bad") != "" {
		t.Fatal("quoted value extraction")
	}
}

func TestYAMLAnalyzerHelpers(t *testing.T) {
	lines := []string{"Parameters:", "  Name:", "    AssociationProperty: 'ECS::Instance'", "    AssociationPropertyMetadata:", "      Key: value", "      Other: yes", "    Type: String", "Next: value"}
	if CountIndent(lines[4]) != 6 || !isInsideAssociationPropertyMetadata(lines, 4, 6) || isInsideAssociationPropertyMetadata(lines, 6, 4) {
		t.Fatal("indentation or ancestor detection")
	}
	if got := findSiblingValue(lines, 3, 4, "AssociationProperty"); got != "ECS::Instance" {
		t.Fatalf("preceding sibling: %q", got)
	}
	if got := findSiblingValue(lines, 3, 4, "Type"); got != "String" {
		t.Fatalf("following sibling: %q", got)
	}
	if got := findSiblingValue(lines, 3, 4, "Missing"); got != "" {
		t.Fatalf("unexpected sibling: %q", got)
	}
	keys := findExistingKeysAtIndent(lines, 4, 6)
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, []string{"Other"}) {
		t.Fatalf("sibling keys: %v", keys)
	}
}

func TestJSONValueContexts(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		check      func([]string, int, int) *AnalysisContext
		want       ContextType
		prefix     string
	}{
		{"parameter type", `  "Type": "Str"`, checkJSONParameterTypeContext, ContextParameterTypeValue, "Str"},
		{"local type", `  "Type": "Mac"`, checkJSONLocalsTypeContext, ContextLocalsTypeValue, "Mac"},
		{"resource type", `  "Type": "ALIYUN::ECS"`, checkJSONTypeContext, ContextResourceType, "ALIYUN::ECS"},
		{"association", `  "AssociationProperty": "ALIYUN::ACR"`, checkJSONAssociationPropertyContext, ContextAssociationPropertyValue, "ALIYUN::ACR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.line
			cursor := len(line) - 1
			got := tc.check([]string{line}, 0, cursor)
			if got == nil || got.Type != tc.want || got.Prefix != tc.prefix {
				t.Fatalf("context: %+v", got)
			}
			if tc.check([]string{line}, 0, 0) != nil {
				t.Fatal("cursor before value should not match")
			}
			if tc.check([]string{`  "Type"`}, 0, 8) != nil {
				t.Fatal("incomplete key should not match")
			}
		})
	}
}

func TestJSONMultilineGetAttContext(t *testing.T) {
	lines := []string{`"Fn::GetAtt": [`, `  "Instance",`, `  "InstanceId"`, `]`}
	resource := checkJSONGetAttMultiline(lines, 0, 1, len(lines[1])-2)
	if resource == nil || resource.Type != ContextGetAttResource || resource.Prefix != "Instance" {
		t.Fatalf("resource context: %+v", resource)
	}
	attr := checkJSONGetAttMultiline(lines, 0, 2, len(lines[2])-1)
	if attr == nil || attr.Type != ContextGetAttAttribute || attr.GetAttResourceName != "Instance" || attr.Prefix != "InstanceId" {
		t.Fatalf("attribute context: %+v", attr)
	}
}

func TestGetAttIncompleteJSONAndMetadataKeyContext(t *testing.T) {
	elements, positions := extractJSONArrayElements(`"Instance", "Unfinished`, 10)
	if !reflect.DeepEqual(elements, []string{"Instance", "Unfinished"}) ||
		!reflect.DeepEqual(positions, []jsonArrayPos{{start: 11, end: 19}, {start: 23, end: 33}}) {
		t.Fatalf("partial array: %v %+v", elements, positions)
	}
	lines := []string{`"Fn::GetAtt": ["Instance",`, `  "InstanceId"`, `]`}
	ctx := checkJSONGetAttMultiline(lines, 0, 1, len(lines[1])-1)
	if ctx == nil || ctx.Type != ContextGetAttAttribute || ctx.GetAttResourceName != "Instance" || ctx.Prefix != "InstanceId" {
		t.Fatalf("inline first argument: %+v", ctx)
	}
	yaml := []string{"Parameters:", "  Name:", "    AssociationProperty: ECS::Instance", "    AssociationPropertyMetadata:", "      RegionId: value", "      Prefix"}
	ctx = checkAssociationPropertyMetadataContext(yaml, 5, len(yaml[5]), yaml[5], 6, "Name")
	if ctx == nil || ctx.Type != ContextAssociationPropertyMetadataKey || ctx.ResourceTypeName != "ECS::Instance" || ctx.CurrentParamName != "Name" || ctx.Prefix != "Prefix" {
		t.Fatalf("metadata context: %+v", ctx)
	}
	if !reflect.DeepEqual(ctx.ExistingKeys, []string{"RegionId"}) {
		t.Fatalf("existing metadata keys: %v", ctx.ExistingKeys)
	}
}

func TestDefinitionIgnoresInvalidPositionsAndIncompleteReferences(t *testing.T) {
	provider := &ROSTemplateProvider{}
	content := "Parameters:\n  Name:\n    Type: String\nOutputs:\n  Value: ${Name}\n"
	for _, tc := range []struct{ line, col int }{{-1, 0}, {99, 0}, {4, -1}} {
		if got := provider.Definition(DefinitionContext{Content: content, Line: tc.line, Col: tc.col, IsYAML: true}); got != nil {
			t.Errorf("invalid position %+v: %+v", tc, got)
		}
	}
	for _, tc := range []struct {
		line string
		col  int
		want string
	}{
		{"before ${Name} after", 12, "Name"},
		{"before ${Name} after", 100, ""},
		{"before ${Name", 12, ""},
		{"before ${} after", 9, ""},
	} {
		if got := extractParamRefAtCursor(tc.line, tc.col); got != tc.want {
			t.Errorf("reference %q at %d: got %q, want %q", tc.line, tc.col, got, tc.want)
		}
	}
}

func TestEditorOperationsRejectNegativeColumn(t *testing.T) {
	provider := &ROSTemplateProvider{}
	for _, yaml := range []bool{true, false} {
		content := "Value: !Ref Name"
		if !yaml {
			content = `{"Ref": "Name"}`
		}
		if got := AnalyzePosition(content, 0, -1, yaml); got.Type != ContextUnknown {
			t.Fatalf("analysis for negative column: %+v", got)
		}
		if got := provider.Complete(CompletionContext{Content: content, Line: 0, Col: -1, IsYAML: yaml}); got != nil {
			t.Fatalf("completion for negative column: %+v", got)
		}
		if got := provider.Hover(HoverContext{Content: content, Line: 0, Col: -1, IsYAML: yaml}); got != nil {
			t.Fatalf("hover for negative column: %+v", got)
		}
	}
}

func TestYAMLResourceTypeStaysWithinResource(t *testing.T) {
	lines := []string{
		"Parameters:", "  First:", "    Type: String",
		"Resources:", "  First:", "    Properties:", "      Nested:", "        Type: nested",
		"  Second:", "    Type: ALIYUN::ECS::Instance",
	}
	if got := findResourceType(lines, "First"); got != "" {
		t.Fatalf("missing type picked up another field or resource: %q", got)
	}
	if got := AnalyzePosition(strings.Join(lines, "\n"), 6, len(lines[6]), true); got.ResourceTypeName != "" {
		t.Fatalf("completion used another resource's type: %+v", got)
	}
	if got := findResourceType(lines, "Second"); got != "ALIYUN::ECS::Instance" {
		t.Fatalf("second resource type: %q", got)
	}
	lines = append(lines[:8], append([]string{"    Type: ALIYUN::ECS::Disk"}, lines[8:]...)...)
	if got := findResourceType(lines, "First"); got != "ALIYUN::ECS::Disk" {
		t.Fatalf("direct type after nested properties: %q", got)
	}
	if got := AnalyzePosition(strings.Join(lines, "\n"), 6, len(lines[6]), true); got.ResourceTypeName != "ALIYUN::ECS::Disk" {
		t.Fatalf("completion missed direct resource type: %+v", got)
	}
}

func TestYAMLNestedPropertyHelpers(t *testing.T) {
	lines := []string{"Resources:", "  Instance:", "    Properties:", "      Rules:", "        - Rule:", "          Metadata:", "", "            Name: value", "  Other:", "    Type: example"}
	if got := findPropertyPath(lines, 7, 4); !reflect.DeepEqual(got, []string{"Rules", "Metadata"}) {
		t.Fatalf("nested list property path: %v", got)
	}
	for _, tc := range []struct{ line, want string }{
		{"- Name: value", "Name"}, {"!Ref Name", ""}, {"Fn::Join: []", ""}, {"- Fn::Join: []", ""}, {": value", ""}, {"unfinished", ""},
	} {
		if got := extractLineKey(tc.line); got != tc.want {
			t.Errorf("line key %q: got %q, want %q", tc.line, got, tc.want)
		}
	}
	if got := findExistingProperties([]string{"Resources:", "  Instance:"}, 1); got != nil {
		t.Fatalf("properties without a Properties block: %v", got)
	}
	if got := findLocalTypeYAML([]string{"Locals:", "  A:", "    Value: x", "  B:", "    Type: Eval"}, 2, "A"); got != "" {
		t.Fatalf("local picked up sibling type: %q", got)
	}
}

func TestYAMLGetAttCompletionContexts(t *testing.T) {
	for _, tc := range []struct {
		name             string
		lines            []string
		line             int
		want             ContextType
		resource, prefix string
	}{
		{"short resource", []string{"Resources:", "  Example:", "    Value: !GetAtt Ins"}, 2, ContextGetAttResource, "", "Ins"},
		{"short attribute", []string{"Resources:", "  Example:", "    Value: !GetAtt Instance.Ins"}, 2, ContextGetAttAttribute, "Instance", "Ins"},
		{"short empty", []string{"Resources:", "  Example:", "    Value: !GetAtt"}, 2, ContextGetAttResource, "", ""},
		{"list resource", []string{"Resources:", "  Example:", "    Fn::GetAtt:", "      - Ins"}, 3, ContextGetAttResource, "", "Ins"},
		{"list attribute", []string{"Resources:", "  Example:", "    Fn::GetAtt:", "      - Instance", "      - Ins"}, 4, ContextGetAttAttribute, "Instance", "Ins"},
		{"long inline", []string{"Resources:", "  Example:", "    Fn::GetAtt: Ins"}, 2, ContextGetAttResource, "", "Ins"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := checkGetAttContext(tc.lines, tc.line, len(tc.lines[tc.line]))
			if got == nil || got.Type != tc.want || got.GetAttResourceName != tc.resource || got.Prefix != tc.prefix || got.ResourceName != "Example" {
				t.Fatalf("context: %+v", got)
			}
		})
	}
	if got := checkGetAttContext([]string{"  - value"}, 0, len("  - value")); got != nil {
		t.Fatalf("unrelated list: %+v", got)
	}
}

func TestYAMLFindInMapCompletionContexts(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		lines                []string
		want                 ContextType
		mapping, key, prefix string
	}{
		{"short empty", []string{"Value: !FindInMap"}, ContextFindInMapMapName, "", "", ""},
		{"short map", []string{"Value: !FindInMap [Reg"}, ContextFindInMapMapName, "", "", "Reg"},
		{"short first", []string{"Value: !FindInMap [Regions, Ea"}, ContextFindInMapFirstKey, "Regions", "", "Ea"},
		{"short second", []string{"Value: !FindInMap [Regions, East, Im"}, ContextFindInMapSecondKey, "Regions", "East", "Im"},
		{"inline long", []string{"Fn::FindInMap: [Regions, East, Im"}, ContextFindInMapSecondKey, "Regions", "East", "Im"},
		{"long map", []string{"Fn::FindInMap:", "  - Reg"}, ContextFindInMapMapName, "", "", "Reg"},
		{"long first", []string{"Fn::FindInMap:", "  - Regions", "  - Ea"}, ContextFindInMapFirstKey, "Regions", "", "Ea"},
		{"long second", []string{"Fn::FindInMap:", "  - Regions", "  - East", "  - Im"}, ContextFindInMapSecondKey, "Regions", "East", "Im"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := len(tc.lines) - 1
			got := checkFindInMapContext(tc.lines, line, len(tc.lines[line]))
			if got == nil || got.Type != tc.want || got.FindInMapMapName != tc.mapping || got.FindInMapFirstKey != tc.key || got.Prefix != tc.prefix {
				t.Fatalf("context: %+v", got)
			}
		})
	}
}

func TestJSONFindInMapCompletionContexts(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		lines                []string
		want                 ContextType
		mapping, key, prefix string
	}{
		{"inline empty", []string{`"Fn::FindInMap": [`}, ContextFindInMapMapName, "", "", ""},
		{"inline map", []string{`"Fn::FindInMap": ["Reg`}, ContextFindInMapMapName, "", "", "Reg"},
		{"inline first", []string{`"Fn::FindInMap": ["Regions", "Ea`}, ContextFindInMapFirstKey, "Regions", "", "Ea"},
		{"inline second", []string{`"Fn::FindInMap": ["Regions", "East", "Im`}, ContextFindInMapSecondKey, "Regions", "East", "Im"},
		{"multiline map", []string{`"Fn::FindInMap": [`, `  "Reg`}, ContextFindInMapMapName, "", "", "Reg"},
		{"multiline first", []string{`"Fn::FindInMap": [`, `  "Regions",`, `  "Ea`}, ContextFindInMapFirstKey, "Regions", "", "Ea"},
		{"multiline second", []string{`"Fn::FindInMap": [`, `  "Regions",`, `  "East",`, `  "Im`}, ContextFindInMapSecondKey, "Regions", "East", "Im"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := len(tc.lines) - 1
			got := checkJSONFindInMapContext(tc.lines, line, len(tc.lines[line]))
			if got == nil || got.Type != tc.want || got.FindInMapMapName != tc.mapping || got.FindInMapFirstKey != tc.key || got.Prefix != tc.prefix {
				t.Fatalf("context: %+v", got)
			}
		})
	}
}

func TestJSONDefinitionTargetPositions(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lines     []string
		line, col int
		want      string
		getAtt    bool
	}{
		{"ref inside", []string{`"Ref": "Instance"`}, 0, 11, "Instance", false},
		{"ref outside", []string{`"Ref": "Instance"`}, 0, 2, "", false},
		{"GetAtt resource", []string{`"Fn::GetAtt": ["Instance", "Id"]`}, 0, 19, "Instance", true},
		{"GetAtt attribute", []string{`"Fn::GetAtt": ["Instance", "Id"]`}, 0, 29, "", false},
		{"adjacent GetAtt attribute", []string{`"Fn::GetAtt": ["Other", "Id"],`, `"Fn::GetAtt": ["Instance", "Id"]`}, 1, 29, "", false},
		{"GetAtt multiline resource", []string{`"Fn::GetAtt": [`, `  "Instance",`, `  "Id"`, `]`}, 1, 5, "Instance", true},
		{"GetAtt multiline attribute", []string{`"Fn::GetAtt": [`, `  "Instance",`, `  "Id"`, `]`}, 2, 5, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, resource := extractDefinitionTargetJSON(tc.lines[tc.line], tc.lines, tc.line, tc.col)
			if name != tc.want || resource != tc.getAtt {
				t.Fatalf("target %q resource=%v", name, resource)
			}
		})
	}
}

func TestJSONResourceTypeContextFindsEnclosingResource(t *testing.T) {
	lines := []string{`{`, `  "Resources": {`, `    "Earlier": {},`, ``, `    "Instance": {`, `      "Type": "ALIYUN::ECS`, `    }`, `  }`, `}`}
	got := checkJSONTypeContext(lines, 5, len(lines[5]))
	if got == nil || got.Type != ContextResourceType || got.ResourceName != "Instance" || got.Prefix != "ALIYUN::ECS" {
		t.Fatalf("resource context: %+v", got)
	}
	if got := checkJSONTypeContext([]string{`"Type"`}, 0, 6); got != nil {
		t.Fatalf("missing colon accepted: %+v", got)
	}
}

func TestHasPropertiesSectionWithinSameResource(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		typeLine      int
		want          bool
	}{
		{"YAML following", "Resources:\n  Instance:\n    Type: X\n\n    Properties:\n      Name: n\n", 2, true},
		{"YAML preceding", "Resources:\n  Instance:\n    Properties: {}\n\n    Type: X\n", 4, true},
		{"JSON following", "{\n  \"Instance\": {\n    \"Type\": \"X\",\n    \"Properties\": {}\n  }\n}", 2, true},
		{"next resource", "Resources:\n  First:\n    Type: X\n  Second:\n    Properties: {}\n", 2, false},
		{"previous resource", "Resources:\n  First:\n    Properties: {}\n  Second:\n    Type: X\n", 4, false},
		{"invalid line", "Resources:\n", 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasPropertiesSection(tc.content, tc.typeLine); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestYAMLRefCompletionContexts(t *testing.T) {
	for _, tc := range []struct {
		name, line, prefix string
		col                int
		want               bool
	}{
		{"long form", "      Ref: MyParam", "MyParam", 18, true},
		{"short form", "    Value: !Ref MyParam", "MyParam", 23, true},
		{"short form empty", "    Value: !Ref", "", 15, true},
		{"before value", "      Ref: MyParam", "", 3, false},
		{"unrelated", "      Name: MyParam", "", 19, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{"Resources:", "  Instance:", tc.line}
			got := checkRefContext(lines, 2, tc.col)
			if !tc.want {
				if got != nil {
					t.Fatalf("unexpected context: %+v", got)
				}
				return
			}
			if got == nil || got.Type != ContextRefValue || got.ResourceName != "Instance" || got.Prefix != tc.prefix {
				t.Fatalf("context: %+v", got)
			}
		})
	}
}

func TestJSONGetAttInlineCompletionPositions(t *testing.T) {
	for _, tc := range []struct {
		name, line       string
		col              int
		want             ContextType
		resource, prefix string
		absent           bool
	}{
		{"before array", `"Fn::GetAtt": ["Instance"]`, 4, 0, "", "", true},
		{"first value", `"Fn::GetAtt": ["Instance", "InstanceId"]`, 20, ContextGetAttResource, "", "Inst", false},
		{"second value", `"Fn::GetAtt": ["Instance", "InstanceId"]`, 33, ContextGetAttAttribute, "Instance", "Insta", false},
		{"empty array", `"Fn::GetAtt": [ `, 16, ContextGetAttResource, "", "", false},
		{"after first", `"Fn::GetAtt": ["Instance", `, 27, ContextGetAttAttribute, "Instance", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := checkJSONGetAttInline(tc.line, []string{tc.line}, 0, tc.col)
			if tc.absent {
				if got != nil {
					t.Fatalf("unexpected context: %+v", got)
				}
				return
			}
			if got == nil || got.Type != tc.want || got.GetAttResourceName != tc.resource || got.Prefix != tc.prefix {
				t.Fatalf("context: %+v", got)
			}
		})
	}
}

func TestYAMLDefinitionTargetPositions(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		col        int
		want       string
		getAtt     bool
	}{
		{"long ref", "    Ref: Name", 11, "Name", false},
		{"short ref", "    Value: !Ref Name", 20, "Name", false},
		{"ref before value", "    Ref: Name", 2, "", false},
		{"short attribute resource", "    Value: !GetAtt Thing.Id", 22, "Thing", true},
		{"short attribute name", "    Value: !GetAtt Thing.Id", 27, "", false},
		{"short resource only", "    Value: !GetAtt Thing", 24, "Thing", true},
		{"list item", "      - Thing", 10, "Thing", true},
		{"long inline", "    Fn::GetAtt: Thing", 20, "Thing", true},
		{"unrelated", "    Name: value", 10, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, isResource := extractDefinitionTargetYAML(tc.line, tc.col)
			if name != tc.want || isResource != tc.getAtt {
				t.Fatalf("name=%q resource=%v", name, isResource)
			}
		})
	}
}

func TestYAMLConditionFunctionCompletionPositions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lines  []string
		want   ContextType
		prefix string
		absent bool
	}{
		{"short if first", []string{"Value: !If [Con"}, ContextFnIfConditionName, "Con", false},
		{"short if second", []string{"Value: !If [Condition, value"}, 0, "", true},
		{"short and second", []string{"Value: !And [Condition, Oth"}, ContextFnIfConditionName, "Oth", false},
		{"short not empty", []string{"Value: !Not"}, ContextFnIfConditionName, "", false},
		{"long if first", []string{"Fn::If:", "  - Con"}, ContextFnIfConditionName, "Con", false},
		{"long if second", []string{"Fn::If:", "  - Condition", "  - value"}, 0, "", true},
		{"long or second", []string{"Fn::Or:", "  - Condition", "  - Oth"}, ContextFnIfConditionName, "Oth", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := len(tc.lines) - 1
			got := checkConditionFnContext(tc.lines, line, len(tc.lines[line]))
			if tc.absent {
				if got != nil {
					t.Fatalf("unexpected context: %+v", got)
				}
				return
			}
			if got == nil || got.Type != tc.want || got.Prefix != tc.prefix {
				t.Fatalf("context: %+v", got)
			}
		})
	}
}

func TestJSONConditionFunctionCompletionPositions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lines  []string
		prefix string
		absent bool
	}{
		{"inline if first", []string{`"Fn::If": ["Con`}, "Con", false},
		{"inline if second", []string{`"Fn::If": ["Condition", "value`}, "", true},
		{"inline and second", []string{`"Fn::And": ["Condition", "Oth`}, "Oth", false},
		{"multiline if first", []string{`"Fn::If": [`, ``, `  "Con`}, "Con", false},
		{"multiline if second", []string{`"Fn::If": [`, `  "Condition",`, `  "value`}, "", true},
		{"multiline or second", []string{`"Fn::Or": [`, `  "Condition",`, `  "Oth`}, "Oth", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := len(tc.lines) - 1
			got := checkJSONConditionFnContext(tc.lines, line, len(tc.lines[line]))
			if tc.absent {
				if got != nil {
					t.Fatalf("unexpected context: %+v", got)
				}
				return
			}
			if got == nil || got.Type != ContextFnIfConditionName || got.Prefix != tc.prefix {
				t.Fatalf("context: %+v", got)
			}
		})
	}
}

func TestJSONOutputAndLocalValueContexts(t *testing.T) {
	for _, section := range []string{"Outputs", "Locals"} {
		content := "{\n  \"" + section + "\": {\n    \"Item\": {\n      \"Value\": \"text\"\n    }\n  }\n}"
		lines := strings.Split(content, "\n")
		got := AnalyzePosition(content, 3, len(lines[3])-1, false)
		if got.Type != ContextPropertyValue {
			t.Errorf("%s value context: %+v", section, got)
		}
	}
	for _, section := range []string{"Outputs", "Locals"} {
		content := "{\n  \"" + section + "\": {\n  }\n}"
		got := AnalyzePosition(content, 1, len("  \""+section+"\": {"), false)
		if got.Type != ContextUnknown {
			t.Errorf("%s section without item: %+v", section, got)
		}
	}
	for _, pos := range []int{-1, 4} {
		if got := analyzeJSONPosition("{}", pos, 0); got.Type != ContextUnknown {
			t.Errorf("invalid line %d: %+v", pos, got)
		}
	}
}

func TestJSONRefCompletionWithIncompleteInput(t *testing.T) {
	for _, input := range []string{`"Ref"`, `"Ref": 123`, `"Ref": `} {
		if got := checkJSONRefContext([]string{input}, 0, len(input)); got != nil {
			t.Errorf("incomplete reference %q: %+v", input, got)
		}
	}
	input := `"Ref": "Instance"`
	if got := checkJSONRefContext([]string{input}, 0, 3); got != nil {
		t.Fatalf("reference key is not value: %+v", got)
	}
	if got := checkJSONRefContext([]string{input}, 0, len(input)+10); got == nil || got.Type != ContextRefValue || got.Prefix != "Instance" {
		t.Fatalf("clamped reference: %+v", got)
	}
}

func TestJSONValueCompletionClampsColumnsAndRejectsMalformedValues(t *testing.T) {
	for _, tc := range []struct {
		key   string
		check func([]string, int, int) *AnalysisContext
		kind  ContextType
	}{
		{"Type", checkJSONParameterTypeContext, ContextParameterTypeValue},
		{"Type", checkJSONLocalsTypeContext, ContextLocalsTypeValue},
		{"Type", checkJSONTypeContext, ContextResourceType},
		{"AssociationProperty", checkJSONAssociationPropertyContext, ContextAssociationPropertyValue},
	} {
		key := `"` + tc.key + `"`
		for _, line := range []string{key, key + `: 123`} {
			if got := tc.check([]string{line}, 0, len(line)); got != nil {
				t.Errorf("malformed %q: %+v", line, got)
			}
		}
		line := key + `: "Value"`
		if got := tc.check([]string{line}, 0, len(line)+10); got == nil || got.Type != tc.kind || got.Prefix != "Value" {
			t.Errorf("clamped %q: %+v", line, got)
		}
	}
}

func TestYAMLCompletionContextBoundaries(t *testing.T) {
	for _, section := range []struct {
		name string
		find func([]string, int, int) (string, bool)
	}{{"Outputs", findOutputContext}, {"Locals", findLocalsContext}} {
		lines := []string{section.name + ":", "  Example:", "", "    Value: text", "Other:", "  Example:", "    Value: text"}
		if name, ok := section.find(lines, 3, 4); !ok || name != "Example" {
			t.Errorf("%s context: %q %v", section.name, name, ok)
		}
		if name, ok := section.find(lines, 6, 4); ok || name != "" {
			t.Errorf("%s crossed section: %q %v", section.name, name, ok)
		}
		if name, ok := section.find([]string{"    Value: text"}, 0, 4); ok || name != "" {
			t.Errorf("%s without parent: %q %v", section.name, name, ok)
		}
	}
	for _, find := range []func([]string, int, int) []string{findExistingSiblingKeys, findExistingParameterAttrs, findExistingLocalsAttrs} {
		if got := find([]string{"    Value: text"}, 0, 4); got != nil {
			t.Errorf("siblings without parent: %v", got)
		}
		lines := []string{"  Parent:", "", "    First: yes", "", "    Second: yes", "  Next:"}
		if got := find(lines, 4, 4); !reflect.DeepEqual(got, []string{"First", "Second"}) {
			t.Errorf("siblings: %v", got)
		}
	}
	if isInsideSection([]string{"    Value: text"}, 0, 4, "Outputs") {
		t.Fatal("line without section matched")
	}
	if findParentKeyIndent([]string{"  Parent:", "    Value: yes"}, 1, 4, "Other") != -1 {
		t.Fatal("wrong parent matched")
	}
}

func TestJSONCompletionContextBoundaries(t *testing.T) {
	for _, find := range []func([]string, int) []string{findExistingParameterAttrsJSON, findExistingLocalsAttrsJSON, findExistingPropertiesJSON} {
		if got := find([]string{`    "Value": "x"`}, 0); got != nil {
			t.Errorf("keys without enclosing object: %v", got)
		}
	}
	for _, tc := range []struct {
		name string
		find func([]string, int) string
	}{
		{"parameter", findParameterNameJSON}, {"local", findLocalNameJSON}, {"resource", findResourceNameJSON},
	} {
		lines := []string{"{", "  {", "", "    \"Type\": \"String\""}
		if got := tc.find(lines, 3); got != "" {
			t.Errorf("%s without named parent: %q", tc.name, got)
		}
	}
	for _, line := range []string{"value:", "value[", "value{", "value}", "value,"} {
		if _, _, ok := FindJSONKeyEditRange(line, len(line)); ok {
			t.Errorf("%q should not be a quoted key", line)
		}
	}
	if _, _, ok := FindJSONKeyEditRange(`"key": 123`, len(`"key": 123`)); ok {
		t.Fatal("value mistaken for key")
	}
}

func TestYAMLPrefixesAndEnclosingResources(t *testing.T) {
	for _, tc := range []struct {
		line string
		col  int
		want string
	}{
		{"  Type", 99, "Type"}, {"  Type: Value", 0, ""}, {"  Type: Value", 7, ""}, {"  Type: Value", 99, "Value"},
	} {
		if got := extractValuePrefix(tc.line, tc.col); got != tc.want {
			t.Errorf("prefix %q at %d: %q", tc.line, tc.col, got)
		}
	}
	if got := extractPropertyValuePrefix("  Name: value", 100, "Name"); got != "value" {
		t.Fatalf("property value prefix: %q", got)
	}
	if got := extractPropertyValuePrefix("  Other: value", 100, "Name"); got != "Other: value" {
		t.Fatalf("nested value prefix: %q", got)
	}
	lines := []string{"Resources:", "  Instance:", "", "    Properties:", "      Name: value", "Outputs:", "  Value: text"}
	if got := findEnclosingResourceName(lines, 4); got != "Instance" {
		t.Fatalf("resource name: %q", got)
	}
	if got := findEnclosingResourceName(lines, 6); got != "" {
		t.Fatalf("resource crossed sections: %q", got)
	}
	if name, section := findResourceContext([]string{"    Property: value"}, 0, 4); name != "" || section != "" {
		t.Fatalf("resource without section: %q %q", name, section)
	}
	for _, col := range []int{0, 99} {
		if got := parseFindInMapShortForm("[Map, Key]", 1, col); got.Type != ContextFindInMapMapName || got.Prefix != "" {
			t.Errorf("invalid map cursor %d: %+v", col, got)
		}
	}
}

func TestLocalPropertyCompletionRequiresKnownType(t *testing.T) {
	yamlLines := []string{"Locals:", "  Example:", "", "    Properties:", "      Name: value", "Other:", "  Missing:"}
	if got := findLocalTypeYAML(yamlLines, 4, "Example"); got != "" {
		t.Fatalf("missing local type: %q", got)
	}
	if got := findLocalTypeYAML(yamlLines, 6, "Example"); got != "" {
		t.Fatalf("local crossed section: %q", got)
	}
	if got := analyzeLocalsPropertiesContext(yamlLines, 4, len(yamlLines[4]), yamlLines[4], 6); got != nil {
		t.Fatalf("properties without local type: %+v", got)
	}
	jsonLines := []string{"{", `  "Locals": {`, `    "Example": {`, `      "Properties": {`, `        "Name": "value"`, "      }", "    }", "  }", "}"}
	if got := findLocalTypeJSON(jsonLines, "Example"); got != "" {
		t.Fatalf("missing JSON local type: %q", got)
	}
	if got := checkJSONLocalsPropertiesContext(jsonLines, 4, len(jsonLines[4])); got != nil {
		t.Fatalf("JSON properties without local type: %+v", got)
	}
}
