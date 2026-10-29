package template

import (
	"strings"
	"testing"
)

func TestDuplicateYAMLKeysAreScoped(t *testing.T) {
	content := `Resources:
  First:
    Type: ALIYUN::ECS::Instance
    Properties:
      Name: one
      Name: two
  Second:
    Type: ALIYUN::ECS::Instance
    Properties:
      Name: three
List:
  - Name: a
    Value: one
    Value: duplicate
  - Name: b
    Value: two
`
	diags := validateDuplicateKeys(ValidationContext{Content: content, IsYAML: true})
	if len(diags) != 2 {
		t.Fatalf("duplicate diagnostics: %+v", diags)
	}
	if diags[0].Range.Start.Line != 5 || !strings.Contains(diags[0].Message, "Name") || diags[1].Range.Start.Line != 13 || !strings.Contains(diags[1].Message, "Value") {
		t.Fatalf("diagnostic positions: %+v", diags)
	}
}

func TestTemplateKeyAndNodeLocations(t *testing.T) {
	content := "Description: example\nResources:\n  Instance:\n    Type: ALIYUN::ECS::Instance\n"
	parsed := ParseYAML(content)
	if parsed.FindYAMLNodeAtPosition(3, 4) == nil || parsed.FindYAMLNodeAtPosition(50, 0) != nil {
		t.Fatal("unexpected YAML node location")
	}
	if got := FindKeyLineInYAML(content, "Resources"); got != 1 {
		t.Fatalf("YAML key line %d", got)
	}
	if got := FindKeyLineInYAML(content, "Instance"); got != -1 {
		t.Fatalf("nested key treated as top-level: %d", got)
	}
	line, start, end := FindKeyRangeInYAML(content, "Resources")
	if line != 1 || start != 0 || end != len("Resources") {
		t.Fatalf("range: %d %d %d", line, start, end)
	}
	if got := FindKeyLineInJSON("{\n  \"Resources\": {}\n}", "Resources"); got != 1 {
		t.Fatalf("JSON key line %d", got)
	}
}
