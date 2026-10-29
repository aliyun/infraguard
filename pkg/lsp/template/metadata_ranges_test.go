package template

import (
	"strings"
	"testing"
)

func TestMetadataDiagnosticRangesStayInParameter(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		yaml          bool
		keyLine       int
		refLine       int
	}{
		{"yaml", "Parameters:\n  First:\n    Type: String\n    AssociationPropertyMetadata:\n      Region: ${Other}\n  Second:\n    Type: String\n    AssociationPropertyMetadata:\n      Region: ${First}\n", true, 8, 8},
		{"json", "{\n  \"Parameters\": {\n    \"First\": {\n      \"Type\": \"String\",\n      \"AssociationPropertyMetadata\": {\n        \"Region\": \"${Other}\"\n      }\n    },\n    \"Second\": {\n      \"Type\": \"String\",\n      \"AssociationPropertyMetadata\": {\n        \"Region\": \"${First}\"\n      }\n    }\n  }\n}", false, 11, 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := getFormatHandler(tc.yaml)
			lines := strings.Split(tc.content, "\n")
			key := h.FindAssociationPropertyMetadataKeyRange(tc.content, "Second", "Region")
			ref := h.FindParamRefInMetadataRange(tc.content, "Second", "First")
			if key.Start.Line != tc.keyLine || lines[key.Start.Line][key.Start.Character:key.End.Character] != "Region" {
				t.Fatalf("key range: %+v", key)
			}
			if ref.Start.Line != tc.refLine || lines[ref.Start.Line][ref.Start.Character:ref.End.Character] != "${First}" {
				t.Fatalf("reference range: %+v", ref)
			}
			other := h.FindParamRefInMetadataRange(tc.content, "First", "Other")
			if other.Start.Line >= ref.Start.Line || lines[other.Start.Line][other.Start.Character:other.End.Character] != "${Other}" {
				t.Fatalf("first parameter reference: %+v", other)
			}
			missing := h.FindParamRefInMetadataRange(tc.content, "First", "First")
			if missing.Start.Line >= ref.Start.Line {
				t.Fatalf("missing reference matched a different parameter: %+v", missing)
			}
		})
	}
}

func TestYAMLMissingDiagnosticRangesStayWithinSection(t *testing.T) {
	content := "Metadata:\n  Region: ignored\n\nParameters:\n  First:\n    Type: String\n    AssociationPropertyMetadata:\n      Region: ${First}\n\n  Second:\n    Type: Number\nOutputs:\n  Other:\n    Value: ignored\n"
	for _, find := range []func() bool{
		func() bool { return isZeroRange(findParameterRangeYAML(content, "Missing")) },
		func() bool { return isZeroRange(findLocalsRangeYAML(content, "Missing")) },
		func() bool { return isZeroRange(findMappingsRangeYAML(content, "Missing")) },
		func() bool { return isZeroRange(findConditionsRangeYAML(content, "Missing")) },
		func() bool { return isZeroRange(findConditionValueRangeYAML(content, "Outputs", "Other")) },
	} {
		if !find() {
			t.Error("missing entry received a location")
		}
	}
	fallback := findParameterAttrValueRangeYAML(content, "First", "Missing")
	if fallback.Start.Line != 4 {
		t.Fatalf("missing attribute should fall back to its parameter: %+v", fallback)
	}
	meta := findAssociationPropertyMetadataKeyRangeYAML(content, "First", "Missing")
	if meta.Start.Line != 6 {
		t.Fatalf("missing metadata key should fall back to metadata block: %+v", meta)
	}
	ref := findParamRefInMetadataRangeYAML(content, "First", "Missing")
	if ref.Start.Line != 6 {
		t.Fatalf("missing metadata reference should fall back to metadata block: %+v", ref)
	}
}

func TestJSONMissingDiagnosticRangesAndAttributeValue(t *testing.T) {
	content := "{\n  \"Parameters\": {\n    \"First\": {\n      \"Type\": \"String\",   \n      \"AssociationPropertyMetadata\": {\n        \"Region\": \"${First}\"\n      }\n    }\n  },\n  \"Resources\": {\n    \"Item\": {\n      \"Type\": \"ALIYUN::ECS::Instance\"\n    }\n  }\n}"
	for _, find := range []func() bool{
		func() bool { return isZeroRange(findParameterRangeJSON(content, "Missing")) },
		func() bool { return isZeroRange(findResourceRangeJSON(content, "Missing")) },
		func() bool { return isZeroRange(findMappingsRangeJSON(content, "Missing")) },
		func() bool { return isZeroRange(findConditionsRangeJSON(content, "Missing")) },
		func() bool { return isZeroRange(findLocalsRangeJSON(content, "Missing")) },
		func() bool { return isZeroRange(findConditionValueRangeJSON(content, "Resources", "Item")) },
	} {
		if !find() {
			t.Error("missing JSON entry received a location")
		}
	}
	lines := strings.Split(content, "\n")
	value := findParameterAttrValueRangeJSON(content, "First", "Type")
	if value.Start.Line != 3 || lines[value.Start.Line][value.Start.Character:value.End.Character] != `"String"` {
		t.Fatalf("type range: %+v", value)
	}
	fallback := findResourcePropertyValueRangeJSON(content, "Item", "Missing")
	if fallback.Start.Line != 10 {
		t.Fatalf("missing property should fall back to resource: %+v", fallback)
	}
}
