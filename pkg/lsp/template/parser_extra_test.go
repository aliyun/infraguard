package template

import (
	"reflect"
	"testing"
)

func TestParsedTemplateGettersHandleMissingAndInvalidSections(t *testing.T) {
	for _, pt := range []*ParsedTemplate{{}, ParseYAML("Resources: bad\nParameters: bad\nMappings: bad\nConditions: bad\nLocals: bad\n"), ParseJSON(`{"Resources":"bad","Parameters":"bad","Mappings":"bad","Conditions":"bad","Locals":"bad"}`)} {
		if pt.HasROSTemplateFormatVersion() || pt.GetROSTemplateFormatVersion() != "" || pt.GetResourceProperties("Missing") != nil || len(pt.GetResourceNames()) != 0 || len(pt.GetParameterNames()) != 0 || len(pt.GetConditionNames()) != 0 || len(pt.GetMappingNames()) != 0 {
			t.Fatalf("invalid sections: %+v", pt)
		}
	}
	for _, pt := range []*ParsedTemplate{ParseYAML("Resources:\n  Invalid: value\n  NoProperties: {}\n  Good:\n    Properties:\n      Name: test\n"), ParseJSON(`{"Resources":{"Invalid":"value","NoProperties":{},"Good":{"Properties":{"Name":"test"}}}}`)} {
		if pt.GetResourceProperties("Invalid") != nil || pt.GetResourceProperties("NoProperties") != nil || !reflect.DeepEqual(pt.GetResourceProperties("Good"), map[string]interface{}{"Name": "test"}) {
			t.Fatalf("resource properties: %+v", pt.Root)
		}
	}
}

func TestYAMLNodeLookupTraversesNestedMappingsAndSequences(t *testing.T) {
	pt := ParseYAML("Resources:\n  Thing:\n    Properties:\n      Items:\n        - first\n        - second\n")
	if pt.Err != nil {
		t.Fatal(pt.Err)
	}
	for _, line := range []int{0, 1, 2, 3, 4, 5} {
		if node := pt.FindYAMLNodeAtPosition(line, 0); node == nil {
			t.Errorf("missing node at line %d", line)
		}
	}
	if pt.FindYAMLNodeAtPosition(20, 0) != nil {
		t.Fatal("node found outside document")
	}
	if ParseJSON(`{"x":1}`).FindYAMLNodeAtPosition(0, 0) != nil {
		t.Fatal("JSON has YAML node")
	}
}

func TestTemplateParserRejectsNonObjectRoots(t *testing.T) {
	for _, tc := range []struct {
		name    string
		parse   func(string) *ParsedTemplate
		content string
	}{
		{"YAML sequence", ParseYAML, "- first\n- second\n"},
		{"YAML scalar", ParseYAML, "text\n"},
		{"JSON array", ParseJSON, `[1, 2]`},
		{"JSON scalar", ParseJSON, `"text"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.parse(tc.content)
			if got.Err == nil || got.Root != nil {
				t.Fatalf("non-object root: %+v", got)
			}
		})
	}
}

func TestMappingKeysWithMissingAndMalformedEntries(t *testing.T) {
	for _, pt := range []*ParsedTemplate{
		{},
		ParseJSON(`{"Mappings":{"Broken":"scalar","Region":{"East":{"Image":"x"},"West":{"Size":1,"Image":"y"},"Bad":"scalar"}}}`),
	} {
		if got := pt.GetMappingFirstKeys("Broken"); got != nil {
			t.Fatalf("first keys of malformed map: %v", got)
		}
		if got := pt.GetMappingSecondKeys("Broken", "East"); got != nil {
			t.Fatalf("second keys of malformed map: %v", got)
		}
		if got := pt.GetAllMappingSecondKeys("Broken"); got != nil {
			t.Fatalf("union of malformed map: %v", got)
		}
		if pt.Root != nil {
			if got := pt.GetMappingSecondKeys("Region", "Bad"); got != nil {
				t.Fatalf("malformed region: %v", got)
			}
			if got := pt.GetAllMappingSecondKeys("Region"); !reflect.DeepEqual(got, []string{"Image", "Size"}) {
				t.Fatalf("deduplicated mapping keys: %v", got)
			}
		}
	}
}
