package template

import (
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/lsp/schema"
)

func TestValidationDiagnosticsWhenTranslationsAreMissing(t *testing.T) {
	oldLanguage := i18n.GetLanguage()
	i18n.SetLanguage("en")
	messages := i18n.Msg()
	oldDiagnostics := messages.LSPDiag
	t.Cleanup(func() { messages.LSPDiag = oldDiagnostics; i18n.SetLanguage(oldLanguage) })
	messages.LSPDiag.InvalidFormatVersion = ""
	messages.LSPDiag.UnknownTopLevelKey = ""
	messages.LSPDiag.DidYouMean = ""
	messages.LSPDiag.ParamMissingType = ""
	messages.LSPDiag.ParamInvalidType = ""
	messages.LSPDiag.ParamAttrTypeMismatch = ""
	messages.LSPDiag.LocalMissingValue = ""
	messages.LSPDiag.LocalDatasourceMissingProperties = ""
	messages.LSPDiag.MissingType = ""
	messages.LSPDiag.UnknownResourceType = ""
	messages.LSPDiag.MissingRequiredProperty = ""
	messages.LSPDiag.TypeMismatch = ""
	messages.LSPDiag.MappingsInvalidStructure = ""
	messages.LSPDiag.ConditionsInvalidExpression = ""
	messages.LSPDiag.UndefinedCondition = ""
	messages.LSPDiag.AssocMetaUndefinedParamRef = ""
	messages.LSPDiag.AssocMetaValueTypeMismatch = ""
	messages.LSPDiag.UndefinedRef = ""
	messages.LSPDiag.UndefinedGetAttResource = ""
	messages.LSPDiag.UndefinedGetAttAttribute = ""
	messages.LSPDiag.AllowedValuesViolation = ""
	messages.LSPDiag.RangeViolation = ""
	messages.LSPDiag.LengthViolation = ""
	messages.LSPDiag.PatternViolation = ""
	content := `ROSTemplateFormatVersion: invalid
Resourcs: {}
Parameters:
  MissingType: {}
  InvalidType:
    Type: BadType
    MinLength: wrong
  Repository:
    Type: String
    AssociationProperty: ALIYUN::ACR::Namespace::Name
    AssociationPropertyMetadata:
      Status: 42
      RegionId: ${MissingParameter}
Locals:
  MissingValue: {Type: Macro}
  MissingProperties: {Type: 'DATASOURCE::VPC::Vpcs'}
Resources:
  MissingResourceType: {}
  UnknownType: {Type: 'ALIYUN::TEST::Unknown'}
  Instance:
    Type: ALIYUN::ECS::Instance
    Condition: MissingCondition
    Properties:
      ImageId: 123
Mappings:
  Bad: scalar
  BadNested:
    East: scalar
Conditions:
  BadCondition: scalar
Outputs:
  BadRef:
    Value: !Ref MissingTarget
  BadResource:
    Value: !GetAtt MissingResource.Id
  BadAttribute:
    Value: !GetAtt Instance.NoSuchAttribute
`
	registry := newTestRegistry()
	if err := registry.LoadAssociationProperties(); err != nil {
		t.Fatal(err)
	}
	diagnostics := (&ROSTemplateProvider{}).Validate(ValidationContext{Content: content, IsYAML: true, Registry: registry})
	var text strings.Builder
	for _, diag := range diagnostics {
		text.WriteString(diag.Message)
		text.WriteByte('\n')
	}
	for _, want := range []string{
		"Invalid ROSTemplateFormatVersion", "Unknown top-level key", "did you mean",
		"missing required Type", "invalid Type value", "expected type", "missing required Value",
		"missing Properties", "Unknown resource type", "missing required property",
		"two-level map", "must use a condition function", "undefined target", "undefined resource", "not a valid attribute",
		"Undefined condition", "references undefined parameter", "AssociationPropertyMetadata of parameter",
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("missing fallback %q in diagnostics:\n%s", want, text.String())
		}
	}
	minValue, minLength := 2.0, 3
	for _, tc := range []struct {
		value      interface{}
		constraint schema.Constraint
		want       string
	}{
		{"bad", schema.Constraint{AllowedValues: []interface{}{"good"}}, "not in allowed values"},
		{1, schema.Constraint{MinValue: &minValue}, "out of range"},
		{[]interface{}{1}, schema.Constraint{MinLength: &minLength}, "length"},
		{"bad", schema.Constraint{AllowedPattern: "good"}, "does not match pattern"},
	} {
		diags := (&ROSTemplateProvider{}).validatePropertyConstraints(getFormatHandler(true), ValidationContext{Content: content, IsYAML: true}, "Instance", "ImageId", tc.value, &schema.Property{Constraints: &tc.constraint})
		if len(diags) != 1 || !strings.Contains(diags[0].Message, tc.want) {
			t.Errorf("constraint fallback %q: %+v", tc.want, diags)
		}
	}
}
