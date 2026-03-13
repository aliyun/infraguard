package template

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/lsp/protocol"
	"github.com/aliyun/infraguard/pkg/lsp/schema"
	. "github.com/smartystreets/goconvey/convey"
)

func newTestRegistry() *schema.Registry {
	r := &schema.Registry{}
	sf := &schema.SchemaFile{
		Version: "2026-01-01",
		ResourceTypes: map[string]*schema.ResourceType{
			"ALIYUN::ECS::Instance": {
				Description: "An ECS instance",
				Properties: map[string]*schema.Property{
					"InstanceType": {Type: "String", Required: true, Updatable: false, Description: "The instance type"},
					"ImageId":      {Type: "String", Required: true, Updatable: true, Description: "The image ID"},
					"ZoneId":       {Type: "String", Required: false, Updatable: false, Description: "The zone ID"},
				},
				Attributes: map[string]*schema.Attribute{
					"InstanceId": {Description: "The instance ID"},
				},
			},
			"ALIYUN::ECS::VPC": {
				Description: "A VPC",
				Properties: map[string]*schema.Property{
					"CidrBlock": {Type: "String", Required: false, Description: "CIDR block"},
				},
			},
			"DATASOURCE::VPC::Vpcs": {
				Description: "Query VPCs",
				Properties: map[string]*schema.Property{
					"VpcName":  {Type: "String", Required: false, Description: "VPC name"},
					"VpcId":    {Type: "String", Required: false, Description: "VPC ID"},
					"IsDefault": {Type: "Boolean", Required: false, Description: "Whether default VPC"},
				},
			},
			"ALIYUN::ECS::Disk": {
				Description: "A disk",
				Properties: map[string]*schema.Property{
					"DiskName":  {Type: "string", Required: true, Description: "Disk name"},
					"Size":      {Type: "integer", Required: true, Description: "Disk size in GB"},
					"Encrypted": {Type: "boolean", Required: false, Description: "Whether encrypted"},
					"Tags":      {Type: "list", Required: false, Description: "Tags"},
					"Options":   {Type: "map", Required: false, Description: "Options"},
				},
			},
		},
	}
	data, _ := json.Marshal(sf)
	_ = r.LoadFromData(data)
	return r
}

func TestComplete_TopLevel(t *testing.T) {
	Convey("Given a ROSTemplateProvider and a template with some top-level keys", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
`

		ctx := CompletionContext{
			Content:  content,
			Line:     4,
			Col:      0,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return top-level block completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
		})

		Convey("It should exclude existing keys", func() {
			for _, item := range items {
				So(item.Label, ShouldNotEqual, "ROSTemplateFormatVersion")
				So(item.Label, ShouldNotEqual, "Resources")
			}
		})

		Convey("It should include remaining blocks", func() {
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["Parameters"], ShouldBeTrue)
			So(labels["Outputs"], ShouldBeTrue)
			So(labels["Description"], ShouldBeTrue)
		})
	})
}

func TestComplete_ResourceType(t *testing.T) {
	Convey("Given a ROSTemplateProvider at resource Type position", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS
`

		ctx := CompletionContext{
			Content:  content,
			Line:     3,
			Col:      22,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return resource type completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
		})

		Convey("It should filter by prefix", func() {
			for _, item := range items {
				So(item.Label, ShouldStartWith, "ALIYUN::ECS")
			}
		})
	})
}

func TestComplete_ResourceProperties(t *testing.T) {
	Convey("Given a ROSTemplateProvider at resource Properties position", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType: ecs.c6.large
      
`

		ctx := CompletionContext{
			Content:  content,
			Line:     6,
			Col:      6,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return property completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
		})

		Convey("It should exclude already existing properties", func() {
			for _, item := range items {
				So(item.Label, ShouldNotEqual, "InstanceType")
			}
		})

		Convey("Required properties should come first", func() {
			// ImageId is required, ZoneId is not
			imageIdx := -1
			zoneIdx := -1
			for i, item := range items {
				if item.Label == "ImageId" {
					imageIdx = i
				}
				if item.Label == "ZoneId" {
					zoneIdx = i
				}
			}
			if imageIdx >= 0 && zoneIdx >= 0 {
				So(imageIdx, ShouldBeLessThan, zoneIdx)
			}
		})
	})
}

func TestComplete_PropertyValueWithRegularPrefix(t *testing.T) {
	Convey("Given a ROSTemplateProvider typing a regular value in a property", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType: ecs.c6.large
`

		ctx := CompletionContext{
			Content:  content,
			Line:     5,
			Col:      33,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should NOT return completions for a regular value like an IP or instance type", func() {
			So(items, ShouldBeEmpty)
		})
	})
}

func TestComplete_PropertyValueEmpty(t *testing.T) {
	Convey("Given a ROSTemplateProvider at an empty property value position", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType: 
`

		ctx := CompletionContext{
			Content:  content,
			Line:     5,
			Col:      20,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions with snippet and command", func() {
			So(len(items), ShouldBeGreaterThan, 0)

			var refShort, refLong *protocol.CompletionItem
			for i := range items {
				if items[i].Label == "!Ref" {
					refShort = &items[i]
				}
				if items[i].Label == "Ref" {
					refLong = &items[i]
				}
			}
			So(refShort, ShouldNotBeNil)
			So(refShort.TextEdit, ShouldNotBeNil)
			So(refShort.TextEdit.NewText, ShouldEqual, "!Ref $0")
			So(refShort.InsertTextFormat, ShouldEqual, protocol.InsertTextFormatSnippet)
			So(refShort.Command, ShouldNotBeNil)
			So(refShort.Command.Command, ShouldEqual, "editor.action.triggerSuggest")

			So(refLong, ShouldNotBeNil)
			So(refLong.TextEdit, ShouldNotBeNil)
			So(refLong.TextEdit.NewText, ShouldEqual, "Ref: $0")
			So(refLong.InsertTextFormat, ShouldEqual, protocol.InsertTextFormatSnippet)
			So(refLong.Command, ShouldNotBeNil)
			So(refLong.Command.Command, ShouldEqual, "editor.action.triggerSuggest")
		})
	})
}

func TestComplete_PropertyValueWithBangPrefix(t *testing.T) {
	Convey("Given a ROSTemplateProvider typing '!' in a property value", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType: !
`

		ctx := CompletionContext{
			Content:  content,
			Line:     5,
			Col:      21,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
		})
	})
}

func TestComplete_PropertyValueWithFunctionNamePrefix(t *testing.T) {
	Convey("Given a ROSTemplateProvider typing 'Re' (start of Ref) in a property value on a separate line", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType:
        Re
`

		ctx := CompletionContext{
			Content:  content,
			Line:     6,
			Col:      10,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions since 'Re' matches 'Ref'", func() {
			So(len(items), ShouldBeGreaterThan, 0)
		})
	})
}

func TestComplete_PropertyValueNoPseudoParameters(t *testing.T) {
	Convey("Given a ROSTemplateProvider at a property value position", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType:
`

		ctx := CompletionContext{
			Content:  content,
			Line:     5,
			Col:      20,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should NOT include pseudo-parameters like ALIYUN::StackName", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			for _, item := range items {
				So(item.Label, ShouldNotStartWith, "ALIYUN::")
			}
		})
	})
}

func TestComplete_OutputBlockOnNameLine(t *testing.T) {
	Convey("Given cursor after ':' on an output name line in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Outputs:
  OutputName:
`

		ctx := CompletionContext{
			Content:  content,
			Line:     2,
			Col:      14, // after ':'
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return Value with newline+indent snippet using relative indentation", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundValue bool
			for _, item := range items {
				if item.Label == "Value" {
					foundValue = true
					So(item.InsertText, ShouldEqual, "\n  Value: $0")
					So(item.Command, ShouldNotBeNil)
				}
			}
			So(foundValue, ShouldBeTrue)
		})
	})
}

func TestComplete_JSONOutputBlockOnNameLine(t *testing.T) {
	Convey("Given cursor after ':' on an output name line in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Outputs": {
    "OutputName":
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     3,
			Col:      18, // after ':'
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return Value with object snippet using relative indentation", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundValue bool
			for _, item := range items {
				if item.Label == "Value" {
					foundValue = true
					So(item.InsertText, ShouldEqual, " {\n  \"Value\": $0\n}")
					So(item.Command, ShouldNotBeNil)
				}
			}
			So(foundValue, ShouldBeTrue)
		})
	})
}

func TestComplete_OutputBlock(t *testing.T) {
	Convey("Given a ROSTemplateProvider at output block level in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
Outputs:
  OutputName:
    Va
`

		ctx := CompletionContext{
			Content:  content,
			Line:     6,
			Col:      6,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return output block keys matching prefix", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundValue bool
			for _, item := range items {
				if item.Label == "Value" {
					foundValue = true
					So(item.InsertText, ShouldEqual, "Value: $0")
					So(item.InsertTextFormat, ShouldEqual, protocol.InsertTextFormatSnippet)
					So(item.Command, ShouldNotBeNil)
					So(item.Command.Command, ShouldEqual, "editor.action.triggerSuggest")
				}
			}
			So(foundValue, ShouldBeTrue)
		})
	})
}

func TestComplete_OutputBlockAllKeys(t *testing.T) {
	Convey("Given a ROSTemplateProvider at output block level with no prefix", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Outputs:
  OutputName:
    
`

		ctx := CompletionContext{
			Content:  content,
			Line:     3,
			Col:      4,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return Value, Description, Condition", func() {
			So(len(items), ShouldEqual, 3)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["Value"], ShouldBeTrue)
			So(labels["Description"], ShouldBeTrue)
			So(labels["Condition"], ShouldBeTrue)
		})
	})
}

func TestComplete_OutputBlockExcludeExisting(t *testing.T) {
	Convey("Given an output that already has Value", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Outputs:
  OutputName:
    Value: !Ref MyECS
    
`

		ctx := CompletionContext{
			Content:  content,
			Line:     4,
			Col:      4,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should exclude Value from completions", func() {
			for _, item := range items {
				So(item.Label, ShouldNotEqual, "Value")
			}
			So(len(items), ShouldEqual, 2)
		})
	})
}

func TestComplete_JSONOutputBlock(t *testing.T) {
	Convey("Given a ROSTemplateProvider at output block level in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Outputs": {
    "OutputName": {
      ""
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     4,
			Col:      7,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return output block keys", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundValue bool
			for _, item := range items {
				if item.Label == "Value" {
					foundValue = true
					So(item.Command, ShouldNotBeNil)
					So(item.Command.Command, ShouldEqual, "editor.action.triggerSuggest")
				}
			}
			So(foundValue, ShouldBeTrue)
		})
	})
}

func TestComplete_OutputsValue(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Outputs Value position in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
Outputs:
  OutputName:
    Value:
      F
`

		ctx := CompletionContext{
			Content:  content,
			Line:     7,
			Col:      7,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var hasRef, hasFn bool
			for _, item := range items {
				if item.Label == "Ref" || item.Label == "!Ref" {
					hasRef = true
				}
				if strings.HasPrefix(item.Label, "Fn::") || strings.HasPrefix(item.Label, "!") {
					hasFn = true
				}
			}
			So(hasRef, ShouldBeTrue)
			So(hasFn, ShouldBeTrue)
		})
	})
}

func TestComplete_OutputsValueInline(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Outputs Value inline position in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
Outputs:
  OutputName:
    Value: R
`

		ctx := CompletionContext{
			Content:  content,
			Line:     6,
			Col:      12,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions matching prefix R", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var hasRef bool
			for _, item := range items {
				if item.Label == "Ref" || item.Label == "!Ref" {
					hasRef = true
				}
			}
			So(hasRef, ShouldBeTrue)
		})
	})
}

func TestComplete_JSONOutputsValue(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Outputs Value position in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Resources": {
    "MyECS": {
      "Type": "ALIYUN::ECS::Instance"
    }
  },
  "Outputs": {
    "OutputName": {
      "Value": {
        ""
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     10,
			Col:      9,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var hasRef bool
			for _, item := range items {
				if item.Label == "Ref" {
					hasRef = true
				}
			}
			So(hasRef, ShouldBeTrue)
		})
	})
}

func TestComplete_ParameterProperties(t *testing.T) {
	Convey("Given a ROSTemplateProvider at parameter property position", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  MyParam:
    Type: String
    
`

		ctx := CompletionContext{
			Content:  content,
			Line:     4,
			Col:      4,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return parameter property completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
		})

		Convey("It should exclude already existing properties", func() {
			for _, item := range items {
				So(item.Label, ShouldNotEqual, "Type")
			}
		})

		Convey("It should include remaining parameter attributes", func() {
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["Default"], ShouldBeTrue)
			So(labels["AllowedValues"], ShouldBeTrue)
			So(labels["Description"], ShouldBeTrue)
			So(labels["Label"], ShouldBeTrue)
			So(labels["NoEcho"], ShouldBeTrue)
			So(labels["AssociationProperty"], ShouldBeTrue)
			So(labels["Required"], ShouldBeTrue)
			So(labels["Placeholder"], ShouldBeTrue)
		})
	})
}

func TestComplete_ParameterTypeValue(t *testing.T) {
	Convey("Given a ROSTemplateProvider at parameter Type value position", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  MyParam:
    Type: 
`

		ctx := CompletionContext{
			Content:  content,
			Line:     3,
			Col:      10,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return parameter type value completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
		})

		Convey("It should include all valid type values", func() {
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["String"], ShouldBeTrue)
			So(labels["Number"], ShouldBeTrue)
			So(labels["Boolean"], ShouldBeTrue)
			So(labels["Json"], ShouldBeTrue)
			So(labels["CommaDelimitedList"], ShouldBeTrue)
			So(labels["ALIYUN::OOS::Parameter::Value"], ShouldBeTrue)
			So(labels["ALIYUN::OOS::SecretParameter::Value"], ShouldBeTrue)
		})
	})
}

func TestComplete_ParameterTypeValueWithPrefix(t *testing.T) {
	Convey("Given a ROSTemplateProvider typing a parameter Type value", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  MyParam:
    Type: Str
`

		ctx := CompletionContext{
			Content:  content,
			Line:     3,
			Col:      13,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should filter by prefix", func() {
			So(len(items), ShouldEqual, 1)
			So(items[0].Label, ShouldEqual, "String")
		})
	})
}

func TestHover_ParameterProperty(t *testing.T) {
	Convey("Given a ROSTemplateProvider at a parameter property key", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  MyParam:
    Type: String
    Default: hello
`

		ctx := HoverContext{
			Content:  content,
			Line:     4,
			Col:      8,
			IsYAML:   true,
			Registry: registry,
		}

		result := provider.Hover(ctx)

		Convey("It should return hover content for the parameter property", func() {
			So(result, ShouldNotBeNil)
			So(result.Contents, ShouldContainSubstring, "Default")
		})
	})
}

func TestHover_ParameterTypeValue(t *testing.T) {
	Convey("Given a ROSTemplateProvider at a parameter Type value", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  MyParam:
    Type: String
`

		ctx := HoverContext{
			Content:  content,
			Line:     3,
			Col:      12,
			IsYAML:   true,
			Registry: registry,
		}

		result := provider.Hover(ctx)

		Convey("It should return hover content for the type value", func() {
			So(result, ShouldNotBeNil)
			So(result.Contents, ShouldContainSubstring, "String")
		})
	})
}

func TestValidate_MissingFormatVersion(t *testing.T) {
	Convey("Given a template without ROSTemplateFormatVersion", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report an error", func() {
			So(len(diags), ShouldBeGreaterThan, 0)
			found := false
			for _, d := range diags {
				if d.Message == "Missing required field: ROSTemplateFormatVersion" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestValidate_InvalidFormatVersion(t *testing.T) {
	Convey("Given a template with invalid format version", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2020-01-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report an error about invalid version", func() {
			found := false
			for _, d := range diags {
				if len(d.Message) > 0 && d.Message[:7] == "Invalid" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestValidate_UnknownTopLevelKey(t *testing.T) {
	Convey("Given a template with unknown top-level key", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resourcs:
  MyECS:
    Type: ALIYUN::ECS::Instance
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report a warning about unknown key", func() {
			found := false
			for _, d := range diags {
				if len(d.Message) > 7 && d.Message[:7] == "Unknown" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestValidate_MissingRequiredProperties(t *testing.T) {
	Convey("Given a template with missing required properties", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      ZoneId: cn-hangzhou-a
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report missing required properties", func() {
			missingCount := 0
			for _, d := range diags {
				if len(d.Message) > 8 && d.Message[:8] == "Resource" {
					missingCount++
				}
			}
			So(missingCount, ShouldBeGreaterThan, 0)
		})
	})
}

func TestValidate_PropertyTypeMismatch_YAML(t *testing.T) {
	Convey("Given a YAML template with property type mismatches", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyDisk:
    Type: ALIYUN::ECS::Disk
    Properties:
      DiskName: 123
      Size: not_a_number
      Encrypted: wrong
      Tags: not_a_list
      Options: not_a_map
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report type mismatch for DiskName (expected string, got number)", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "DiskName") && strings.Contains(d.Message, "string") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})

		Convey("It should report type mismatch for Size (expected integer, got string)", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "Size") && strings.Contains(d.Message, "integer") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})

		Convey("It should report type mismatch for Encrypted (expected boolean, got string)", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "Encrypted") && strings.Contains(d.Message, "boolean") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})

		Convey("It should report type mismatch for Tags (expected list, got string)", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "Tags") && strings.Contains(d.Message, "list") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})

		Convey("It should report type mismatch for Options (expected map, got string)", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "Options") && strings.Contains(d.Message, "map") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})

		Convey("Diagnostic range should point to the property value, not the resource name", func() {
			for _, d := range diags {
				if strings.Contains(d.Message, "Size") && strings.Contains(d.Message, "integer") {
					So(d.Range.Start.Line, ShouldEqual, 6)
					break
				}
			}
		})
	})
}

func TestValidate_PropertyTypeValid_YAML(t *testing.T) {
	Convey("Given a YAML template with correct property types", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyDisk:
    Type: ALIYUN::ECS::Disk
    Properties:
      DiskName: my-disk
      Size: 100
      Encrypted: true
      Tags:
        - Key: env
          Value: prod
      Options:
        AutoRenew: true
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should NOT report any type mismatch errors", func() {
			typeMismatchCount := 0
			for _, d := range diags {
				if strings.Contains(d.Message, "expected type") {
					typeMismatchCount++
				}
			}
			So(typeMismatchCount, ShouldEqual, 0)
		})
	})
}

func TestValidate_PropertyTypeMismatch_JSON(t *testing.T) {
	Convey("Given a JSON template with property type mismatches", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Resources": {
    "MyDisk": {
      "Type": "ALIYUN::ECS::Disk",
      "Properties": {
        "DiskName": 123,
        "Size": "not_a_number",
        "Encrypted": "wrong"
      }
    }
  }
}`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   false,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report type mismatch for DiskName (expected string, got number)", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "DiskName") && strings.Contains(d.Message, "string") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})

		Convey("It should report type mismatch for Size (expected integer, got string)", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "Size") && strings.Contains(d.Message, "integer") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})

		Convey("It should report type mismatch for Encrypted (expected boolean, got string)", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "Encrypted") && strings.Contains(d.Message, "boolean") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestValidate_PropertyTypeSkipsIntrinsicFunctions_YAML(t *testing.T) {
	Convey("Given a YAML template with intrinsic functions as property values", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyDisk:
    Type: ALIYUN::ECS::Disk
    Properties:
      DiskName: !Ref MyParam
      Size:
        Ref: SizeParam
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should NOT report type mismatch for intrinsic function values", func() {
			typeMismatchCount := 0
			for _, d := range diags {
				if strings.Contains(d.Message, "expected type") {
					typeMismatchCount++
				}
			}
			So(typeMismatchCount, ShouldEqual, 0)
		})
	})
}

func TestValidate_ParameterAttrTypeMismatch(t *testing.T) {
	Convey("Given a template with parameter attribute type mismatch", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  MyParam:
    Type: String
    MinLength: invalid_string
    MaxLength: 10
    NoEcho: not_boolean
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report type mismatch for MinLength (expected Integer, got String)", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "MinLength") && strings.Contains(d.Message, "Integer") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})

		Convey("It should report type mismatch for NoEcho (expected Boolean, got String)", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "NoEcho") && strings.Contains(d.Message, "Boolean") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})

		Convey("It should NOT report error for valid MaxLength", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "MaxLength") {
					found = true
				}
			}
			So(found, ShouldBeFalse)
		})
	})
}

func TestValidate_ParameterInvalidType(t *testing.T) {
	Convey("Given a template with invalid parameter Type value", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  MyParam:
    Type: InvalidType
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report invalid Type value", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "InvalidType") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestValidate_ParameterMissingType(t *testing.T) {
	Convey("Given a template with parameter missing Type field", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  MyParam:
    Default: hello
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report missing Type field", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "MyParam") && strings.Contains(d.Message, "Type") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestValidate_ParameterValidConfig(t *testing.T) {
	Convey("Given a template with correctly typed parameter attributes", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  MyParam:
    Type: String
    Default: hello
    MinLength: 1
    MaxLength: 100
    NoEcho: true
    AllowedValues:
      - hello
      - world
    Description: A test parameter
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should not report any parameter validation errors", func() {
			paramDiags := 0
			for _, d := range diags {
				if strings.Contains(d.Message, "MyParam") {
					paramDiags++
				}
			}
			So(paramDiags, ShouldEqual, 0)
		})
	})
}

func TestValidate_JSONParameterAttrTypeMismatch(t *testing.T) {
	Convey("Given a JSON template with parameter attribute type mismatch", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Parameters": {
    "MyParam": {
      "Type": "String",
      "MinLength": "asdf"
    }
  }
}`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   false,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report type mismatch for MinLength", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "MinLength") && strings.Contains(d.Message, "Integer") {
					found = true
					So(d.Range.Start.Line, ShouldBeGreaterThan, 0)
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestValidate_JSONParameterInvalidType(t *testing.T) {
	Convey("Given a JSON template with invalid parameter Type value", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Parameters": {
    "MyParam": {
      "Type": "InvalidType"
    }
  }
}`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   false,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report invalid Type value", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "InvalidType") {
					found = true
					So(d.Range.Start.Line, ShouldBeGreaterThan, 0)
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestHover_TopLevel(t *testing.T) {
	Convey("Given a ROSTemplateProvider at a top-level key", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
`

		ctx := HoverContext{
			Content:  content,
			Line:     1,
			Col:      5,
			IsYAML:   true,
			Registry: registry,
		}

		result := provider.Hover(ctx)

		Convey("It should return hover content", func() {
			So(result, ShouldNotBeNil)
			So(result.Contents, ShouldContainSubstring, "Resources")
		})
	})
}

func TestHover_ResourceType(t *testing.T) {
	Convey("Given a ROSTemplateProvider at a resource Type value", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
`

		ctx := HoverContext{
			Content:  content,
			Line:     3,
			Col:      15,
			IsYAML:   true,
			Registry: registry,
		}

		result := provider.Hover(ctx)

		Convey("It should return resource type description", func() {
			So(result, ShouldNotBeNil)
			So(result.Contents, ShouldContainSubstring, "ECS instance")
		})
	})
}

// --- JSON Completion Tests ---

func TestComplete_JSONTopLevel(t *testing.T) {
	Convey("Given a ROSTemplateProvider at top-level in a JSON template", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Re"
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     2,
			Col:      6,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return top-level block completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var found bool
			for _, item := range items {
				if item.Label == "Resources" {
					found = true
					break
				}
			}
			So(found, ShouldBeTrue)
		})

		Convey("It should exclude already existing keys", func() {
			for _, item := range items {
				So(item.Label, ShouldNotEqual, "ROSTemplateFormatVersion")
			}
		})
	})
}

func TestComplete_JSONResourceProperties(t *testing.T) {
	Convey("Given a ROSTemplateProvider at resource properties in a JSON template", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Resources": {
    "MyECS": {
      "Type": "ALIYUN::ECS::Instance",
      "Properties": {
        "InstanceType": "ecs.c6.large",
        "Im"
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     7,
			Col:      12,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return resource property completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
		})

		Convey("It should exclude already existing property keys", func() {
			for _, item := range items {
				So(item.Label, ShouldNotEqual, "InstanceType")
			}
		})
	})
}

func TestComplete_JSONPropertyValue(t *testing.T) {
	Convey("Given a ROSTemplateProvider at a property value position in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "Resources": {
    "Vsw": {
      "Type": "ALIYUN::ECS::VSwitch",
      "Properties": {
        "VpcId": {
          "Re"
        }
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     6,
			Col:      14,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundRef bool
			for _, item := range items {
				if item.Label == "Ref" {
					foundRef = true
					So(item.InsertTextFormat, ShouldEqual, protocol.InsertTextFormatSnippet)
					So(item.Command, ShouldNotBeNil)
					So(item.Command.Command, ShouldEqual, "editor.action.triggerSuggest")
					break
				}
			}
			So(foundRef, ShouldBeTrue)
		})

		Convey("It should NOT return short tag completions for JSON", func() {
			for _, item := range items {
				So(item.Label, ShouldNotStartWith, "!")
			}
		})
	})
}

func TestComplete_JSONRefValue(t *testing.T) {
	Convey("Given a ROSTemplateProvider at a Ref value position in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "Parameters": {
    "VpcParam": {
      "Type": "String"
    }
  },
  "Resources": {
    "Vpc": {
      "Type": "ALIYUN::ECS::VPC"
    },
    "Vsw": {
      "Type": "ALIYUN::ECS::VSwitch",
      "Properties": {
        "VpcId": {
          "Ref": ""
        }
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     14, // "Ref": "" line
			Col:      18, // cursor inside the empty value string between quotes
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return parameter and resource names", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundParam, foundResource bool
			for _, item := range items {
				if item.Label == "VpcParam" {
					foundParam = true
				}
				if item.Label == "Vpc" {
					foundResource = true
				}
			}
			So(foundParam, ShouldBeTrue)
			So(foundResource, ShouldBeTrue)
		})

		Convey("It should not include the enclosing resource itself", func() {
			for _, item := range items {
				So(item.Label, ShouldNotEqual, "Vsw")
			}
		})
	})
}

func TestComplete_JSONRefValueWithInvalidJSON(t *testing.T) {
	Convey("Given an invalid JSON template with Ref value position", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		// The JSON is invalid (incomplete key "Re on a different line),
		// but the Ref line itself is valid and should still provide completions
		// via text-based fallback parsing.
		content := `{
  "Parameters": {
    "VpcParam": {
      "Type": "String"
    }
  },
  "Resources": {
    "Vpc": {
      "Type": "ALIYUN::ECS::VPC"
    },
    "Vsw": {
      "Type": "ALIYUN::ECS::VSwitch",
      "Properties": {
        "CidrBlock": "10.10.10.10/22",
        "VpcId": {
          "Ref": ""
        },
        "ZoneId": {
          "Re
        }
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     15, // "Ref": "" line
			Col:      18, // cursor inside value between quotes
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return parameter and resource names via text fallback", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundParam, foundResource bool
			for _, item := range items {
				if item.Label == "VpcParam" {
					foundParam = true
				}
				if item.Label == "Vpc" {
					foundResource = true
				}
			}
			So(foundParam, ShouldBeTrue)
			So(foundResource, ShouldBeTrue)
		})
	})
}

func TestComplete_JSONRefValueInOutputs(t *testing.T) {
	Convey("Given Ref inside Outputs Value in JSON with double-colon typo", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "Parameters": {
    "VpcParam": {
      "Type": "String"
    }
  },
  "Resources": {
    "Vpc": {
      "Type": "ALIYUN::ECS::VPC"
    }
  },
  "Outputs": {
    "OutputName":: {
      "Value": {
        "Ref": ""
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     14, // "Ref": "" line
			Col:      16, // cursor inside empty value string
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return parameters, resources, and pseudo-parameters", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundParam, foundResource, foundPseudo bool
			for _, item := range items {
				if item.Label == "VpcParam" {
					foundParam = true
				}
				if item.Label == "Vpc" {
					foundResource = true
				}
				if item.Label == "ALIYUN::StackName" {
					foundPseudo = true
				}
			}
			So(foundParam, ShouldBeTrue)
			So(foundResource, ShouldBeTrue)
			So(foundPseudo, ShouldBeTrue)
		})
	})
}

func TestComplete_RefValueAlwaysIncludesAll(t *testing.T) {
	Convey("Given Ref inside Outputs Value in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  VpcParam:
    Type: String
Resources:
  Vpc:
    Type: ALIYUN::ECS::VPC
Outputs:
  OutputName:
    Value:
      Ref: 
`

		ctx := CompletionContext{
			Content:  content,
			Line:     10, // "      Ref: " line
			Col:      11, // after "Ref: "
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return parameters, resources, and pseudo-parameters", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundParam, foundResource, foundPseudo bool
			for _, item := range items {
				if item.Label == "VpcParam" {
					foundParam = true
				}
				if item.Label == "Vpc" {
					foundResource = true
				}
				if item.Label == "ALIYUN::StackName" {
					foundPseudo = true
				}
			}
			So(foundParam, ShouldBeTrue)
			So(foundResource, ShouldBeTrue)
			So(foundPseudo, ShouldBeTrue)
		})
	})

	Convey("Given Ref inside Outputs Value in valid JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "Parameters": {
    "VpcParam": {
      "Type": "String"
    }
  },
  "Resources": {
    "Vpc": {
      "Type": "ALIYUN::ECS::VPC"
    }
  },
  "Outputs": {
    "OutputName": {
      "Value": {
        "Ref": ""
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     14,
			Col:      16,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return parameters, resources, and pseudo-parameters", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundParam, foundResource, foundPseudo bool
			for _, item := range items {
				if item.Label == "VpcParam" {
					foundParam = true
				}
				if item.Label == "Vpc" {
					foundResource = true
				}
				if item.Label == "ALIYUN::StackName" {
					foundPseudo = true
				}
			}
			So(foundParam, ShouldBeTrue)
			So(foundResource, ShouldBeTrue)
			So(foundPseudo, ShouldBeTrue)
		})
	})
}

func TestComplete_JSONGetAttResource(t *testing.T) {
	Convey("Given a ROSTemplateProvider at a GetAtt resource position in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "Resources": {
    "Vpc": {
      "Type": "ALIYUN::ECS::VPC"
    },
    "Vsw": {
      "Type": "ALIYUN::ECS::VSwitch",
      "Properties": {
        "VpcId": {
          "Fn::GetAtt": [""]
        }
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     9,
			Col:      26, // cursor inside the first empty string element between quotes
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return resource names for GetAtt", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundVpc bool
			for _, item := range items {
				if item.Label == "Vpc" {
					foundVpc = true
				}
			}
			So(foundVpc, ShouldBeTrue)
		})
	})
}

func TestComplete_JSONResourceBlock(t *testing.T) {
	Convey("Given a ROSTemplateProvider at a resource block in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "Resources": {
    "MyECS": {
      "Type": "ALIYUN::ECS::Instance",
      "Pr"
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     4,
			Col:      9,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return resource block keys like Properties, DependsOn", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundProperties bool
			for _, item := range items {
				if item.Label == "Properties" {
					foundProperties = true
				}
			}
			So(foundProperties, ShouldBeTrue)
		})
	})
}

func TestComplete_JSONParameterProperties(t *testing.T) {
	Convey("Given a ROSTemplateProvider at parameter properties in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "Parameters": {
    "MyParam": {
      "Type": "String",
      "De"
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     4,
			Col:      9,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return parameter property completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
		})

		Convey("It should exclude already existing keys", func() {
			for _, item := range items {
				So(item.Label, ShouldNotEqual, "Type")
			}
		})
	})
}

// --- Locals tests ---

func TestComplete_LocalsBlock_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at locals block position in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Locals:
  Description:
    Value: test
    
`

		ctx := CompletionContext{
			Content:  content,
			Line:     4,
			Col:      4,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return locals property completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["Type"], ShouldBeTrue)
			So(labels["Properties"], ShouldBeTrue)
		})

		Convey("It should exclude already existing keys like Value", func() {
			for _, item := range items {
				So(item.Label, ShouldNotEqual, "Value")
			}
		})
	})
}

func TestComplete_LocalsTypeValue_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at locals Type value position in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Locals:
  MyLocal:
    Type: 
`

		ctx := CompletionContext{
			Content:  content,
			Line:     3,
			Col:      10,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return Macro, Eval, and DATASOURCE types", func() {
			So(len(items), ShouldBeGreaterThanOrEqualTo, 2)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["Macro"], ShouldBeTrue)
			So(labels["Eval"], ShouldBeTrue)
		})
	})
}

func TestComplete_RefIncludesLocals_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider with Locals defined in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  P1:
    Type: String
Locals:
  MyLocal:
    Value: test
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType: ecs.s1.medium
      ImageId:
        Ref: 
`

		ctx := CompletionContext{
			Content:  content,
			Line:     13,
			Col:      13,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should include Locals in Ref completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundLocal bool
			for _, item := range items {
				if item.Label == "MyLocal" && item.Detail == "Local" {
					foundLocal = true
				}
			}
			So(foundLocal, ShouldBeTrue)
		})

		Convey("It should also include Parameters and Resources", func() {
			var foundParam, foundResource bool
			for _, item := range items {
				if item.Label == "P1" {
					foundParam = true
				}
				if item.Label == "MyECS" {
					foundResource = true
				}
			}
			So(foundParam, ShouldBeTrue)
			So(foundResource, ShouldBeFalse) // MyECS is the enclosing resource
		})
	})
}

func TestComplete_LocalsBlock_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider at locals block position in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "Locals": {
    "MyLocal": {
      "Value": "test",
      ""
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     4,
			Col:      7,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return locals property completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["Type"], ShouldBeTrue)
			So(labels["Properties"], ShouldBeTrue)
		})

		Convey("It should exclude already existing keys like Value", func() {
			for _, item := range items {
				So(item.Label, ShouldNotEqual, "Value")
			}
		})
	})
}

func TestComplete_RefIncludesLocals_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider with Locals defined in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Parameters": {
    "P1": {
      "Type": "String"
    }
  },
  "Locals": {
    "MyLocal": {
      "Value": "test"
    }
  },
  "Resources": {
    "MyECS": {
      "Type": "ALIYUN::ECS::Instance",
      "Properties": {
        "InstanceType": "ecs.s1.medium",
        "ImageId": { "Ref": "" }
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     17,
			Col:      29,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should include Locals in Ref completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundLocal bool
			for _, item := range items {
				if item.Label == "MyLocal" && item.Detail == "Local" {
					foundLocal = true
				}
			}
			So(foundLocal, ShouldBeTrue)
		})
	})
}

func TestValidate_Locals_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider validating Locals in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		Convey("When Macro type local is missing Value", func() {
			content := `ROSTemplateFormatVersion: '2015-09-01'
Locals:
  NoValue:
    Type: Macro
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType: ecs.s1.medium
      ImageId: img-123
`

			ctx := ValidationContext{
				Content:  content,
				IsYAML:   true,
				Registry: registry,
			}

			diags := provider.Validate(ctx)

			var found bool
			for _, d := range diags {
				if strings.Contains(d.Message, "NoValue") && strings.Contains(d.Message, "Value") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})

		Convey("When valid Locals are defined", func() {
			content := `ROSTemplateFormatVersion: '2015-09-01'
Locals:
  ValidLocal:
    Value: test
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType: ecs.s1.medium
      ImageId: img-123
`

			ctx := ValidationContext{
				Content:  content,
				IsYAML:   true,
				Registry: registry,
			}

			diags := provider.Validate(ctx)

			var localsErrors int
			for _, d := range diags {
				if strings.Contains(d.Message, "Local") && strings.Contains(d.Message, "ValidLocal") {
					localsErrors++
				}
			}
			So(localsErrors, ShouldEqual, 0)
		})
	})
}

func TestComplete_TopLevel_IncludesLocals(t *testing.T) {
	Convey("Given a ROSTemplateProvider at top-level position", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
`

		ctx := CompletionContext{
			Content:  content,
			Line:     4,
			Col:      0,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should include Locals in top-level completions", func() {
			var foundLocals bool
			for _, item := range items {
				if item.Label == "Locals" {
					foundLocals = true
				}
			}
			So(foundLocals, ShouldBeTrue)
		})
	})
}

func TestHover_LocalsProperty_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider hovering over Locals property in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Locals:
  MyLocal:
    Type: Macro
    Value: test
`

		ctx := HoverContext{
			Content:  content,
			Line:     3,
			Col:      6,
			IsYAML:   true,
			Registry: registry,
		}

		result := provider.Hover(ctx)

		Convey("It should return hover info for Type property", func() {
			So(result, ShouldNotBeNil)
			So(result.Contents, ShouldContainSubstring, "Type")
		})
	})
}

func TestHover_LocalsTypeValue_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider hovering over Locals Type value in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Locals:
  MyLocal:
    Type: Eval
    Value: test
`

		ctx := HoverContext{
			Content:  content,
			Line:     3,
			Col:      11,
			IsYAML:   true,
			Registry: registry,
		}

		result := provider.Hover(ctx)

		Convey("It should return hover info for Eval type", func() {
			So(result, ShouldNotBeNil)
			So(result.Contents, ShouldContainSubstring, "Eval")
		})
	})
}

func TestComplete_LocalsDatasourceProperties_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at DATASOURCE Properties in Locals (YAML)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Locals:
  Vpcs:
    Type: DATASOURCE::VPC::Vpcs
    Properties:
      
`

		ctx := CompletionContext{
			Content:  content,
			Line:     5,
			Col:      6,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return DATASOURCE resource properties", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["VpcName"], ShouldBeTrue)
			So(labels["VpcId"], ShouldBeTrue)
			So(labels["IsDefault"], ShouldBeTrue)
		})

		Convey("It should NOT return local variable attrs like Type or Value", func() {
			for _, item := range items {
				So(item.Label, ShouldNotEqual, "Type")
				So(item.Label, ShouldNotEqual, "Value")
			}
		})
	})
}

func TestComplete_LocalsDatasourcePropertiesWithPrefix_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider typing a property inside Locals DATASOURCE Properties (YAML)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Locals:
  Vpcs:
    Type: DATASOURCE::VPC::Vpcs
    Properties:
      VpcN
`

		ctx := CompletionContext{
			Content:  content,
			Line:     5,
			Col:      10,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching DATASOURCE properties", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var foundVpcName bool
			for _, item := range items {
				if item.Label == "VpcName" {
					foundVpcName = true
				}
			}
			So(foundVpcName, ShouldBeTrue)
		})
	})
}

func TestComplete_LocalsDatasourceProperties_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider at DATASOURCE Properties in Locals (JSON)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Locals": {
    "Vpcs": {
      "Type": "DATASOURCE::VPC::Vpcs",
      "Properties": {
        ""
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     6,
			Col:      9,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return DATASOURCE resource properties", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["VpcName"], ShouldBeTrue)
			So(labels["VpcId"], ShouldBeTrue)
		})
	})
}

func TestComplete_LocalsValueIntrinsicFunctions_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Locals Value nested position in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Locals:
  MyLocal:
    Type: Eval
    Value:
      F
`

		ctx := CompletionContext{
			Content:  content,
			Line:     5,
			Col:      7,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var hasRef, hasFn bool
			for _, item := range items {
				if item.Label == "Ref" || item.Label == "!Ref" {
					hasRef = true
				}
				if strings.HasPrefix(item.Label, "Fn::") || strings.HasPrefix(item.Label, "!") {
					hasFn = true
				}
			}
			So(hasRef, ShouldBeTrue)
			So(hasFn, ShouldBeTrue)
		})
	})
}

func TestComplete_LocalsValueInline_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Locals Value inline position in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Locals:
  MyLocal:
    Type: Eval
    Value: R
`

		ctx := CompletionContext{
			Content:  content,
			Line:     4,
			Col:      12,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions matching prefix R", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var hasRef bool
			for _, item := range items {
				if item.Label == "Ref" || item.Label == "!Ref" {
					hasRef = true
				}
			}
			So(hasRef, ShouldBeTrue)
		})
	})
}

func TestComplete_LocalsValueIntrinsicFunctions_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Locals Value position in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Locals": {
    "MyLocal": {
      "Type": "Eval",
      "Value": {
        "F"
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     6,
			Col:      10,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var hasRef, hasFn bool
			for _, item := range items {
				if item.Label == "Ref" || item.Label == "!Ref" {
					hasRef = true
				}
				if strings.HasPrefix(item.Label, "Fn::") {
					hasFn = true
				}
			}
			So(hasRef, ShouldBeTrue)
			So(hasFn, ShouldBeTrue)
		})
	})
}

func TestComplete_ResourcesDatasourceProperties_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at DATASOURCE Properties in Resources (YAML)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  Vpcs:
    Type: DATASOURCE::VPC::Vpcs
    Properties:
      
`

		ctx := CompletionContext{
			Content:  content,
			Line:     5,
			Col:      6,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return DATASOURCE resource properties", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["VpcName"], ShouldBeTrue)
			So(labels["VpcId"], ShouldBeTrue)
			So(labels["IsDefault"], ShouldBeTrue)
		})
	})
}

func TestComplete_FindInMapSecondKey_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider with Mappings and Fn::FindInMap at 3rd arg (YAML)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  regionParam:
    Type: String
    AllowedValues:
      - hangzhou
      - beijing
Mappings:
  RegionMap:
    hangzhou:
      '32': m-25l0rcfjo
      '64': m-25l0rcfj1
    beijing:
      '32': m-25l0rcfj2
      '64': m-25l0rcfj3
Resources:
  WebServer:
    Type: ALIYUN::ECS::Instance
    Properties:
      ImageId:
        Fn::FindInMap:
          - RegionMap
          - Ref: regionParam
          - 
`

		ctx := CompletionContext{
			Content:  content,
			Line:     23,
			Col:      12,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return second-level keys ('32' and '64'), not first-level keys", func() {
			So(len(items), ShouldEqual, 2)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["32"], ShouldBeTrue)
			So(labels["64"], ShouldBeTrue)
			So(labels["hangzhou"], ShouldBeFalse)
			So(labels["beijing"], ShouldBeFalse)
		})
	})
}

func TestComplete_FindInMapSecondKey_JSON_Inline(t *testing.T) {
	Convey("Given a ROSTemplateProvider with Fn::FindInMap inline array (JSON)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Mappings": {
    "RegionMap": {
      "hangzhou": {
        "32": "m-25l0rcfjo",
        "64": "m-25l0rcfj1"
      },
      "beijing": {
        "32": "m-25l0rcfj2",
        "64": "m-25l0rcfj3"
      }
    }
  },
  "Resources": {
    "WebServer": {
      "Type": "ALIYUN::ECS::Instance",
      "Properties": {
        "ImageId": {
          "Fn::FindInMap": ["RegionMap", {"Ref": "regionParam"}, ""]
        }
      }
    }
  }
}`

		lines := strings.Split(content, "\n")
		targetLine := -1
		for i, l := range lines {
			if strings.Contains(l, "Fn::FindInMap") {
				targetLine = i
				break
			}
		}

		line := lines[targetLine]
		lastQuote := strings.LastIndex(line, `""`)
		col := lastQuote + 1

		ctx := CompletionContext{
			Content:  content,
			Line:     targetLine,
			Col:      col,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return second-level keys ('32' and '64'), not first-level keys", func() {
			So(len(items), ShouldEqual, 2)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["32"], ShouldBeTrue)
			So(labels["64"], ShouldBeTrue)
			So(labels["hangzhou"], ShouldBeFalse)
			So(labels["beijing"], ShouldBeFalse)
		})
	})
}

func TestComplete_FindInMapSecondKey_JSON_Multiline(t *testing.T) {
	Convey("Given a ROSTemplateProvider with Fn::FindInMap multi-line array (JSON)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Mappings": {
    "RegionMap": {
      "hangzhou": {
        "32": "m-25l0rcfjo",
        "64": "m-25l0rcfj1"
      },
      "beijing": {
        "32": "m-25l0rcfj2",
        "64": "m-25l0rcfj3"
      }
    }
  },
  "Resources": {
    "WebServer": {
      "Type": "ALIYUN::ECS::Instance",
      "Properties": {
        "ImageId": {
          "Fn::FindInMap": [
            "RegionMap",
            {"Ref": "regionParam"},
            
          ]
        }
      }
    }
  }
}`

		// Find the empty line (3rd arg position) between {"Ref":...} and ]
		lines := strings.Split(content, "\n")
		targetLine := -1
		for i, l := range lines {
			if strings.Contains(l, `{"Ref"`) {
				targetLine = i + 1 // next line is the empty 3rd arg position
				break
			}
		}
		So(targetLine, ShouldBeGreaterThan, 0)

		ctx := CompletionContext{
			Content:  content,
			Line:     targetLine,
			Col:      12,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return second-level keys ('32' and '64'), not first-level keys", func() {
			So(len(items), ShouldEqual, 2)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["32"], ShouldBeTrue)
			So(labels["64"], ShouldBeTrue)
			So(labels["hangzhou"], ShouldBeFalse)
			So(labels["beijing"], ShouldBeFalse)
		})
	})
}

func TestComplete_FindInMapSecondKey_JSON_MultilineWithPrefix(t *testing.T) {
	Convey("Given Fn::FindInMap multi-line array with partial typed input (JSON)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := "{" + `
  "ROSTemplateFormatVersion": "2015-09-01",
  "Description": "",
  "Parameters": {
    "regionParam": {
      "Type": "String",
      "Default": "hangzhou"
    }
  },
  "Mappings": {
    "RegionMap": {
      "hangzhou": {
        "32": "m-25l0rcfjo",
        "64": "25l0rcfj1"
      },
      "beijing": {
        "32": "m-25l0rcfjo",
        "64": "25l0rcfj1"
      }
    }
  },
  "Resources": {
    "WebServer": {
      "Type": "ALIYUN::ECS::Instance",
      "Properties": {
        "ImageId": {
          "Fn::FindInMap": [
            "RegionMap",
            {"Ref": "regionParam"},
            "3
          ]
        }
      }
    }
  }
}`

		lines := strings.Split(content, "\n")
		targetLine := -1
		for i, l := range lines {
			trimmed := strings.TrimSpace(l)
			if trimmed == `"3` {
				targetLine = i
				break
			}
		}
		So(targetLine, ShouldBeGreaterThan, 0)

		col := len(lines[targetLine])

		ctx := CompletionContext{
			Content:  content,
			Line:     targetLine,
			Col:      col,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return second-level keys matching prefix '3'", func() {
			So(len(items), ShouldBeGreaterThanOrEqualTo, 1)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["32"], ShouldBeTrue)
			So(labels["hangzhou"], ShouldBeFalse)
			So(labels["beijing"], ShouldBeFalse)
		})
	})
}

// --- Conditions tests ---

func TestComplete_ConditionsBlock_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider inside a Conditions block in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  EnvType:
    Type: String
Conditions:
  IsProd:
    Fn::Equals:
      - Ref: EnvType
      - prod
  IsTest:
    
`

		ctx := CompletionContext{
			Content:  content,
			Line:     10,
			Col:      4,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions (condition functions)", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var hasFnEquals, hasFnAnd, hasFnOr, hasFnNot bool
			for _, item := range items {
				switch item.Label {
				case "Fn::Equals", "!Equals":
					hasFnEquals = true
				case "Fn::And", "!And":
					hasFnAnd = true
				case "Fn::Or", "!Or":
					hasFnOr = true
				case "Fn::Not", "!Not":
					hasFnNot = true
				}
			}
			So(hasFnEquals, ShouldBeTrue)
			So(hasFnAnd, ShouldBeTrue)
			So(hasFnOr, ShouldBeTrue)
			So(hasFnNot, ShouldBeTrue)
		})
	})
}

func TestComplete_ConditionsBlock_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider inside a Conditions block in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Conditions": {
    "IsProd": {
      "Fn::Equals": ["prod", "prod"]
    },
    "IsTest": {
      ""
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     8,
			Col:      7,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return intrinsic function completions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			var hasFnEquals bool
			for _, item := range items {
				if item.Label == "Fn::Equals" {
					hasFnEquals = true
				}
			}
			So(hasFnEquals, ShouldBeTrue)
		})
	})
}

func TestComplete_ConditionValue_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Condition value in resource block (YAML)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  IsProd:
    Fn::Equals:
      - Ref: EnvType
      - prod
  IsTest:
    Fn::Equals:
      - Ref: EnvType
      - test
Resources:
  WebServer:
    Type: ALIYUN::ECS::Instance
    Condition: 
    Properties:
      InstanceType: ecs.c6.large
      ImageId: img-123
`

		ctx := CompletionContext{
			Content:  content,
			Line:     13,
			Col:      15,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return condition names", func() {
			So(len(items), ShouldEqual, 2)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["IsProd"], ShouldBeTrue)
			So(labels["IsTest"], ShouldBeTrue)
		})
	})
}

func TestComplete_ConditionValue_YAML_WithPrefix(t *testing.T) {
	Convey("Given a ROSTemplateProvider typing a Condition value with prefix (YAML)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  IsProd:
    Fn::Equals:
      - Ref: EnvType
      - prod
  IsTest:
    Fn::Equals:
      - Ref: EnvType
      - test
Resources:
  WebServer:
    Type: ALIYUN::ECS::Instance
    Condition: IsP
    Properties:
      InstanceType: ecs.c6.large
      ImageId: img-123
`

		ctx := CompletionContext{
			Content:  content,
			Line:     13,
			Col:      18,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return only matching condition names", func() {
			So(len(items), ShouldEqual, 1)
			So(items[0].Label, ShouldEqual, "IsProd")
		})
	})
}

func TestComplete_ConditionValue_InOutput_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Condition value in output block (YAML)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  IsProd:
    Fn::Equals:
      - Ref: EnvType
      - prod
Outputs:
  OutputName:
    Value: test
    Condition: 
`

		ctx := CompletionContext{
			Content:  content,
			Line:     9,
			Col:      15,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return condition names", func() {
			So(len(items), ShouldEqual, 1)
			So(items[0].Label, ShouldEqual, "IsProd")
			So(items[0].Detail, ShouldEqual, "Condition")
		})
	})
}

func TestComplete_ConditionValue_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Condition value in resource block (JSON)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Conditions": {
    "IsProd": {
      "Fn::Equals": ["prod", {"Ref": "EnvType"}]
    },
    "IsTest": {
      "Fn::Equals": ["test", {"Ref": "EnvType"}]
    }
  },
  "Resources": {
    "WebServer": {
      "Type": "ALIYUN::ECS::Instance",
      "Condition": "",
      "Properties": {
        "InstanceType": "ecs.c6.large",
        "ImageId": "img-123"
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     13,
			Col:      20,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return condition names", func() {
			So(len(items), ShouldEqual, 2)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["IsProd"], ShouldBeTrue)
			So(labels["IsTest"], ShouldBeTrue)
		})
	})
}

func TestComplete_ConditionValue_InOutput_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Condition value in output block (JSON)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Conditions": {
    "IsProd": {
      "Fn::Equals": ["prod", {"Ref": "EnvType"}]
    }
  },
  "Outputs": {
    "OutputName": {
      "Value": "test",
      "Condition": ""
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     10,
			Col:      20,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return condition names", func() {
			So(len(items), ShouldEqual, 1)
			So(items[0].Label, ShouldEqual, "IsProd")
		})
	})
}

func TestValidate_Conditions_InvalidExpression_YAML(t *testing.T) {
	Convey("Given a template with an invalid condition expression in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  BadCondition: invalid_value
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType: ecs.c6.large
      ImageId: img-123
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report invalid condition expression", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "BadCondition") && strings.Contains(d.Message, "condition function") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestValidate_Conditions_ValidExpression_YAML(t *testing.T) {
	Convey("Given a template with valid condition expressions in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  EnvType:
    Type: String
Conditions:
  IsProd:
    Fn::Equals:
      - Ref: EnvType
      - prod
  NotProd:
    Fn::Not:
      - IsProd
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Condition: IsProd
    Properties:
      InstanceType: ecs.c6.large
      ImageId: img-123
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should NOT report condition errors", func() {
			condErrors := 0
			for _, d := range diags {
				if strings.Contains(d.Message, "condition") {
					condErrors++
				}
			}
			So(condErrors, ShouldEqual, 0)
		})
	})
}

func TestValidate_UndefinedConditionRef_YAML(t *testing.T) {
	Convey("Given a template with undefined condition reference in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  IsProd:
    Fn::Equals:
      - prod
      - prod
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Condition: NonExistent
    Properties:
      InstanceType: ecs.c6.large
      ImageId: img-123
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report undefined condition", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "NonExistent") && strings.Contains(d.Message, "Undefined") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestValidate_UndefinedConditionRef_JSON(t *testing.T) {
	Convey("Given a template with undefined condition reference in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Conditions": {
    "IsProd": {
      "Fn::Equals": ["prod", "prod"]
    }
  },
  "Resources": {
    "MyECS": {
      "Type": "ALIYUN::ECS::Instance",
      "Condition": "NonExistent",
      "Properties": {
        "InstanceType": "ecs.c6.large",
        "ImageId": "img-123"
      }
    }
  }
}`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   false,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report undefined condition", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "NonExistent") && strings.Contains(d.Message, "Undefined") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestValidate_Conditions_InvalidExpression_JSON(t *testing.T) {
	Convey("Given a JSON template with an invalid condition expression", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Conditions": {
    "BadCondition": {
      "InvalidKey": "value"
    }
  },
  "Resources": {
    "MyECS": {
      "Type": "ALIYUN::ECS::Instance",
      "Properties": {
        "InstanceType": "ecs.c6.large",
        "ImageId": "img-123"
      }
    }
  }
}`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   false,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report invalid condition expression", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "BadCondition") && strings.Contains(d.Message, "condition function") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestComplete_TopLevel_ConditionsSnippet_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at top-level, Conditions snippet should be offered", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
`

		ctx := CompletionContext{
			Content:  content,
			Line:     4,
			Col:      0,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should include Conditions in top-level completions", func() {
			var foundConditions bool
			for _, item := range items {
				if item.Label == "Conditions" {
					foundConditions = true
					So(item.InsertText, ShouldContainSubstring, "Conditions:")
					So(item.InsertText, ShouldContainSubstring, "Fn::Equals")
				}
			}
			So(foundConditions, ShouldBeTrue)
		})
	})
}

func TestComplete_TopLevel_ConditionsSnippet_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider at top-level in JSON, Conditions snippet should be offered", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  ""
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     2,
			Col:      4,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should include Conditions in top-level completions", func() {
			var foundConditions bool
			for _, item := range items {
				if item.Label == "Conditions" {
					foundConditions = true
				}
			}
			So(foundConditions, ShouldBeTrue)
		})
	})
}

func TestValidate_UndefinedConditionRef_InOutput_YAML(t *testing.T) {
	Convey("Given a template with undefined condition reference in output (YAML)", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  IsProd:
    Fn::Equals:
      - prod
      - prod
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType: ecs.c6.large
      ImageId: img-123
Outputs:
  EcsId:
    Value: !Ref MyECS
    Condition: NonExistentCond
`

		ctx := ValidationContext{
			Content:  content,
			IsYAML:   true,
			Registry: registry,
		}

		diags := provider.Validate(ctx)

		Convey("It should report undefined condition in output", func() {
			found := false
			for _, d := range diags {
				if strings.Contains(d.Message, "NonExistentCond") && strings.Contains(d.Message, "Undefined") {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestParser_GetConditionNames(t *testing.T) {
	Convey("Given a template with Conditions", t, func() {
		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  IsProd:
    Fn::Equals:
      - prod
      - prod
  IsTest:
    Fn::Not:
      - IsProd
`
		pt := ParseYAML(content)

		Convey("GetConditionNames should return sorted condition names", func() {
			names := pt.GetConditionNames()
			So(len(names), ShouldEqual, 2)
			So(names[0], ShouldEqual, "IsProd")
			So(names[1], ShouldEqual, "IsTest")
		})

		Convey("GetConditions should return the conditions map", func() {
			conditions := pt.GetConditions()
			So(conditions, ShouldNotBeNil)
			So(len(conditions), ShouldEqual, 2)
		})
	})

	Convey("Given a template without Conditions", t, func() {
		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
`
		pt := ParseYAML(content)

		Convey("GetConditionNames should return nil", func() {
			names := pt.GetConditionNames()
			So(names, ShouldBeNil)
		})

		Convey("GetConditions should return nil", func() {
			conditions := pt.GetConditions()
			So(conditions, ShouldBeNil)
		})
	})
}

func TestComplete_FnIfConditionName_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at the first argument of Fn::If in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  EnvType:
    Type: String
Conditions:
  CreateProdRes:
    Fn::Equals:
      - prod
      - Ref: EnvType
  IsPreEnv:
    Fn::Equals:
      - pre
      - Ref: EnvType
Resources:
  WebServer:
    Type: ALIYUN::ECS::Instance
    Properties:
      DiskMappings:
        Fn::If:
          - Cre
`

		ctx := CompletionContext{
			Content:  content,
			Line:     19,
			Col:      15,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching condition names", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			found := false
			for _, item := range items {
				if item.Label == "CreateProdRes" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestComplete_FnIfConditionName_YAML_AllConditions(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Fn::If first arg without prefix in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  CreateProdRes:
    Fn::Equals:
      - prod
      - Ref: EnvType
  IsPreEnv:
    Fn::Equals:
      - pre
      - Ref: EnvType
Resources:
  WebServer:
    Type: ALIYUN::ECS::Instance
    Properties:
      DiskMappings:
        Fn::If:
          - 
`

		ctx := CompletionContext{
			Content:  content,
			Line:     16,
			Col:      12,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return all condition names", func() {
			So(len(items), ShouldEqual, 2)
			labels := make([]string, len(items))
			for i, item := range items {
				labels[i] = item.Label
			}
			So(labels, ShouldContain, "CreateProdRes")
			So(labels, ShouldContain, "IsPreEnv")
		})
	})
}

func TestComplete_FnIfConditionName_YAML_ShortForm(t *testing.T) {
	Convey("Given a ROSTemplateProvider at !If short form first arg in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  CreateProdRes:
    Fn::Equals:
      - prod
      - Ref: EnvType
Resources:
  WebServer:
    Type: ALIYUN::ECS::Instance
    Properties:
      DiskMappings: !If [Cre, value1, value2]
`

		ctx := CompletionContext{
			Content:  content,
			Line:     10,
			Col:      28,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching condition names", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			found := false
			for _, item := range items {
				if item.Label == "CreateProdRes" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestComplete_FnIfConditionName_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Fn::If first arg in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Conditions": {
    "CreateProdRes": {
      "Fn::Equals": ["prod", {"Ref": "EnvType"}]
    },
    "IsPreEnv": {
      "Fn::Equals": ["pre", {"Ref": "EnvType"}]
    }
  },
  "Resources": {
    "WebServer": {
      "Type": "ALIYUN::ECS::Instance",
      "Properties": {
        "DiskMappings": {
          "Fn::If": [
            "CreateProdRes",
            "value1",
            "value2"
          ]
        }
      }
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     16,
			Col:      18,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching condition names", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			found := false
			for _, item := range items {
				if item.Label == "CreateProdRes" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestComplete_FnIfConditionName_JSON_Inline(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Fn::If inline first arg in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Conditions": {
    "CreateProdRes": {
      "Fn::Equals": ["prod", {"Ref": "EnvType"}]
    }
  },
  "Resources": {
    "WebServer": {
      "Type": "ALIYUN::ECS::Instance",
      "Properties": {
        "DiskMappings": {"Fn::If": ["Cre
`

		ctx := CompletionContext{
			Content:  content,
			Line:     11,
			Col:      40,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching condition names", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			found := false
			for _, item := range items {
				if item.Label == "CreateProdRes" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

// --- Fn::And / Fn::Or / Fn::Not completion tests ---

func TestComplete_FnAnd_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Fn::And argument in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  IsProd:
    Fn::Equals:
      - prod
      - Ref: EnvType
  IsLarge:
    Fn::Equals:
      - large
      - Ref: InstanceSize
  BothConditions:
    Fn::And:
      - Is
`

		ctx := CompletionContext{
			Content:  content,
			Line:     12,
			Col:      10,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching condition names", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["IsProd"], ShouldBeTrue)
			So(labels["IsLarge"], ShouldBeTrue)
		})
	})
}

func TestComplete_FnAnd_YAML_SecondArg(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Fn::And second argument in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  IsProd:
    Fn::Equals:
      - prod
      - Ref: EnvType
  IsLarge:
    Fn::Equals:
      - large
      - Ref: InstanceSize
  BothConditions:
    Fn::And:
      - IsProd
      - IsL
`

		ctx := CompletionContext{
			Content:  content,
			Line:     13,
			Col:      12,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching condition names for all arg positions", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			found := false
			for _, item := range items {
				if item.Label == "IsLarge" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestComplete_FnOr_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Fn::Or argument in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  IsProd:
    Fn::Equals:
      - prod
      - Ref: EnvType
  IsStaging:
    Fn::Equals:
      - staging
      - Ref: EnvType
  EitherCondition:
    Fn::Or:
      - 
`

		ctx := CompletionContext{
			Content:  content,
			Line:     12,
			Col:      8,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return all condition names", func() {
			So(len(items), ShouldBeGreaterThanOrEqualTo, 2)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["IsProd"], ShouldBeTrue)
			So(labels["IsStaging"], ShouldBeTrue)
		})
	})
}

func TestComplete_FnNot_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Fn::Not argument in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  IsProd:
    Fn::Equals:
      - prod
      - Ref: EnvType
  IsNotProd:
    Fn::Not:
      - Is
`

		ctx := CompletionContext{
			Content:  content,
			Line:     8,
			Col:      10,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching condition names", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			found := false
			for _, item := range items {
				if item.Label == "IsProd" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestComplete_FnAnd_ShortForm_YAML(t *testing.T) {
	Convey("Given a ROSTemplateProvider at !And short form in YAML", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `ROSTemplateFormatVersion: '2015-09-01'
Conditions:
  IsProd:
    Fn::Equals:
      - prod
      - Ref: EnvType
  IsLarge:
    Fn::Equals:
      - large
      - Ref: InstanceSize
  BothConditions: !And [IsProd, IsL]
`

		ctx := CompletionContext{
			Content:  content,
			Line:     10,
			Col:      37,
			IsYAML:   true,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching condition names at second arg of !And", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			found := false
			for _, item := range items {
				if item.Label == "IsLarge" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestComplete_FnAnd_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Fn::And argument in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Conditions": {
    "IsProd": {
      "Fn::Equals": ["prod", {"Ref": "EnvType"}]
    },
    "IsLarge": {
      "Fn::Equals": ["large", {"Ref": "InstanceSize"}]
    },
    "BothConditions": {
      "Fn::And": ["IsProd", "IsL"]
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     10,
			Col:      33,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching condition names at second arg", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			found := false
			for _, item := range items {
				if item.Label == "IsLarge" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}

func TestComplete_FnOr_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Fn::Or argument in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Conditions": {
    "IsProd": {
      "Fn::Equals": ["prod", {"Ref": "EnvType"}]
    },
    "IsStaging": {
      "Fn::Equals": ["staging", {"Ref": "EnvType"}]
    },
    "EitherCond": {
      "Fn::Or": ["Is"]
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     10,
			Col:      20,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching condition names", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			labels := make(map[string]bool)
			for _, item := range items {
				labels[item.Label] = true
			}
			So(labels["IsProd"], ShouldBeTrue)
			So(labels["IsStaging"], ShouldBeTrue)
		})
	})
}

func TestComplete_FnNot_JSON(t *testing.T) {
	Convey("Given a ROSTemplateProvider at Fn::Not argument in JSON", t, func() {
		provider := &ROSTemplateProvider{}
		registry := newTestRegistry()

		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Conditions": {
    "IsProd": {
      "Fn::Equals": ["prod", {"Ref": "EnvType"}]
    },
    "IsNotProd": {
      "Fn::Not": ["Is"]
    }
  }
}`

		ctx := CompletionContext{
			Content:  content,
			Line:     7,
			Col:      20,
			IsYAML:   false,
			Registry: registry,
		}

		items := provider.Complete(ctx)

		Convey("It should return matching condition names", func() {
			So(len(items), ShouldBeGreaterThan, 0)
			found := false
			for _, item := range items {
				if item.Label == "IsProd" {
					found = true
				}
			}
			So(found, ShouldBeTrue)
		})
	})
}
