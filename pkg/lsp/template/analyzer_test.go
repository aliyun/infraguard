package template

import (
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAnalyzePosition_TopLevel(t *testing.T) {
	Convey("Given a YAML template with cursor at root level", t, func() {
		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
`
		ctx := AnalyzePosition(content, 4, 0, true)

		Convey("It should detect top-level context", func() {
			So(ctx.Type, ShouldEqual, ContextTopLevel)
		})

		Convey("It should list existing top-level keys", func() {
			So(ctx.ExistingKeys, ShouldContain, "ROSTemplateFormatVersion")
			So(ctx.ExistingKeys, ShouldContain, "Resources")
		})
	})
}

func TestAnalyzePosition_ResourceType(t *testing.T) {
	Convey("Given a YAML template with cursor at Type value", t, func() {
		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::EC
    Properties:
      InstanceType: ecs.c6.large
`
		ctx := AnalyzePosition(content, 3, 20, true)

		Convey("It should detect resource type context", func() {
			So(ctx.Type, ShouldEqual, ContextResourceType)
			So(ctx.ResourceName, ShouldEqual, "MyECS")
		})
	})
}

func TestAnalyzePosition_ResourceProperties(t *testing.T) {
	Convey("Given a YAML template with cursor at Properties level", t, func() {
		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType: ecs.c6.large
      
`
		ctx := AnalyzePosition(content, 6, 6, true)

		Convey("It should detect resource properties context", func() {
			So(ctx.Type, ShouldEqual, ContextResourceProperties)
			So(ctx.ResourceName, ShouldEqual, "MyECS")
			So(ctx.ResourceTypeName, ShouldEqual, "ALIYUN::ECS::Instance")
		})
	})
}

func TestAnalyzePosition_ResourcePropertiesWithPrefix(t *testing.T) {
	Convey("Given a YAML template with cursor typing a property name prefix", t, func() {
		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  vsw:
    Type: ALIYUN::ECS::VSwitch
    Properties:
      V
`
		ctx := AnalyzePosition(content, 5, 7, true)

		Convey("It should detect resource properties context, not property value", func() {
			So(ctx.Type, ShouldEqual, ContextResourceProperties)
			So(ctx.ResourceName, ShouldEqual, "vsw")
			So(ctx.ResourceTypeName, ShouldEqual, "ALIYUN::ECS::VSwitch")
		})

		Convey("It should extract the typed prefix", func() {
			So(ctx.Prefix, ShouldEqual, "V")
		})
	})
}

func TestAnalyzePosition_ResourcePropertiesWithExistingProps(t *testing.T) {
	Convey("Given a YAML template with existing properties and cursor typing a new one", t, func() {
		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  vsw:
    Type: ALIYUN::ECS::VSwitch
    Properties:
      CidrBlock: 10.0.0.0/24
      V
`
		ctx := AnalyzePosition(content, 6, 7, true)

		Convey("It should detect resource properties context", func() {
			So(ctx.Type, ShouldEqual, ContextResourceProperties)
			So(ctx.ResourceName, ShouldEqual, "vsw")
		})

		Convey("It should list existing property keys", func() {
			So(ctx.ExistingKeys, ShouldContain, "CidrBlock")
		})
	})
}

func TestAnalyzePosition_ParameterProperties(t *testing.T) {
	Convey("Given a YAML template with cursor inside a parameter definition", t, func() {
		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  MyParam:
    Type: String
    
`
		ctx := AnalyzePosition(content, 4, 4, true)

		Convey("It should detect parameter properties context", func() {
			So(ctx.Type, ShouldEqual, ContextParameterProperties)
		})

		Convey("It should list existing parameter attribute keys", func() {
			So(ctx.ExistingKeys, ShouldContain, "Type")
		})
	})
}

func TestAnalyzePosition_ParameterTypeValue(t *testing.T) {
	Convey("Given a YAML template with cursor at parameter Type value", t, func() {
		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  MyParam:
    Type: Str
`
		ctx := AnalyzePosition(content, 3, 13, true)

		Convey("It should detect parameter type value context", func() {
			So(ctx.Type, ShouldEqual, ContextParameterTypeValue)
		})

		Convey("It should extract the prefix", func() {
			So(ctx.Prefix, ShouldEqual, "Str")
		})
	})
}

func TestAnalyzePosition_ParameterNameLevel(t *testing.T) {
	Convey("Given a YAML template with cursor at parameter name level", t, func() {
		content := `ROSTemplateFormatVersion: '2015-09-01'
Parameters:
  
`
		ctx := AnalyzePosition(content, 2, 2, true)

		Convey("It should not detect parameter properties context (parameter names are user-defined)", func() {
			So(ctx.Type, ShouldEqual, ContextUnknown)
		})
	})
}

func TestAnalyzePosition_FindInMapThirdArg_YAML(t *testing.T) {
	Convey("Given a YAML template with Fn::FindInMap long form and cursor at 3rd arg", t, func() {
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
		// cursor is on the "          - " line (line 23), col 12 (after "- ")
		ctx := AnalyzePosition(content, 23, 12, true)

		Convey("It should detect FindInMap second key context (3rd argument)", func() {
			So(ctx.Type, ShouldEqual, ContextFindInMapSecondKey)
		})

		Convey("It should have the correct map name", func() {
			So(ctx.FindInMapMapName, ShouldEqual, "RegionMap")
		})
	})
}

func TestAnalyzePosition_FindInMapThirdArg_JSON(t *testing.T) {
	Convey("Given a JSON template with Fn::FindInMap and cursor at 3rd arg", t, func() {
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
		// cursor on the line with Fn::FindInMap, at the third argument ""
		lines := strings.Split(content, "\n")
		targetLine := -1
		for i, l := range lines {
			if strings.Contains(l, "Fn::FindInMap") {
				targetLine = i
				break
			}
		}
		So(targetLine, ShouldBeGreaterThan, 0)

		// Find position of the last "" in the array
		line := lines[targetLine]
		lastQuote := strings.LastIndex(line, `""`)
		col := lastQuote + 1 // inside the quotes

		ctx := AnalyzePosition(content, targetLine, col, false)

		Convey("It should detect FindInMap second key context (3rd argument)", func() {
			So(ctx.Type, ShouldEqual, ContextFindInMapSecondKey)
		})

		Convey("It should have the correct map name", func() {
			So(ctx.FindInMapMapName, ShouldEqual, "RegionMap")
		})
	})
}

func TestAnalyzePosition_FindInMapThirdArg_JSON_MultilinePartial(t *testing.T) {
	Convey("Given a JSON template with Fn::FindInMap multi-line and partial input at 3rd arg", t, func() {
		content := "{" + `
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
			if strings.TrimSpace(l) == `"3` {
				targetLine = i
				break
			}
		}
		So(targetLine, ShouldBeGreaterThan, 0)

		col := len(lines[targetLine])

		ctx := AnalyzePosition(content, targetLine, col, false)

		Convey("It should detect FindInMap second key context", func() {
			So(ctx.Type, ShouldEqual, ContextFindInMapSecondKey)
		})

		Convey("It should have the correct map name and prefix", func() {
			So(ctx.FindInMapMapName, ShouldEqual, "RegionMap")
			So(ctx.Prefix, ShouldEqual, "3")
		})
	})
}

func TestIntrinsicFunctions(t *testing.T) {
	Convey("Given intrinsic function metadata", t, func() {
		Convey("GetIntrinsicFunction finds by name", func() {
			fn := GetIntrinsicFunction("Fn::Join")
			So(fn, ShouldNotBeNil)
			So(fn.ShortTag, ShouldEqual, "!Join")
		})

		Convey("GetIntrinsicFunction finds by short tag", func() {
			fn := GetIntrinsicFunction("!Ref")
			So(fn, ShouldNotBeNil)
			So(fn.Name, ShouldEqual, "Ref")
		})

		Convey("GetIntrinsicFunction returns nil for unknown", func() {
			fn := GetIntrinsicFunction("Unknown")
			So(fn, ShouldBeNil)
		})

		Convey("IsIntrinsicFunctionValue detects Ref", func() {
			So(IsIntrinsicFunctionValue(map[string]interface{}{"Ref": "MyParam"}), ShouldBeTrue)
		})

		Convey("IsIntrinsicFunctionValue detects Fn::", func() {
			So(IsIntrinsicFunctionValue(map[string]interface{}{"Fn::Join": []interface{}{}}), ShouldBeTrue)
		})

		Convey("IsIntrinsicFunctionValue rejects non-functions", func() {
			So(IsIntrinsicFunctionValue(map[string]interface{}{"key": "value"}), ShouldBeFalse)
			So(IsIntrinsicFunctionValue("string"), ShouldBeFalse)
		})
	})
}
