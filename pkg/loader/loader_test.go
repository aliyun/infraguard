package loader

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestValidateROSTemplate(t *testing.T) {
	Convey("Given the ValidateROSTemplate function", t, func() {
		Convey("When validating a valid ROS template", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources": map[string]interface{}{
					"VPC": map[string]interface{}{
						"Type": "ALIYUN::ECS::VPC",
					},
				},
			}

			err := ValidateROSTemplate(data)

			Convey("It should return no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When ROSTemplateFormatVersion is missing", func() {
			data := map[string]interface{}{
				"Resources": map[string]interface{}{},
			}

			err := ValidateROSTemplate(data)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
				validationErr, ok := err.(*ROSTemplateValidationError)
				So(ok, ShouldBeTrue)
				So(validationErr.Field, ShouldEqual, "ROSTemplateFormatVersion")
				So(validationErr.Message, ShouldContainSubstring, "missing")
			})
		})

		Convey("When ROSTemplateFormatVersion is not a string", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": 2015,
				"Resources":                map[string]interface{}{},
			}

			err := ValidateROSTemplate(data)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
				validationErr, ok := err.(*ROSTemplateValidationError)
				So(ok, ShouldBeTrue)
				So(validationErr.Field, ShouldEqual, "ROSTemplateFormatVersion")
				So(validationErr.Message, ShouldContainSubstring, "must be a string")
			})
		})

		Convey("When ROSTemplateFormatVersion has invalid version", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": "2020-01-01",
				"Resources":                map[string]interface{}{},
			}

			err := ValidateROSTemplate(data)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
				validationErr, ok := err.(*ROSTemplateValidationError)
				So(ok, ShouldBeTrue)
				So(validationErr.Field, ShouldEqual, "ROSTemplateFormatVersion")
				So(validationErr.Message, ShouldContainSubstring, "invalid version")
			})
		})

		Convey("When Resources is missing", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
			}

			err := ValidateROSTemplate(data)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
				validationErr, ok := err.(*ROSTemplateValidationError)
				So(ok, ShouldBeTrue)
				So(validationErr.Field, ShouldEqual, "Resources")
				So(validationErr.Message, ShouldContainSubstring, "missing")
			})
		})

		Convey("When Resources is not a map", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources":                "not a map",
			}

			err := ValidateROSTemplate(data)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
				validationErr, ok := err.(*ROSTemplateValidationError)
				So(ok, ShouldBeTrue)
				So(validationErr.Field, ShouldEqual, "Resources")
				So(validationErr.Message, ShouldContainSubstring, "must be a map")
			})
		})

		Convey("When validating an empty map", func() {
			data := map[string]interface{}{}

			err := ValidateROSTemplate(data)

			Convey("It should return an error for missing ROSTemplateFormatVersion", func() {
				So(err, ShouldNotBeNil)
				validationErr, ok := err.(*ROSTemplateValidationError)
				So(ok, ShouldBeTrue)
				So(validationErr.Field, ShouldEqual, "ROSTemplateFormatVersion")
			})
		})

		Convey("When validating a template with empty Resources", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources":                map[string]interface{}{},
			}

			err := ValidateROSTemplate(data)

			Convey("It should return no error (empty Resources is valid)", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When a resource is not a map", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources": map[string]interface{}{
					"VPC": "not a map",
				},
			}

			err := ValidateROSTemplate(data)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
				validationErr, ok := err.(*ROSTemplateValidationError)
				So(ok, ShouldBeTrue)
				So(validationErr.Field, ShouldEqual, "Resources.VPC")
				So(validationErr.Message, ShouldContainSubstring, "must be a map")
			})
		})

		Convey("When a resource is missing Type", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources": map[string]interface{}{
					"VPC": map[string]interface{}{
						"Properties": map[string]interface{}{},
					},
				},
			}

			err := ValidateROSTemplate(data)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
				validationErr, ok := err.(*ROSTemplateValidationError)
				So(ok, ShouldBeTrue)
				So(validationErr.Field, ShouldEqual, "Resources.VPC.Type")
				So(validationErr.Message, ShouldContainSubstring, "missing")
			})
		})

		Convey("When a resource Type is not a string", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources": map[string]interface{}{
					"VPC": map[string]interface{}{
						"Type": 123,
					},
				},
			}

			err := ValidateROSTemplate(data)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
				validationErr, ok := err.(*ROSTemplateValidationError)
				So(ok, ShouldBeTrue)
				So(validationErr.Field, ShouldEqual, "Resources.VPC.Type")
				So(validationErr.Message, ShouldContainSubstring, "must be a string")
			})
		})

		Convey("When a resource Properties is not a map", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources": map[string]interface{}{
					"VPC": map[string]interface{}{
						"Type":       "ALIYUN::ECS::VPC",
						"Properties": "not a map",
					},
				},
			}

			err := ValidateROSTemplate(data)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
				validationErr, ok := err.(*ROSTemplateValidationError)
				So(ok, ShouldBeTrue)
				So(validationErr.Field, ShouldEqual, "Resources.VPC.Properties")
				So(validationErr.Message, ShouldContainSubstring, "must be a map")
			})
		})

		Convey("When a resource has valid Type without Properties", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources": map[string]interface{}{
					"VPC": map[string]interface{}{
						"Type": "ALIYUN::ECS::VPC",
					},
				},
			}

			err := ValidateROSTemplate(data)

			Convey("It should return no error", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When validating a complete ROS template", func() {
			data := map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Description":              "Test template",
				"Parameters": map[string]interface{}{
					"InstanceType": map[string]interface{}{
						"Type":    "String",
						"Default": "ecs.c6.large",
					},
				},
				"Resources": map[string]interface{}{
					"ECS": map[string]interface{}{
						"Type": "ALIYUN::ECS::InstanceGroup",
						"Properties": map[string]interface{}{
							"InstanceType": map[string]interface{}{
								"Ref": "InstanceType",
							},
						},
					},
				},
				"Outputs": map[string]interface{}{
					"InstanceId": map[string]interface{}{
						"Value": map[string]interface{}{
							"Ref": "ECS",
						},
					},
				},
			}

			err := ValidateROSTemplate(data)

			Convey("It should return no error", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestROSTemplateValidationError(t *testing.T) {
	Convey("Given an ROSTemplateValidationError", t, func() {
		err := &ROSTemplateValidationError{
			Field:   "TestField",
			Message: "test message",
		}

		Convey("When calling Error()", func() {
			result := err.Error()

			Convey("It should return formatted error string", func() {
				So(result, ShouldEqual, "TestField: test message")
			})
		})
	})
}

func TestLoadLocal(t *testing.T) {
	Convey("Given the LoadLocal function", t, func() {
		Convey("When loading a YAML file", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			yamlContent := `ROSTemplateFormatVersion: '2015-09-01'
Description: Test template
Resources:
  WebServer:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      InstanceType: ecs.c6.large
      AllocatePublicIP: true
`

			yamlPath := filepath.Join(tmpDir, "test.yaml")
			err = os.WriteFile(yamlPath, []byte(yamlContent), 0644)
			So(err, ShouldBeNil)

			node, data, err := LoadLocal(yamlPath)

			Convey("It should return YAML node", func() {
				So(err, ShouldBeNil)
				So(node, ShouldNotBeNil)
			})

			Convey("It should parse data correctly", func() {
				So(data, ShouldNotBeNil)
				So(data["Description"], ShouldEqual, "Test template")

				resources, ok := data["Resources"].(map[string]interface{})
				So(ok, ShouldBeTrue)
				_, ok = resources["WebServer"]
				So(ok, ShouldBeTrue)
			})
		})

		Convey("When loading a JSON file", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			jsonContent := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Description": "Test JSON template",
  "Resources": {
    "WebServer": {
      "Type": "ALIYUN::ECS::InstanceGroup",
      "Properties": {
        "InstanceType": "ecs.c6.large",
        "AllocatePublicIP": false
      }
    }
  }
}`

			jsonPath := filepath.Join(tmpDir, "test.json")
			err = os.WriteFile(jsonPath, []byte(jsonContent), 0644)
			So(err, ShouldBeNil)

			node, data, err := LoadLocal(jsonPath)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
				_ = node
			})

			Convey("It should parse data correctly", func() {
				So(data, ShouldNotBeNil)
				So(data["Description"], ShouldEqual, "Test JSON template")

				resources := data["Resources"].(map[string]interface{})
				webServer := resources["WebServer"].(map[string]interface{})
				props := webServer["Properties"].(map[string]interface{})
				So(props["AllocatePublicIP"], ShouldEqual, false)
			})
		})

		Convey("When loading JSON content with non-JSON extension", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			jsonContent := `{"key": "value", "number": 42}`

			txtPath := filepath.Join(tmpDir, "test.txt")
			err = os.WriteFile(txtPath, []byte(jsonContent), 0644)
			So(err, ShouldBeNil)

			_, data, err := LoadLocal(txtPath)

			Convey("It should detect and parse as JSON", func() {
				So(err, ShouldBeNil)
				So(data["key"], ShouldEqual, "value")
				So(data["number"], ShouldEqual, 42.0)
			})
		})

		Convey("When file does not exist", func() {
			_, _, err := LoadLocal("/nonexistent/path/to/file.yaml")

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When loading invalid YAML", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			invalidYAML := `key: value
  bad_indent: this is wrong
    even_worse: nope`

			yamlPath := filepath.Join(tmpDir, "invalid.yaml")
			err = os.WriteFile(yamlPath, []byte(invalidYAML), 0644)
			So(err, ShouldBeNil)

			_, _, err = LoadLocal(yamlPath)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When loading invalid JSON", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			invalidJSON := `{"key": "value", "incomplete`

			jsonPath := filepath.Join(tmpDir, "invalid.json")
			err = os.WriteFile(jsonPath, []byte(invalidJSON), 0644)
			So(err, ShouldBeNil)

			_, _, err = LoadLocal(jsonPath)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When loading an empty file", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			emptyPath := filepath.Join(tmpDir, "empty.yaml")
			err = os.WriteFile(emptyPath, []byte{}, 0644)
			So(err, ShouldBeNil)

			node, data, err := LoadLocal(emptyPath)

			Convey("It should handle empty YAML file", func() {
				So(err, ShouldBeNil)
				_ = node
				_ = data
			})
		})

		Convey("When loading policy test templates", func() {
			testFiles := []struct {
				path        string
				description string
			}{
				{"../../policies/testdata/aliyun/packs/security-group-best-practice/compliant.yaml", "compliant template"},
				{"../../policies/testdata/aliyun/packs/security-group-best-practice/violation.yaml", "violation template"},
			}

			for _, tf := range testFiles {
				Convey("Loading "+tf.description, func() {
					node, data, err := LoadLocal(tf.path)

					Convey("It should parse successfully", func() {
						So(err, ShouldBeNil)
						So(node, ShouldNotBeNil)
						So(data, ShouldNotBeNil)
					})

					Convey("It should have standard ROS template structure", func() {
						_, ok := data["ROSTemplateFormatVersion"]
						So(ok, ShouldBeTrue)
						_, ok = data["Resources"]
						So(ok, ShouldBeTrue)
					})
				})
			}
		})

		Convey("When loading JSON with complex structure", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			complexYAML := `ROSTemplateFormatVersion: '2015-09-01'
Description: Complex template
Parameters:
  InstanceType:
    Type: String
    Default: ecs.c6.large
    AllowedValues:
      - ecs.c6.large
      - ecs.c6.xlarge
Resources:
  SecurityGroup:
    Type: ALIYUN::ECS::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          PortRange: 22/22
          SourceCidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          PortRange: 80/80
          SourceCidrIp: 0.0.0.0/0
Outputs:
  SecurityGroupId:
    Value:
      Ref: SecurityGroup
`

			yamlPath := filepath.Join(tmpDir, "complex.yaml")
			err = os.WriteFile(yamlPath, []byte(complexYAML), 0644)
			So(err, ShouldBeNil)

			node, data, err := LoadLocal(yamlPath)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
				So(node, ShouldNotBeNil)
			})

			Convey("It should parse Parameters correctly", func() {
				params := data["Parameters"].(map[string]interface{})
				instanceType := params["InstanceType"].(map[string]interface{})
				allowedValues := instanceType["AllowedValues"].([]interface{})
				So(len(allowedValues), ShouldEqual, 2)
			})

			Convey("It should parse SecurityGroupIngress correctly", func() {
				resources := data["Resources"].(map[string]interface{})
				sg := resources["SecurityGroup"].(map[string]interface{})
				props := sg["Properties"].(map[string]interface{})
				ingress := props["SecurityGroupIngress"].([]interface{})
				So(len(ingress), ShouldEqual, 2)
			})

			Convey("It should parse Outputs correctly", func() {
				outputs := data["Outputs"].(map[string]interface{})
				_, ok := outputs["SecurityGroupId"]
				So(ok, ShouldBeTrue)
			})
		})

		Convey("When loading JSON with uppercase extension", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			jsonContent := `{"format": "uppercase extension"}`

			jsonPath := filepath.Join(tmpDir, "test.JSON")
			err = os.WriteFile(jsonPath, []byte(jsonContent), 0644)
			So(err, ShouldBeNil)

			_, data, err := LoadLocal(jsonPath)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
				So(data["format"], ShouldEqual, "uppercase extension")
			})
		})

		Convey("When loading JSON array", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			jsonContent := `[{"item": 1}, {"item": 2}]`

			txtPath := filepath.Join(tmpDir, "array.txt")
			err = os.WriteFile(txtPath, []byte(jsonContent), 0644)
			So(err, ShouldBeNil)

			_, _, err = LoadLocal(txtPath)

			Convey("It should return an error for JSON array", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When loading simple valid JSON", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			jsonContent := `{"simple": "json"}`

			jsonPath := filepath.Join(tmpDir, "test.json")
			err = os.WriteFile(jsonPath, []byte(jsonContent), 0644)
			So(err, ShouldBeNil)

			node, data, err := LoadLocal(jsonPath)

			Convey("It should have both node and data", func() {
				So(err, ShouldBeNil)
				So(node, ShouldNotBeNil)
				So(data, ShouldNotBeNil)
				So(data["simple"], ShouldEqual, "json")
			})
		})
	})
}

func TestYAMLTagParsing(t *testing.T) {
	Convey("Given the LoadLocal function with YAML tags", t, func() {
		Convey("When loading YAML with !Ref tag", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			yamlContent := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  WebServer:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      InstanceType: !Ref MyParameter
`

			yamlPath := filepath.Join(tmpDir, "ref-test.yaml")
			err = os.WriteFile(yamlPath, []byte(yamlContent), 0644)
			So(err, ShouldBeNil)

			_, data, err := LoadLocal(yamlPath)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should convert !Ref to map format", func() {
				resources := data["Resources"].(map[string]interface{})
				webServer := resources["WebServer"].(map[string]interface{})
				props := webServer["Properties"].(map[string]interface{})
				instanceType := props["InstanceType"].(map[string]interface{})
				So(instanceType["Ref"], ShouldEqual, "MyParameter")
			})
		})

		Convey("When loading YAML with !Join tag", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			yamlContent := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  WebServer:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      InstanceName: !Join ["-", ["web", "server", "prod"]]
`

			yamlPath := filepath.Join(tmpDir, "join-test.yaml")
			err = os.WriteFile(yamlPath, []byte(yamlContent), 0644)
			So(err, ShouldBeNil)

			_, data, err := LoadLocal(yamlPath)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should convert !Join to Fn::Join format", func() {
				resources := data["Resources"].(map[string]interface{})
				webServer := resources["WebServer"].(map[string]interface{})
				props := webServer["Properties"].(map[string]interface{})
				instanceName := props["InstanceName"].(map[string]interface{})
				joinFunc := instanceName["Fn::Join"].([]interface{})
				So(joinFunc[0], ShouldEqual, "-")
				parts := joinFunc[1].([]interface{})
				So(len(parts), ShouldEqual, 3)
				So(parts[0], ShouldEqual, "web")
			})
		})

		Convey("When loading YAML with !Sub tag", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			yamlContent := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  WebServer:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      UserData: !Sub "Hello ${Name}"
`

			yamlPath := filepath.Join(tmpDir, "sub-test.yaml")
			err = os.WriteFile(yamlPath, []byte(yamlContent), 0644)
			So(err, ShouldBeNil)

			_, data, err := LoadLocal(yamlPath)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should convert !Sub to Fn::Sub format", func() {
				resources := data["Resources"].(map[string]interface{})
				webServer := resources["WebServer"].(map[string]interface{})
				props := webServer["Properties"].(map[string]interface{})
				userData := props["UserData"].(map[string]interface{})
				So(userData["Fn::Sub"], ShouldEqual, "Hello ${Name}")
			})
		})

		Convey("When loading YAML with !Base64Encode tag", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			yamlContent := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  WebServer:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      UserData: !Base64Encode "hello world"
`

			yamlPath := filepath.Join(tmpDir, "base64-test.yaml")
			err = os.WriteFile(yamlPath, []byte(yamlContent), 0644)
			So(err, ShouldBeNil)

			_, data, err := LoadLocal(yamlPath)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should convert !Base64Encode to Fn::Base64Encode format", func() {
				resources := data["Resources"].(map[string]interface{})
				webServer := resources["WebServer"].(map[string]interface{})
				props := webServer["Properties"].(map[string]interface{})
				userData := props["UserData"].(map[string]interface{})
				So(userData["Fn::Base64Encode"], ShouldEqual, "hello world")
			})
		})

		Convey("When loading YAML with !GetAtt tag", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			yamlContent := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  WebServer:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      Endpoint: !GetAtt [MyDB, ConnectionString]
`

			yamlPath := filepath.Join(tmpDir, "getatt-test.yaml")
			err = os.WriteFile(yamlPath, []byte(yamlContent), 0644)
			So(err, ShouldBeNil)

			_, data, err := LoadLocal(yamlPath)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should convert !GetAtt to Fn::GetAtt format", func() {
				resources := data["Resources"].(map[string]interface{})
				webServer := resources["WebServer"].(map[string]interface{})
				props := webServer["Properties"].(map[string]interface{})
				endpoint := props["Endpoint"].(map[string]interface{})
				getAtt := endpoint["Fn::GetAtt"].([]interface{})
				So(len(getAtt), ShouldEqual, 2)
				So(getAtt[0], ShouldEqual, "MyDB")
				So(getAtt[1], ShouldEqual, "ConnectionString")
			})
		})

		Convey("When loading YAML with nested tags", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			yamlContent := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  WebServer:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      InstanceName: !Join ["-", [!Ref Prefix, "suffix"]]
`

			yamlPath := filepath.Join(tmpDir, "nested-test.yaml")
			err = os.WriteFile(yamlPath, []byte(yamlContent), 0644)
			So(err, ShouldBeNil)

			_, data, err := LoadLocal(yamlPath)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should convert nested tags correctly", func() {
				resources := data["Resources"].(map[string]interface{})
				webServer := resources["WebServer"].(map[string]interface{})
				props := webServer["Properties"].(map[string]interface{})
				instanceName := props["InstanceName"].(map[string]interface{})
				joinFunc := instanceName["Fn::Join"].([]interface{})
				parts := joinFunc[1].([]interface{})
				So(len(parts), ShouldEqual, 2)

				// First element should be a Ref
				ref := parts[0].(map[string]interface{})
				So(ref["Ref"], ShouldEqual, "Prefix")

				// Second element should be a string
				So(parts[1], ShouldEqual, "suffix")
			})
		})

		Convey("When loading JSON format with Ref", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			jsonContent := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Resources": {
    "WebServer": {
      "Type": "ALIYUN::ECS::InstanceGroup",
      "Properties": {
        "InstanceType": {"Ref": "MyParameter"}
      }
    }
  }
}`

			jsonPath := filepath.Join(tmpDir, "json-ref-test.json")
			err = os.WriteFile(jsonPath, []byte(jsonContent), 0644)
			So(err, ShouldBeNil)

			_, data, err := LoadLocal(jsonPath)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should have the same structure as YAML !Ref", func() {
				resources := data["Resources"].(map[string]interface{})
				webServer := resources["WebServer"].(map[string]interface{})
				props := webServer["Properties"].(map[string]interface{})
				instanceType := props["InstanceType"].(map[string]interface{})
				So(instanceType["Ref"], ShouldEqual, "MyParameter")
			})
		})

		Convey("When loading JSON format with Fn::Join", func() {
			tmpDir, err := os.MkdirTemp("", "loader-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			jsonContent := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Resources": {
    "WebServer": {
      "Type": "ALIYUN::ECS::InstanceGroup",
      "Properties": {
        "InstanceName": {"Fn::Join": ["-", ["web", "server"]]}
      }
    }
  }
}`

			jsonPath := filepath.Join(tmpDir, "json-join-test.json")
			err = os.WriteFile(jsonPath, []byte(jsonContent), 0644)
			So(err, ShouldBeNil)

			_, data, err := LoadLocal(jsonPath)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should have the same structure as YAML !Join", func() {
				resources := data["Resources"].(map[string]interface{})
				webServer := resources["WebServer"].(map[string]interface{})
				props := webServer["Properties"].(map[string]interface{})
				instanceName := props["InstanceName"].(map[string]interface{})
				joinFunc := instanceName["Fn::Join"].([]interface{})
				So(joinFunc[0], ShouldEqual, "-")
				parts := joinFunc[1].([]interface{})
				So(len(parts), ShouldEqual, 2)
			})
		})
	})
}
