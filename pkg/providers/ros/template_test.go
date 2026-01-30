package ros

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
	})
}

func TestLoadLocalTemplate(t *testing.T) {
	Convey("Given the LoadLocalTemplate function", t, func() {
		tmpDir := t.TempDir()

		Convey("When loading a valid YAML template", func() {
			templatePath := filepath.Join(tmpDir, "template.yaml")
			content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  VPC:
    Type: ALIYUN::ECS::VPC
    Properties:
      CidrBlock: 192.168.0.0/16
`
			err := os.WriteFile(templatePath, []byte(content), 0644)
			So(err, ShouldBeNil)

			yamlRoot, data, err := LoadLocalTemplate(templatePath)

			Convey("It should load successfully", func() {
				So(err, ShouldBeNil)
				So(yamlRoot, ShouldNotBeNil)
				So(data, ShouldNotBeNil)
				So(data["ROSTemplateFormatVersion"], ShouldEqual, "2015-09-01")
				So(data["Resources"], ShouldNotBeNil)
			})
		})

		Convey("When loading a valid JSON template", func() {
			templatePath := filepath.Join(tmpDir, "template.json")
			content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Resources": {
    "VPC": {
      "Type": "ALIYUN::ECS::VPC",
      "Properties": {
        "CidrBlock": "192.168.0.0/16"
      }
    }
  }
}`
			err := os.WriteFile(templatePath, []byte(content), 0644)
			So(err, ShouldBeNil)

			_, data, err := LoadLocalTemplate(templatePath)

			Convey("It should load successfully", func() {
				So(err, ShouldBeNil)
				So(data, ShouldNotBeNil)
				So(data["ROSTemplateFormatVersion"], ShouldEqual, "2015-09-01")
				So(data["Resources"], ShouldNotBeNil)
			})
		})

		Convey("When file does not exist", func() {
			_, _, err := LoadLocalTemplate("/nonexistent/template.yaml")

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}
