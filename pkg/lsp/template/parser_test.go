package template

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestParseYAML(t *testing.T) {
	Convey("Given a valid ROS YAML template", t, func() {
		content := `ROSTemplateFormatVersion: '2015-09-01'
Resources:
  MyECS:
    Type: ALIYUN::ECS::Instance
    Properties:
      InstanceType: ecs.c6.large
      ImageId: centos_7
`
		pt := ParseYAML(content)

		Convey("It should parse without error", func() {
			So(pt.Err, ShouldBeNil)
			So(pt.Root, ShouldNotBeNil)
		})

		Convey("It should detect ROSTemplateFormatVersion", func() {
			So(pt.HasROSTemplateFormatVersion(), ShouldBeTrue)
			So(pt.GetROSTemplateFormatVersion(), ShouldEqual, "2015-09-01")
		})

		Convey("It should extract top-level keys", func() {
			So(pt.TopLevelKeys, ShouldContain, "ROSTemplateFormatVersion")
			So(pt.TopLevelKeys, ShouldContain, "Resources")
		})

		Convey("It should extract resources", func() {
			resources := pt.GetResources()
			So(resources, ShouldNotBeNil)
			So(resources, ShouldContainKey, "MyECS")
		})

		Convey("It should get resource type", func() {
			So(pt.GetResourceType("MyECS"), ShouldEqual, "ALIYUN::ECS::Instance")
		})

		Convey("It should get resource properties", func() {
			props := pt.GetResourceProperties("MyECS")
			So(props, ShouldNotBeNil)
			So(props["InstanceType"], ShouldEqual, "ecs.c6.large")
		})
	})
}

func TestParseJSON(t *testing.T) {
	Convey("Given a valid ROS JSON template", t, func() {
		content := `{
  "ROSTemplateFormatVersion": "2015-09-01",
  "Resources": {
    "MyECS": {
      "Type": "ALIYUN::ECS::Instance",
      "Properties": {
        "InstanceType": "ecs.c6.large"
      }
    }
  }
}`
		pt := ParseJSON(content)

		Convey("It should parse without error", func() {
			So(pt.Err, ShouldBeNil)
			So(pt.Root, ShouldNotBeNil)
		})

		Convey("It should detect ROSTemplateFormatVersion", func() {
			So(pt.HasROSTemplateFormatVersion(), ShouldBeTrue)
		})

		Convey("It should extract resources", func() {
			So(pt.GetResourceType("MyECS"), ShouldEqual, "ALIYUN::ECS::Instance")
		})
	})
}

func TestParseYAML_Invalid(t *testing.T) {
	Convey("Given invalid YAML", t, func() {
		content := `invalid: [yaml: broken`
		pt := ParseYAML(content)

		Convey("It should have an error", func() {
			So(pt.Err, ShouldNotBeNil)
		})
	})
}

func TestParseJSON_Invalid(t *testing.T) {
	Convey("Given invalid JSON", t, func() {
		pt := ParseJSON(`{invalid json}`)

		Convey("It should have an error", func() {
			So(pt.Err, ShouldNotBeNil)
		})
	})
}

func TestFindKeyLineInYAML(t *testing.T) {
	Convey("Given YAML content", t, func() {
		content := "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  MyECS:\n    Type: ALIYUN::ECS::Instance"

		Convey("It finds top-level keys", func() {
			So(FindKeyLineInYAML(content, "ROSTemplateFormatVersion"), ShouldEqual, 0)
			So(FindKeyLineInYAML(content, "Resources"), ShouldEqual, 1)
		})

		Convey("It returns -1 for missing keys", func() {
			So(FindKeyLineInYAML(content, "Outputs"), ShouldEqual, -1)
		})
	})
}
