package schema

import (
	"encoding/json"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestRegistry_LoadEmbedded(t *testing.T) {
	Convey("Given a new Registry", t, func() {
		r := &Registry{}
		err := r.Load()

		Convey("It should load the embedded schema without error", func() {
			So(err, ShouldBeNil)
			So(r.schema, ShouldNotBeNil)
			So(r.schema.Version, ShouldNotBeEmpty)
		})

		Convey("It should contain resource types", func() {
			So(r.ResourceTypeCount(), ShouldBeGreaterThan, 0)
		})
	})
}

func TestRegistry_LoadFromData(t *testing.T) {
	Convey("Given a Registry and custom schema data", t, func() {
		r := &Registry{}
		sf := &SchemaFile{
			Version: "2026-01-01",
			ResourceTypes: map[string]*ResourceType{
				"ALIYUN::ECS::Instance": {
					Description: "Test ECS instance",
					Properties: map[string]*Property{
						"InstanceType": {Type: "String", Required: true, Description: "Instance type"},
						"ImageId":      {Type: "String", Required: true, Description: "Image ID"},
						"ZoneId":       {Type: "String", Required: false, Description: "Zone ID"},
					},
					Attributes: map[string]*Attribute{
						"InstanceId": {Description: "Instance ID"},
					},
				},
				"ALIYUN::ECS::VPC": {
					Description: "Test VPC",
					Properties: map[string]*Property{
						"CidrBlock": {Type: "String", Required: false, Description: "CIDR block"},
					},
				},
			},
		}

		data, _ := json.Marshal(sf)
		err := r.LoadFromData(data)
		So(err, ShouldBeNil)

		Convey("GetResourceType returns the correct resource", func() {
			rt := r.GetResourceType("ALIYUN::ECS::Instance")
			So(rt, ShouldNotBeNil)
			So(rt.Description, ShouldEqual, "Test ECS instance")
		})

		Convey("GetResourceType returns nil for unknown type", func() {
			rt := r.GetResourceType("ALIYUN::UNKNOWN::Type")
			So(rt, ShouldBeNil)
		})

		Convey("HasResourceType works correctly", func() {
			So(r.HasResourceType("ALIYUN::ECS::Instance"), ShouldBeTrue)
			So(r.HasResourceType("ALIYUN::UNKNOWN::Type"), ShouldBeFalse)
		})

		Convey("AllResourceTypeNames returns sorted names", func() {
			names := r.AllResourceTypeNames()
			So(names, ShouldHaveLength, 2)
			So(names[0], ShouldEqual, "ALIYUN::ECS::Instance")
			So(names[1], ShouldEqual, "ALIYUN::ECS::VPC")
		})

		Convey("SearchResourceTypes filters by prefix", func() {
			matches := r.SearchResourceTypes("ALIYUN::ECS")
			So(matches, ShouldHaveLength, 2)

			matches = r.SearchResourceTypes("ALIYUN::ECS::V")
			So(matches, ShouldHaveLength, 1)
			So(matches[0], ShouldEqual, "ALIYUN::ECS::VPC")

			matches = r.SearchResourceTypes("ALIYUN::RDS")
			So(matches, ShouldHaveLength, 0)
		})

		Convey("GetProperties returns properties for known type", func() {
			props := r.GetProperties("ALIYUN::ECS::Instance")
			So(props, ShouldNotBeNil)
			So(props, ShouldHaveLength, 3)
		})

		Convey("GetProperties returns nil for unknown type", func() {
			props := r.GetProperties("ALIYUN::UNKNOWN::Type")
			So(props, ShouldBeNil)
		})

		Convey("GetProperty returns a specific property", func() {
			prop := r.GetProperty("ALIYUN::ECS::Instance", "InstanceType")
			So(prop, ShouldNotBeNil)
			So(prop.Type, ShouldEqual, "String")
			So(prop.Required, ShouldBeTrue)
		})

		Convey("GetProperty returns nil for unknown property", func() {
			prop := r.GetProperty("ALIYUN::ECS::Instance", "UnknownProp")
			So(prop, ShouldBeNil)
		})

		Convey("GetAttributes returns attributes for known type", func() {
			attrs := r.GetAttributes("ALIYUN::ECS::Instance")
			So(attrs, ShouldNotBeNil)
			So(attrs, ShouldHaveLength, 1)
		})

		Convey("RequiredProperties returns only required props", func() {
			required := r.RequiredProperties("ALIYUN::ECS::Instance")
			So(required, ShouldHaveLength, 2)
			So(required, ShouldContain, "InstanceType")
			So(required, ShouldContain, "ImageId")
		})

		Convey("ResourceTypeCount returns correct count", func() {
			So(r.ResourceTypeCount(), ShouldEqual, 2)
		})

		Convey("Version returns correct version", func() {
			So(r.Version(), ShouldEqual, "2026-01-01")
		})
	})
}

func TestRegistry_LoadFromData_Invalid(t *testing.T) {
	Convey("Given invalid JSON data", t, func() {
		r := &Registry{}
		err := r.LoadFromData([]byte("not json"))
		Convey("It should return an error", func() {
			So(err, ShouldNotBeNil)
		})
	})
}
