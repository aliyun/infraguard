package terraform

import (
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestLoad(t *testing.T) {
	Convey("Given a Terraform project directory", t, func() {
		dir := setupWithVarsDir(t)

		Convey("It should load and return OPA input", func() {
			inputVars := map[string]interface{}{}
			opaInput, err := Load(dir, inputVars)
			So(err, ShouldBeNil)
			So(opaInput, ShouldNotBeNil)
			So(opaInput["format"], ShouldEqual, "terraform")

			resources := opaInput["resources"].(map[string]interface{})
			So(resources, ShouldContainKey, "alicloud_instance")
		})

		Convey("It should accept input variable overrides", func() {
			inputVars := map[string]interface{}{
				"instance_type": "ecs.g6.large",
			}
			opaInput, err := Load(dir, inputVars)
			So(err, ShouldBeNil)

			resources := opaInput["resources"].(map[string]interface{})
			instances := resources["alicloud_instance"].(map[string]interface{})
			web := instances["web"].(map[string]interface{})
			So(web["instance_type"], ShouldEqual, "ecs.g6.large")
		})
	})
}

func TestLoadSingleFile(t *testing.T) {
	Convey("Given a single .tf file path", t, func() {
		dir := setupWithVarsDir(t)
		file := filepath.Join(dir, "main.tf")

		Convey("It should load the entire directory", func() {
			opaInput, err := Load(file, nil)
			So(err, ShouldBeNil)
			So(opaInput, ShouldNotBeNil)

			resources := opaInput["resources"].(map[string]interface{})
			So(resources, ShouldContainKey, "alicloud_instance")
		})
	})
}

func TestGetSourceRanges(t *testing.T) {
	Convey("Given a loaded Terraform project", t, func() {
		dir := setupWithVarsDir(t)
		opaInput, err := Load(dir, nil)
		So(err, ShouldBeNil)

		Convey("Resources should have __meta__ with file and line info", func() {
			resources := opaInput["resources"].(map[string]interface{})
			instances := resources["alicloud_instance"].(map[string]interface{})
			web := instances["web"].(map[string]interface{})
			meta := web["__meta__"].(map[string]interface{})
			So(meta["filename"], ShouldEqual, "main.tf")
			So(meta["line"], ShouldBeGreaterThan, 0)
		})
	})
}
