package terraform

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func setupWithVarsDir(t *testing.T) string {
	tmpDir := t.TempDir()
	mainContent := []byte(`locals {
  common_tags = {
    Environment = "production"
    Project     = var.project_name
  }
}

resource "alicloud_instance" "web" {
  instance_type              = var.instance_type
  image_id                   = "ubuntu_22_04_x64_20G_alibase_20230208.vhd"
  internet_max_bandwidth_out = var.bandwidth
  tags                       = local.common_tags
}
`)
	varsContent := []byte(`variable "instance_type" {
  type    = string
  default = "ecs.s6-c1m1.small"
}

variable "bandwidth" {
  type    = number
  default = 5
}

variable "project_name" {
  type    = string
  default = "infraguard"
}
`)
	if err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), mainContent, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "variables.tf"), varsContent, 0644); err != nil {
		t.Fatal(err)
	}
	return tmpDir
}

func TestExtractVariables(t *testing.T) {
	Convey("Given a parsed config with variables", t, func() {
		dir := setupWithVarsDir(t)
		parsed, diags := parseTFDir(dir)
		So(diags.HasErrors(), ShouldBeFalse)

		Convey("It should extract variable definitions", func() {
			vars, diags := extractVariables(parsed)
			So(diags.HasErrors(), ShouldBeFalse)
			So(vars, ShouldContainKey, "instance_type")
			So(vars, ShouldContainKey, "bandwidth")
			So(vars, ShouldContainKey, "project_name")
		})
	})
}

func TestExtractLocals(t *testing.T) {
	Convey("Given a parsed config with locals", t, func() {
		dir := setupWithVarsDir(t)
		parsed, diags := parseTFDir(dir)
		So(diags.HasErrors(), ShouldBeFalse)

		Convey("It should extract locals", func() {
			vars, _ := extractVariables(parsed)
			inputVars := map[string]interface{}{}
			evalCtx := buildEvalContext(vars, nil, inputVars)
			locals, diags := extractLocals(parsed, evalCtx)
			So(diags.HasErrors(), ShouldBeFalse)
			So(locals, ShouldContainKey, "common_tags")
		})
	})
}

func TestEvaluateConfig(t *testing.T) {
	Convey("Given a parsed config with variables and locals", t, func() {
		dir := setupWithVarsDir(t)
		parsed, diags := parseTFDir(dir)
		So(diags.HasErrors(), ShouldBeFalse)

		Convey("It should evaluate expressions to concrete values", func() {
			inputVars := map[string]interface{}{}
			result, err := evaluate(parsed, inputVars)
			So(err, ShouldBeNil)
			So(result, ShouldNotBeNil)
			So(result.Resources, ShouldNotBeEmpty)

			instances := result.Resources["alicloud_instance"]
			So(instances, ShouldNotBeNil)
			web := instances["web"]
			So(web, ShouldNotBeNil)
			So(web["instance_type"], ShouldEqual, "ecs.s6-c1m1.small")
			So(web["internet_max_bandwidth_out"], ShouldEqual, float64(5))
		})
	})
}
