package terraform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	. "github.com/smartystreets/goconvey/convey"
)

func TestIntegrationScanTerraform(t *testing.T) {
	Convey("Given a Terraform file with a violation", t, func() {
		tmpDir := t.TempDir()
		mainContent := []byte(`terraform {
  required_providers {
    alicloud = {
      source  = "aliyun/alicloud"
      version = "~> 1.200"
    }
  }
}

resource "alicloud_instance" "web" {
  instance_type              = "ecs.s6-c1m1.small"
  image_id                   = "ubuntu_22_04_x64_20G_alibase_20230208.vhd"
  internet_max_bandwidth_out = 5
  security_groups            = ["sg-xxx"]
}

resource "alicloud_security_group" "default" {
  name   = "test-sg"
  vpc_id = "vpc-xxx"
}
`)
		varsContent := []byte(`variable "instance_type" {
  type    = string
  default = "ecs.s6-c1m1.small"
}

variable "region" {
  type    = string
  default = "cn-hangzhou"
}
`)
		err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), mainContent, 0644)
		So(err, ShouldBeNil)
		err = os.WriteFile(filepath.Join(tmpDir, "variables.tf"), varsContent, 0644)
		So(err, ShouldBeNil)

		opaInput, err := Load(tmpDir, nil)
		So(err, ShouldBeNil)

		Convey("OPA should detect the violation", func() {
			policyContent := `
package infraguard.rules.terraform.ecs_instance_public_ip

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-instance-public-ip",
	"severity": "high",
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	bandwidth := tf.get_attribute(resource, "internet_max_bandwidth_out", 0)
	not tf.is_unknown(bandwidth)
	bandwidth > 0
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity},
	}
}
`
			helperContent := `
package infraguard.helpers.terraform

import rego.v1

resources_by_type(resource_type) := resources if {
	resources := input.resources[resource_type]
}

get_attribute(resource, attr, default_value) := value if {
	value := resource[attr]
	value != null
} else := default_value

is_unknown(value) if {
	value == "<unknown>"
}
`
			ctx := context.Background()
			query := "[v | v := data.infraguard.rules[_][_].deny[_]]"
			r := rego.New(
				rego.Query(query),
				rego.Module("policy.rego", policyContent),
				rego.Module("helpers.rego", helperContent),
				rego.Input(opaInput),
			)

			rs, err := r.Eval(ctx)
			So(err, ShouldBeNil)
			So(len(rs), ShouldBeGreaterThan, 0)
			So(len(rs[0].Expressions), ShouldBeGreaterThan, 0)

			violations, ok := rs[0].Expressions[0].Value.([]interface{})
			So(ok, ShouldBeTrue)
			So(len(violations), ShouldBeGreaterThan, 0)
		})
	})
}

func TestIntegrationScanTerraformCompliant(t *testing.T) {
	Convey("Given a compliant Terraform file", t, func() {
		tmpDir := t.TempDir()
		content := []byte(`
resource "alicloud_instance" "web" {
  instance_type              = "ecs.s6-c1m1.small"
  image_id                   = "ubuntu_22_04_x64_20G_alibase_20230208.vhd"
  internet_max_bandwidth_out = 0
  security_groups            = ["sg-xxx"]
}
`)
		err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), content, 0644)
		So(err, ShouldBeNil)

		opaInput, err := Load(tmpDir, nil)
		So(err, ShouldBeNil)

		Convey("OPA should detect no violations", func() {
			policyContent := `
package infraguard.rules.terraform.ecs_instance_public_ip

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {"id": "ecs-instance-public-ip", "severity": "high"}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	bandwidth := tf.get_attribute(resource, "internet_max_bandwidth_out", 0)
	not tf.is_unknown(bandwidth)
	bandwidth > 0
	violation := {"id": rule_meta.id, "resource_id": sprintf("alicloud_instance.%s", [name]), "meta": {"severity": rule_meta.severity}}
}
`
			helperContent := `
package infraguard.helpers.terraform

import rego.v1

resources_by_type(resource_type) := resources if {
	resources := input.resources[resource_type]
}

get_attribute(resource, attr, default_value) := value if {
	value := resource[attr]
	value != null
} else := default_value

is_unknown(value) if {
	value == "<unknown>"
}
`
			ctx := context.Background()
			query := "[v | v := data.infraguard.rules[_][_].deny[_]]"
			r := rego.New(
				rego.Query(query),
				rego.Module("policy.rego", policyContent),
				rego.Module("helpers.rego", helperContent),
				rego.Input(opaInput),
			)

			rs, err := r.Eval(ctx)
			So(err, ShouldBeNil)
			So(len(rs), ShouldBeGreaterThan, 0)

			violations, ok := rs[0].Expressions[0].Value.([]interface{})
			So(ok, ShouldBeTrue)
			So(len(violations), ShouldEqual, 0)
		})
	})
}
