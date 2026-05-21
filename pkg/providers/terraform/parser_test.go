package terraform

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDiscoverTFFiles(t *testing.T) {
	Convey("Given a directory with .tf files", t, func() {
		tmpDir := t.TempDir()
		err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(`
resource "alicloud_instance" "web" {
  instance_type = "ecs.s6-c1m1.small"
}
`), 0644)
		So(err, ShouldBeNil)
		err = os.WriteFile(filepath.Join(tmpDir, "variables.tf"), []byte(`
variable "instance_type" {
  type    = string
  default = "ecs.s6-c1m1.small"
}
`), 0644)
		So(err, ShouldBeNil)

		Convey("It should discover all .tf files", func() {
			files, err := discoverTFFiles(tmpDir)
			So(err, ShouldBeNil)
			So(len(files), ShouldEqual, 2)
		})
	})
}

func TestParseTFFiles(t *testing.T) {
	Convey("Given .tf files in a directory", t, func() {
		tmpDir := t.TempDir()
		err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(`
resource "alicloud_instance" "web" {
  instance_type              = "ecs.s6-c1m1.small"
  image_id                   = "ubuntu_22_04_x64_20G_alibase_20230208.vhd"
  internet_max_bandwidth_out = 5
  security_groups            = ["sg-xxx"]
}
`), 0644)
		So(err, ShouldBeNil)
		err = os.WriteFile(filepath.Join(tmpDir, "variables.tf"), []byte(`
variable "instance_type" {
  type    = string
  default = "ecs.s6-c1m1.small"
}
`), 0644)
		So(err, ShouldBeNil)

		Convey("It should parse them into a merged body", func() {
			parsed, diags := parseTFDir(tmpDir)
			So(diags.HasErrors(), ShouldBeFalse)
			So(parsed, ShouldNotBeNil)
			So(parsed.Files, ShouldNotBeEmpty)
		})
	})
}
