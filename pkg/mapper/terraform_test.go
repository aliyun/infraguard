package mapper

import (
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	. "github.com/smartystreets/goconvey/convey"
)

func TestMapTerraformViolations(t *testing.T) {
	Convey("Given Terraform violations with __meta__", t, func() {
		opaInput := map[string]interface{}{
			"format": "terraform",
			"resources": map[string]interface{}{
				"alicloud_instance": map[string]interface{}{
					"web": map[string]interface{}{
						"__meta__": map[string]interface{}{
							"filename": "main.tf",
							"line":     float64(10),
						},
						"internet_max_bandwidth_out": float64(5),
					},
				},
			},
		}

		violations := []models.OPAViolation{
			{
				ID:         "ecs-instance-public-ip",
				ResourceID: "alicloud_instance.web",
				Meta: models.ViolationMeta{
					Severity: "high",
					Reason:   "Instance has public IP",
				},
			},
		}

		Convey("It should map violations to source locations", func() {
			dir := "/path/to/project"
			rich := MapTerraformViolations(violations, opaInput, dir, "en")
			So(len(rich), ShouldEqual, 1)
			So(rich[0].Line, ShouldEqual, 10)
			So(rich[0].File, ShouldContainSubstring, "main.tf")
		})

		Convey("It should use i18n for reason and recommendation", func() {
			i18nViolations := []models.OPAViolation{
				{
					ID:         "ecs-instance-public-ip",
					ResourceID: "alicloud_instance.web",
					Meta: models.ViolationMeta{
						Severity: "high",
						Reason: map[string]interface{}{
							"en": "Instance has public IP",
							"zh": "实例有公网IP",
						},
						Recommendation: map[string]interface{}{
							"en": "Remove public IP",
							"zh": "移除公网IP",
						},
					},
				},
			}

			rich := MapTerraformViolations(i18nViolations, opaInput, "/path/to/project", "zh")
			So(rich[0].Reason, ShouldEqual, "实例有公网IP")
			So(rich[0].Recommendation, ShouldEqual, "移除公网IP")
		})

		Convey("It should default to line 1 when resource not found in meta", func() {
			unknownViolations := []models.OPAViolation{
				{
					ID:         "some-rule",
					ResourceID: "alicloud_instance.unknown",
					Meta: models.ViolationMeta{
						Severity: "medium",
						Reason:   "Some reason",
					},
				},
			}

			rich := MapTerraformViolations(unknownViolations, opaInput, "/path/to/project", "en")
			So(len(rich), ShouldEqual, 1)
			So(rich[0].Line, ShouldEqual, 1)
			So(rich[0].File, ShouldEqual, "/path/to/project")
		})
	})
}

func TestFindTerraformResourceLocation(t *testing.T) {
	Convey("Given resources map with __meta__", t, func() {
		resources := map[string]interface{}{
			"alicloud_instance": map[string]interface{}{
				"web": map[string]interface{}{
					"__meta__": map[string]interface{}{
						"filename": "main.tf",
						"line":     float64(10),
					},
				},
			},
		}

		Convey("It should find the resource location by type.name", func() {
			line, filename := findTerraformResourceLocation("alicloud_instance.web", resources)
			So(line, ShouldEqual, 10)
			So(filename, ShouldEqual, "main.tf")
		})

		Convey("It should return 0 for unknown resources", func() {
			line, filename := findTerraformResourceLocation("alicloud_instance.unknown", resources)
			So(line, ShouldEqual, 0)
			So(filename, ShouldEqual, "")
		})

		Convey("It should handle invalid resource ID format", func() {
			line, filename := findTerraformResourceLocation("invalid", resources)
			So(line, ShouldEqual, 0)
			So(filename, ShouldEqual, "")
		})

		Convey("It should handle int line numbers", func() {
			intResources := map[string]interface{}{
				"alicloud_vpc": map[string]interface{}{
					"main": map[string]interface{}{
						"__meta__": map[string]interface{}{
							"filename": "vpc.tf",
							"line":     25,
						},
					},
				},
			}
			line, filename := findTerraformResourceLocation("alicloud_vpc.main", intResources)
			So(line, ShouldEqual, 25)
			So(filename, ShouldEqual, "vpc.tf")
		})

		Convey("It should handle missing __meta__ field", func() {
			noMetaResources := map[string]interface{}{
				"alicloud_instance": map[string]interface{}{
					"web": map[string]interface{}{
						"instance_type": "ecs.t5-lc1m1.small",
					},
				},
			}
			line, filename := findTerraformResourceLocation("alicloud_instance.web", noMetaResources)
			So(line, ShouldEqual, 0)
			So(filename, ShouldEqual, "")
		})

		Convey("It should handle nil resources", func() {
			line, filename := findTerraformResourceLocation("alicloud_instance.web", nil)
			So(line, ShouldEqual, 0)
			So(filename, ShouldEqual, "")
		})
	})
}
