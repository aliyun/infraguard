package terraform

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestConvertToOPAInput(t *testing.T) {
	Convey("Given an EvalResult", t, func() {
		result := &EvalResult{
			Resources: map[string]map[string]map[string]interface{}{
				"alicloud_instance": {
					"web": {
						"instance_type":              "ecs.s6-c1m1.small",
						"internet_max_bandwidth_out": float64(5),
						"__meta__":                   map[string]interface{}{"filename": "main.tf", "line": 10},
					},
				},
			},
			Variables: map[string]interface{}{
				"instance_type": map[string]interface{}{"value": "ecs.s6-c1m1.small"},
			},
			Locals: map[string]interface{}{
				"common_tags": map[string]interface{}{"Environment": "production"},
			},
			DataSources: map[string]map[string]map[string]interface{}{},
			Outputs:     map[string]interface{}{},
		}

		Convey("It should produce a valid OPA input map", func() {
			input := convertToOPAInput(result)
			So(input["format"], ShouldEqual, "terraform")
			So(input["resources"], ShouldNotBeNil)

			resources := input["resources"].(map[string]interface{})
			instances := resources["alicloud_instance"].(map[string]interface{})
			web := instances["web"].(map[string]interface{})
			So(web["instance_type"], ShouldEqual, "ecs.s6-c1m1.small")
			So(web["internet_max_bandwidth_out"], ShouldEqual, float64(5))
		})
	})
}
