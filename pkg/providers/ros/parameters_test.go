package ros

import (
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	. "github.com/smartystreets/goconvey/convey"
)

func TestValidateInputParameters(t *testing.T) {
	Convey("Given ValidateInputParameters function", t, func() {
		Convey("When template has no Parameters section", func() {
			template := map[string]interface{}{
				"ROSTemplateFormatVersion": "2015-09-01",
				"Resources":                map[string]interface{}{},
			}
			inputParams := models.TemplateParams{}

			err := ValidateInputParameters(template, inputParams)

			Convey("It should accept empty input", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When input parameters are all defined", func() {
			template := map[string]interface{}{
				"Parameters": map[string]interface{}{
					"VpcCidr": map[string]interface{}{
						"Type": "String",
					},
				},
			}
			inputParams := models.TemplateParams{
				"VpcCidr": "192.168.0.0/16",
			}

			err := ValidateInputParameters(template, inputParams)

			Convey("It should pass validation", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When input has undefined parameter", func() {
			template := map[string]interface{}{
				"Parameters": map[string]interface{}{
					"VpcCidr": map[string]interface{}{
						"Type": "String",
					},
				},
			}
			inputParams := models.TemplateParams{
				"VpcCidr":      "192.168.0.0/16",
				"UndefinedKey": "value",
			}

			err := ValidateInputParameters(template, inputParams)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "UndefinedKey")
			})
		})
	})
}

func TestResolveParameters(t *testing.T) {
	Convey("Given ResolveParameters function", t, func() {
		Convey("When resolving with CLI input", func() {
			template := map[string]interface{}{
				"Parameters": map[string]interface{}{
					"VpcCidr": map[string]interface{}{
						"Type":    "String",
						"Default": "10.0.0.0/16",
					},
				},
			}
			inputParams := models.TemplateParams{
				"VpcCidr": "192.168.0.0/16",
			}

			result, err := ResolveParameters(template, inputParams)

			Convey("It should use CLI value", func() {
				So(err, ShouldBeNil)
				params := result["Parameters"].(map[string]interface{})
				vpcCidr := params["VpcCidr"].(map[string]interface{})
				So(vpcCidr["ResolvedValue"], ShouldEqual, "192.168.0.0/16")
			})
		})

		Convey("When resolving with default value", func() {
			template := map[string]interface{}{
				"Parameters": map[string]interface{}{
					"VpcCidr": map[string]interface{}{
						"Type":    "String",
						"Default": "10.0.0.0/16",
					},
				},
			}
			inputParams := models.TemplateParams{}

			result, err := ResolveParameters(template, inputParams)

			Convey("It should use default value", func() {
				So(err, ShouldBeNil)
				params := result["Parameters"].(map[string]interface{})
				vpcCidr := params["VpcCidr"].(map[string]interface{})
				So(vpcCidr["ResolvedValue"], ShouldEqual, "10.0.0.0/16")
			})
		})
	})
}
