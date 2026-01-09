package reporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	. "github.com/smartystreets/goconvey/convey"
)

func TestRenderHTML(t *testing.T) {
	Convey("Given a Reporter and violations", t, func() {
		var buf bytes.Buffer
		r := New("html", &buf)

		results := []models.FileResult{
			{
				File: "template1.json",
				Violations: []models.RichViolation{
					{ID: "RULE-LOW", Severity: models.SeverityLow, Reason: "Low reason"},
					{ID: "RULE-HIGH", Severity: models.SeverityHigh, Reason: "High reason"},
					{ID: "RULE-MEDIUM", Severity: models.SeverityMedium, Reason: "Medium reason"},
				},
			},
		}

		Convey("When Render is called", func() {
			err := r.Render(results)

			Convey("It should not return an error", func() {
				So(err, ShouldBeNil)
			})

			Convey("The output should contain the rule IDs and template name", func() {
				output := buf.String()
				So(output, ShouldContainSubstring, "template1.json")
				So(output, ShouldContainSubstring, "RULE-HIGH")
				So(output, ShouldContainSubstring, "RULE-MEDIUM")
				So(output, ShouldContainSubstring, "RULE-LOW")
			})

			Convey("Rules should be sorted by severity (High -> Medium -> Low)", func() {
				results2 := []models.FileResult{
					{
						File: "sort_test.json",
						Violations: []models.RichViolation{
							{ID: "LOW", Severity: models.SeverityLow},
							{ID: "HIGH", Severity: models.SeverityHigh},
							{ID: "MEDIUM", Severity: models.SeverityMedium},
						},
					},
				}
				var buf2 bytes.Buffer
				r2 := New("html", &buf2)
				err := r2.Render(results2)
				So(err, ShouldBeNil)

				output := buf2.String()
				// Check relative positions of rule IDs in the output
				posHigh := strings.Index(output, "HIGH")
				posMedium := strings.Index(output, "MEDIUM")
				posLow := strings.Index(output, "LOW")

				So(posHigh, ShouldBeGreaterThan, -1)
				So(posMedium, ShouldBeGreaterThan, -1)
				So(posLow, ShouldBeGreaterThan, -1)

				So(posHigh, ShouldBeLessThan, posMedium)
				So(posMedium, ShouldBeLessThan, posLow)
			})
		})
	})
}
