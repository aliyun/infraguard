package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	. "github.com/smartystreets/goconvey/convey"
)

func TestRenderJSON(t *testing.T) {
	Convey("Given the JSON renderer", t, func() {
		Convey("When rendering violations", func() {
			violations := []models.RichViolation{
				{
					Severity:       "High",
					ID:             "TEST-001",
					ResourceID:     "WebServer",
					ViolationPath:  []string{"Resources", "WebServer"},
					File:           "test.yaml",
					Line:           10,
					Snippet:        "AllocatePublicIP: true",
					Reason:         "Test reason",
					Recommendation: "Test recommendation",
				},
			}
			results := []models.FileResult{
				{File: "test.yaml", Violations: violations},
			}

			var buf bytes.Buffer
			r := New("json", &buf)
			err := r.Render(results)

			Convey("It should not return an error", func() {
				So(err, ShouldBeNil)
			})

			var report models.Report
			err = json.Unmarshal(buf.Bytes(), &report)

			Convey("It should produce valid JSON", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should have schema_version=2.0", func() {
				So(report.SchemaVersion, ShouldEqual, "2.0")
			})

			Convey("Summary should have 1 violation", func() {
				So(report.Summary.TotalViolations, ShouldEqual, 1)
			})

			Convey("It should have correct violation fields", func() {
				results := report.Results
				So(len(results), ShouldEqual, 1)
				So(results[0].File, ShouldEqual, "test.yaml")

				v := results[0].Violations[0]
				So(v.ID, ShouldEqual, "TEST-001")
				So(v.Severity, ShouldEqual, "High")
				So(v.ResourceID, ShouldEqual, "WebServer")
			})
		})

		Convey("When rendering no violations", func() {
			var buf bytes.Buffer
			r := New("json", &buf)
			err := r.Render([]models.FileResult{})

			Convey("It should not return an error", func() {
				So(err, ShouldBeNil)
			})

			var report models.Report
			err = json.Unmarshal(buf.Bytes(), &report)

			Convey("It should produce valid JSON", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should have schema_version=2.0", func() {
				So(report.SchemaVersion, ShouldEqual, "2.0")
			})

			Convey("It should have 0 violations", func() {
				So(report.Summary.TotalViolations, ShouldEqual, 0)
			})
		})

		Convey("When rendering multiple violations", func() {
			violations := []models.RichViolation{
				{Severity: "Critical", ID: "CRIT-001", ResourceID: "Resource1"},
				{Severity: "High", ID: "HIGH-001", ResourceID: "Resource2"},
				{Severity: "Medium", ID: "MED-001", ResourceID: "Resource3"},
			}
			results := []models.FileResult{
				{File: "test.yaml", Violations: violations},
			}

			var buf bytes.Buffer
			r := New("json", &buf)
			err := r.Render(results)

			Convey("It should not return an error", func() {
				So(err, ShouldBeNil)
			})

			var report models.Report
			err = json.Unmarshal(buf.Bytes(), &report)

			Convey("It should have 3 violations", func() {
				So(err, ShouldBeNil)
				So(report.Summary.TotalViolations, ShouldEqual, 3)
			})
		})

		Convey("When checking JSON indentation", func() {
			violations := []models.RichViolation{
				{Severity: "Low", ID: "LOW-001"},
			}
			results := []models.FileResult{
				{File: "test.yaml", Violations: violations},
			}

			var buf bytes.Buffer
			r := New("json", &buf)
			err := r.Render(results)

			Convey("It should not return an error", func() {
				So(err, ShouldBeNil)
			})

			output := buf.String()

			Convey("It should be pretty-printed", func() {
				So(output, ShouldContainSubstring, "\n  ")
			})

			Convey("It should start with '{'", func() {
				So(output[0], ShouldEqual, '{')
			})
		})
	})
}
