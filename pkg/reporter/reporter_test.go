package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNew(t *testing.T) {
	Convey("Given the New function", t, func() {
		var buf bytes.Buffer
		r := New("json", &buf)

		Convey("It should return a non-nil Reporter", func() {
			So(r, ShouldNotBeNil)
		})

		Convey("It should have correct format", func() {
			So(r.format, ShouldEqual, "json")
		})

		Convey("It should have correct writer", func() {
			So(r.writer, ShouldEqual, &buf)
		})
	})
}

func TestRender_DefaultFormat(t *testing.T) {
	Convey("Given a reporter with empty format", t, func() {
		var buf bytes.Buffer
		r := New("", &buf)

		err := r.Render([]models.FileResult{})

		Convey("It should render without error", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestSeveritySorting(t *testing.T) {
	Convey("Given violations with different severities", t, func() {
		violations := []models.RichViolation{
			{Severity: models.SeverityLow, ID: "WARN-001"},
			{Severity: models.SeverityHigh, ID: "CRIT-001"},
			{Severity: models.SeverityMedium, ID: "ERR-001"},
		}

		results := []models.FileResult{
			{File: "test.yaml", Violations: violations},
		}

		var buf bytes.Buffer
		r := New("json", &buf)

		err := r.Render(results)

		Convey("It should render without error", func() {
			So(err, ShouldBeNil)
		})

		var report models.Report
		err = json.Unmarshal(buf.Bytes(), &report)

		Convey("It should parse JSON correctly", func() {
			So(err, ShouldBeNil)
		})

		Convey("It should contain violations sorted by severity (High -> Medium -> Low)", func() {
			So(len(report.Results), ShouldEqual, 1)
			v := report.Results[0].Violations
			So(len(v), ShouldEqual, 3)
			So(v[0].Severity, ShouldEqual, models.SeverityHigh)
			So(v[1].Severity, ShouldEqual, models.SeverityMedium)
			So(v[2].Severity, ShouldEqual, models.SeverityLow)
		})
	})
}
