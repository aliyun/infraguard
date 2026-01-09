package models

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSeverityOrder(t *testing.T) {
	Convey("Given the SeverityOrder function", t, func() {
		tests := []struct {
			severity string
			order    int
		}{
			{SeverityHigh, 0},
			{SeverityMedium, 1},
			{SeverityLow, 2},
			{"Unknown", 3},
			{"", 3},
		}

		for _, tc := range tests {
			Convey("When severity is "+tc.severity, func() {
				result := SeverityOrder(tc.severity)

				Convey("It should return correct order", func() {
					So(result, ShouldEqual, tc.order)
				})
			})
		}
	})
}

func TestSeveritySorting(t *testing.T) {
	Convey("Given a list of severities", t, func() {
		severities := []string{SeverityLow, SeverityHigh, SeverityMedium}
		expectedOrder := []string{SeverityHigh, SeverityMedium, SeverityLow}

		Convey("When sorted by SeverityOrder", func() {
			for i := 0; i < len(severities)-1; i++ {
				for j := i + 1; j < len(severities); j++ {
					if SeverityOrder(severities[i]) > SeverityOrder(severities[j]) {
						severities[i], severities[j] = severities[j], severities[i]
					}
				}
			}

			Convey("It should be in the correct order", func() {
				for i, s := range severities {
					So(s, ShouldEqual, expectedOrder[i])
				}
			})
		})
	})
}

func TestSeverityLevels(t *testing.T) {
	Convey("Given the SeverityLevels function", t, func() {
		levels := SeverityLevels()

		Convey("It should return 3 severity levels", func() {
			So(len(levels), ShouldEqual, 3)
		})

		Convey("It should return levels in correct order", func() {
			So(levels[0], ShouldEqual, SeverityHigh)
			So(levels[1], ShouldEqual, SeverityMedium)
			So(levels[2], ShouldEqual, SeverityLow)
		})
	})
}
