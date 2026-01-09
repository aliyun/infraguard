package reporter

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestFormatPath(t *testing.T) {
	Convey("Given the FormatPath function", t, func() {
		tests := []struct {
			path     []string
			expected string
		}{
			{[]string{"Resources", "WebServer"}, "Resources.WebServer"},
			{[]string{"Resources", "Items", "0"}, "Resources.Items.[0]"},
			{[]string{"Resources", "Items", "0", "Properties"}, "Resources.Items.[0].Properties"},
			{[]string{"0"}, "[0]"},
			{[]string{}, ""},
			{[]string{"Single"}, "Single"},
			{[]string{"A", "1", "B", "2"}, "A.[1].B.[2]"},
		}

		for _, tc := range tests {
			Convey("For path "+tc.expected, func() {
				result := FormatPath(tc.path)
				So(result, ShouldEqual, tc.expected)
			})
		}
	})
}
