package cmd

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestVersionCommand(t *testing.T) {
	Convey("Given the version command", t, func() {
		Convey("When checking command structure", func() {
			So(versionCmd.Use, ShouldEqual, "version")
			So(versionCmd.Short, ShouldNotBeEmpty)
		})

		Convey("When executing version command", func() {
			// Version command uses fmt.Printf which goes to stdout
			// We test that command can be executed without error
			rootCmd.SetArgs([]string{"version"})
			err := rootCmd.Execute()

			Convey("It should execute successfully", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When checking version variable", func() {
			Convey("Version should be set", func() {
				So(Version, ShouldNotBeEmpty)
			})
		})
	})
}
