package cmd

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestUpdateCommand(t *testing.T) {
	Convey("Given the update command", t, func() {
		Convey("Should be registered", func() {
			So(updateCmd, ShouldNotBeNil)
			So(updateCmd.Use, ShouldEqual, "update")
		})

		Convey("Should have required flags", func() {
			checkFlag := updateCmd.Flags().Lookup("check")
			So(checkFlag, ShouldNotBeNil)
			So(checkFlag.Value.Type(), ShouldEqual, "bool")

			forceFlag := updateCmd.Flags().Lookup("force")
			So(forceFlag, ShouldNotBeNil)
			So(forceFlag.Value.Type(), ShouldEqual, "bool")

			versionFlag := updateCmd.Flags().Lookup("version")
			So(versionFlag, ShouldNotBeNil)
			So(versionFlag.Value.Type(), ShouldEqual, "string")
		})
	})

	Convey("Platform support check", t, func() {
		Convey("Should support macOS amd64", func() {
			So(isSupportedPlatform("darwin", "amd64"), ShouldBeTrue)
		})

		Convey("Should support macOS arm64", func() {
			So(isSupportedPlatform("darwin", "arm64"), ShouldBeTrue)
		})

		Convey("Should support Linux amd64", func() {
			So(isSupportedPlatform("linux", "amd64"), ShouldBeTrue)
		})

		Convey("Should support Linux arm64", func() {
			So(isSupportedPlatform("linux", "arm64"), ShouldBeTrue)
		})

		Convey("Should support Windows amd64", func() {
			So(isSupportedPlatform("windows", "amd64"), ShouldBeTrue)
		})

		Convey("Should support Windows arm64", func() {
			So(isSupportedPlatform("windows", "arm64"), ShouldBeTrue)
		})

		Convey("Should not support unsupported platforms", func() {
			So(isSupportedPlatform("freebsd", "amd64"), ShouldBeFalse)
			So(isSupportedPlatform("linux", "386"), ShouldBeFalse)
		})
	})

	Convey("Byte formatting", t, func() {
		Convey("Should format bytes correctly", func() {
			So(formatBytes(0), ShouldEqual, "0 B")
			So(formatBytes(512), ShouldEqual, "512 B")
			So(formatBytes(1024), ShouldEqual, "1.0 KiB")
			So(formatBytes(1536), ShouldEqual, "1.5 KiB")
			So(formatBytes(1048576), ShouldEqual, "1.0 MiB")
			So(formatBytes(1073741824), ShouldEqual, "1.0 GiB")
		})
	})
}
