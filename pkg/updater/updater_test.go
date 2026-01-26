package updater

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestUpdater(t *testing.T) {
	Convey("Given an Updater instance", t, func() {
		updater := New("0.2.0")

		Convey("When comparing versions", func() {
			Convey("Should detect newer version", func() {
				cmp, err := updater.CompareVersions("0.3.0")
				So(err, ShouldBeNil)
				So(cmp, ShouldEqual, -1)
			})

			Convey("Should detect same version", func() {
				cmp, err := updater.CompareVersions("0.2.0")
				So(err, ShouldBeNil)
				So(cmp, ShouldEqual, 0)
			})

			Convey("Should detect older version", func() {
				cmp, err := updater.CompareVersions("0.1.0")
				So(err, ShouldBeNil)
				So(cmp, ShouldEqual, 1)
			})

			Convey("Should handle major version change", func() {
				cmp, err := updater.CompareVersions("1.0.0")
				So(err, ShouldBeNil)
				So(cmp, ShouldEqual, -1)
			})

			Convey("Should handle patch version change", func() {
				cmp, err := updater.CompareVersions("0.2.1")
				So(err, ShouldBeNil)
				So(cmp, ShouldEqual, -1)
			})
		})

		Convey("When checking if update is needed", func() {
			Convey("Should return true for newer version", func() {
				needed, err := updater.NeedsUpdate("0.3.0")
				So(err, ShouldBeNil)
				So(needed, ShouldBeTrue)
			})

			Convey("Should return false for same version", func() {
				needed, err := updater.NeedsUpdate("0.2.0")
				So(err, ShouldBeNil)
				So(needed, ShouldBeFalse)
			})

			Convey("Should return false for older version", func() {
				needed, err := updater.NeedsUpdate("0.1.0")
				So(err, ShouldBeNil)
				So(needed, ShouldBeFalse)
			})
		})
	})

	Convey("Given a dev version Updater", t, func() {
		updater := New("0.0.0-dev")

		Convey("When comparing with stable version", func() {
			Convey("Should always indicate update available", func() {
				cmp, err := updater.CompareVersions("0.3.0")
				So(err, ShouldBeNil)
				So(cmp, ShouldEqual, -1)
			})
		})
	})

	Convey("Platform detection", t, func() {
		Convey("Should detect OS and architecture", func() {
			goos, goarch := DetectPlatform()
			So(goos, ShouldNotBeEmpty)
			So(goarch, ShouldNotBeEmpty)
			So(goos, ShouldBeIn, "darwin", "linux", "windows", "freebsd")
			So(goarch, ShouldBeIn, "amd64", "arm64", "386", "arm")
		})
	})

	Convey("Asset name generation", t, func() {
		Convey("Should generate correct asset name", func() {
			name := GetAssetName("0.2.0", "darwin", "arm64")
			So(name, ShouldEqual, "infraguard-v0.2.0-darwin-arm64")
		})

		Convey("Should handle version without 'v' prefix", func() {
			name := GetAssetName("0.2.0", "linux", "amd64")
			So(name, ShouldEqual, "infraguard-v0.2.0-linux-amd64")
		})

		Convey("Should keep 'v' prefix if already present", func() {
			name := GetAssetName("v0.2.0", "windows", "amd64")
			So(name, ShouldEqual, "infraguard-v0.2.0-windows-amd64")
		})
	})
}
