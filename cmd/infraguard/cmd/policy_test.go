package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestPolicyCommand(t *testing.T) {
	Convey("Given the policy command", t, func() {
		Convey("When checking policy list command", func() {
			Convey("Command structure should be correct", func() {
				// Test command structure
				So(policyListCmd.Use, ShouldEqual, "list")
				// Short description is set dynamically by i18n, may be empty during test init
				So(policyListCmd.RunE, ShouldNotBeNil)
			})
		})

		Convey("When executing policy get command", func() {
			Convey("With missing argument", func() {
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "get"})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					So(errMsg, ShouldContainSubstring, "accepts 1 arg(s)")
				})
			})

			Convey("With invalid policy ID", func() {
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "get", "invalid:policy:id"})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					hasError := strings.Contains(errMsg, "not found") ||
						strings.Contains(errMsg, "policy") ||
						strings.Contains(errMsg, "error")
					So(hasError, ShouldBeTrue)
				})
			})
		})

		Convey("When executing policy validate command", func() {
			Convey("With missing argument", func() {
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "validate"})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					So(errMsg, ShouldContainSubstring, "accepts 1 arg(s)")
				})
			})

			Convey("With non-existent file", func() {
				tmpDir := t.TempDir()
				nonExistentPath := filepath.Join(tmpDir, "nonexistent.rego")
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "validate", nonExistentPath})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					hasError := strings.Contains(errMsg, "not found") ||
						strings.Contains(errMsg, "no such file") ||
						strings.Contains(errMsg, "cannot find") ||
						strings.Contains(errMsg, "does not exist") ||
						strings.Contains(errMsg, "path does not exist")
					So(hasError, ShouldBeTrue)
				})
			})
		})

		Convey("When executing policy format command", func() {
			Convey("With missing argument", func() {
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "format"})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					So(errMsg, ShouldContainSubstring, "accepts 1 arg(s)")
				})
			})

			Convey("With non-existent file", func() {
				tmpDir := t.TempDir()
				nonExistentPath := filepath.Join(tmpDir, "nonexistent.rego")
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "format", nonExistentPath})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					hasError := strings.Contains(errMsg, "not found") ||
						strings.Contains(errMsg, "no such file") ||
						strings.Contains(errMsg, "cannot find") ||
						strings.Contains(errMsg, "does not exist") ||
						strings.Contains(errMsg, "path does not exist")
					So(hasError, ShouldBeTrue)
				})
			})
		})

		Convey("When checking policy update command", func() {
			Convey("Command structure should be correct", func() {
				// Test command structure without actually executing network operations
				// Policy update requires network access and may prompt for GitHub credentials
				So(policyUpdateCmd.Use, ShouldEqual, "update")
				// Short description is set dynamically by i18n, may be empty during test init
				So(policyUpdateCmd.RunE, ShouldNotBeNil)
			})

			Convey("Command flags should be defined", func() {
				// Verify flags are properly defined
				repoFlag := policyUpdateCmd.Flags().Lookup("repo")
				So(repoFlag, ShouldNotBeNil)

				versionFlag := policyUpdateCmd.Flags().Lookup("version")
				So(versionFlag, ShouldNotBeNil)
			})
		})

		Convey("When checking policy clean command", func() {
			Convey("Command structure should be correct", func() {
				So(policyCleanCmd.Use, ShouldEqual, "clean")
				So(policyCleanCmd.RunE, ShouldNotBeNil)
			})

			Convey("Command flags should be defined", func() {
				forceFlag := policyCleanCmd.Flags().Lookup("force")
				So(forceFlag, ShouldNotBeNil)
				So(forceFlag.Shorthand, ShouldEqual, "f")
			})
		})
	})
}
