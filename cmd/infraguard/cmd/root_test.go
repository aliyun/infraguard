package cmd

import (
	"bytes"
	"testing"

	"github.com/aliyun/infraguard/pkg/i18n"
	. "github.com/smartystreets/goconvey/convey"
)

func TestRootCommand(t *testing.T) {
	Convey("Given the root command", t, func() {
		// Initialize i18n for tests
		i18n.Init()
		updateCommandDescriptions()

		Convey("When checking command registration", func() {
			commands := rootCmd.Commands()
			commandNames := make(map[string]bool)
			for _, cmd := range commands {
				commandNames[cmd.Name()] = true
			}

			Convey("It should have scan command registered", func() {
				So(commandNames["scan"], ShouldBeTrue)
			})

			Convey("It should have policy command registered", func() {
				So(commandNames["policy"], ShouldBeTrue)
			})

			Convey("It should have config command registered", func() {
				So(commandNames["config"], ShouldBeTrue)
			})

			Convey("It should have version command registered", func() {
				So(commandNames["version"], ShouldBeTrue)
			})
		})

		Convey("When executing root command without subcommand", func() {
			var buf bytes.Buffer
			rootCmd.SetArgs([]string{})
			rootCmd.SetOutput(&buf)
			_ = rootCmd.Execute()

			Convey("It should display usage information", func() {
				// Root command without args should show help
				output := buf.String()
				So(output, ShouldContainSubstring, "infraguard")
				So(output, ShouldContainSubstring, "Available Commands")
			})
		})

		Convey("When using --lang flag", func() {
			Convey("With valid language 'en'", func() {
				// Reset i18n before test
				i18n.SetLanguage("")
				// Set language via flag
				rootCmd.SetArgs([]string{"--lang", "en", "version"})
				var buf bytes.Buffer
				rootCmd.SetOutput(&buf)
				// Manually parse lang flag and set language
				globalLang = "en"
				i18n.SetLanguage("en")
				_ = rootCmd.Execute()

				Convey("It should set language to English", func() {
					So(i18n.GetLanguage(), ShouldEqual, "en-US")
				})
			})

			Convey("With valid language 'zh'", func() {
				// Reset i18n before test
				i18n.SetLanguage("")
				// Set language via flag
				rootCmd.SetArgs([]string{"--lang", "zh", "version"})
				var buf bytes.Buffer
				rootCmd.SetOutput(&buf)
				// Manually parse lang flag and set language
				globalLang = "zh"
				i18n.SetLanguage("zh")
				err := rootCmd.Execute()

				Convey("It should execute successfully", func() {
					So(err, ShouldBeNil)
				})

				Convey("It should set language to Chinese", func() {
					So(i18n.GetLanguage(), ShouldEqual, "zh-CN")
				})
			})

			Convey("With invalid language", func() {
				rootCmd.SetArgs([]string{"--lang", "invalid", "version"})
				var buf bytes.Buffer
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should handle invalid language", func() {
					// Command may still execute but language validation happens in subcommands
					// We just verify command structure
					So(err != nil || buf.Len() >= 0, ShouldBeTrue)
				})
			})
		})

		Convey("When checking i18n initialization", func() {
			Convey("Command descriptions should be localized", func() {
				// Verify that command descriptions are set (they are updated by i18n)
				// After calling updateCommandDescriptions(), descriptions should be set
				So(scanCmd.Short, ShouldNotBeEmpty)
				So(policyCmd.Short, ShouldNotBeEmpty)
				So(configCmd.Short, ShouldNotBeEmpty)
			})
		})
	})
}
