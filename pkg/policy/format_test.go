package policy

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestFormatFile(t *testing.T) {
	Convey("Given the FormatFile function", t, func() {
		Convey("When formatting a well-formatted file", func() {
			result, err := FormatFile("testdata/validate/valid/valid-rule.rego", false)

			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Error, ShouldBeNil)
			})
		})

		Convey("When formatting a non-existent file", func() {
			result, err := FormatFile("testdata/validate/nonexistent.rego", false)

			Convey("It should return an error in the result", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Error, ShouldNotBeNil)
			})
		})
	})
}

func TestFormatDirectory(t *testing.T) {
	Convey("Given the FormatDirectory function", t, func() {
		Convey("When formatting a directory", func() {
			summary, err := FormatDirectory("testdata/validate/valid", false)

			Convey("It should process all files", func() {
				So(err, ShouldBeNil)
				So(summary, ShouldNotBeNil)
				So(summary.TotalFiles, ShouldBeGreaterThan, 0)
			})
		})
	})
}

func TestFormatPath(t *testing.T) {
	Convey("Given the FormatPath function", t, func() {
		Convey("When formatting a single file", func() {
			summary, err := FormatPath("testdata/validate/valid/valid-rule.rego", false)

			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
				So(summary, ShouldNotBeNil)
				So(summary.TotalFiles, ShouldEqual, 1)
			})
		})

		Convey("When formatting a directory", func() {
			summary, err := FormatPath("testdata/validate/valid", false)

			Convey("It should process all files", func() {
				So(err, ShouldBeNil)
				So(summary, ShouldNotBeNil)
				So(summary.TotalFiles, ShouldEqual, 2)
			})
		})

		Convey("When formatting a non-existent path", func() {
			_, err := FormatPath("testdata/validate/nonexistent", false)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When formatting a non-rego file", func() {
			// Create a temp file
			tmpFile, _ := os.CreateTemp("", "test*.txt")
			tmpFile.Close()
			defer os.Remove(tmpFile.Name())

			_, err := FormatPath(tmpFile.Name(), false)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestFormatWithWrite(t *testing.T) {
	Convey("Given the FormatFile function with write=true", t, func() {
		// Create a temp file with unformatted content
		tmpDir, _ := os.MkdirTemp("", "format-test")
		defer os.RemoveAll(tmpDir)

		unformattedContent := `package test
import rego.v1
rule_meta := {"id": "test","name": "Test"}`

		tmpFile := filepath.Join(tmpDir, "test.rego")
		os.WriteFile(tmpFile, []byte(unformattedContent), 0644)

		Convey("When formatting with write=true", func() {
			result, err := FormatFile(tmpFile, true)

			Convey("It should write the formatted content", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Changed, ShouldBeTrue)

				// Read the file back
				content, _ := os.ReadFile(tmpFile)
				So(string(content), ShouldNotEqual, unformattedContent)
			})
		})
	})
}

func TestGenerateDiff(t *testing.T) {
	Convey("Given the GenerateDiff function", t, func() {
		Convey("When content is the same", func() {
			diff := GenerateDiff("same content", "same content", "test.rego")

			Convey("It should return empty string", func() {
				So(diff, ShouldBeEmpty)
			})
		})

		Convey("When content is different", func() {
			original := "line1\nline2"
			formatted := "line1\nline2_modified"
			diff := GenerateDiff(original, formatted, "test.rego")

			Convey("It should show differences", func() {
				So(diff, ShouldNotBeEmpty)
				So(diff, ShouldContainSubstring, "---")
				So(diff, ShouldContainSubstring, "+++")
			})
		})
	})
}

func TestFixChineseEnglishSpacing(t *testing.T) {
	Convey("Given the fixChineseEnglishSpacing function", t, func() {
		Convey("When fixing Chinese followed by English", func() {
			input := []byte(`"zh": "ROS最佳实践合规包"`)
			expected := `"zh": "ROS 最佳实践合规包"`
			result := fixZhFieldSpacing(input)

			Convey("It should add space between Chinese and English", func() {
				So(string(result), ShouldEqual, expected)
			})
		})

		Convey("When fixing English followed by Chinese", func() {
			input := []byte(`"zh": "确保PolarDB实例部署在专有网络中"`)
			expected := `"zh": "确保 PolarDB 实例部署在专有网络中"`
			result := fixZhFieldSpacing(input)

			Convey("It should add space between English and Chinese", func() {
				So(string(result), ShouldEqual, expected)
			})
		})

		Convey("When fixing mixed Chinese and English", func() {
			input := []byte(`"zh": "敏感参数必须配置NoEcho"`)
			expected := `"zh": "敏感参数必须配置 NoEcho"`
			result := fixZhFieldSpacing(input)

			Convey("It should add spaces correctly", func() {
				So(string(result), ShouldEqual, expected)
			})
		})

		Convey("When content contains URLs", func() {
			input := []byte(`"zh": "使用 ROS 架构编辑器（https://ros.console.aliyun.com/composer）导入模板"`)
			expected := `"zh": "使用 ROS 架构编辑器（https://ros.console.aliyun.com/composer）导入模板"`
			result := fixZhFieldSpacing(input)

			Convey("It should preserve URLs", func() {
				So(string(result), ShouldEqual, expected)
			})
		})

		Convey("When content has no Chinese characters", func() {
			input := []byte(`"en": "This is an English text"`)
			result := fixZhFieldSpacing(input)

			Convey("It should not modify the content", func() {
				So(string(result), ShouldEqual, string(input))
			})
		})
	})
}

func TestFormatInlineI18nDict(t *testing.T) {
	Convey("Given the formatInlineI18nDict function", t, func() {
		Convey("When formatting inline dict with en first", func() {
			input := []byte(`	"name": {"en": "VPN Gateway SSL-VPN Enabled", "zh": "VPN 网关开启 SSL-VPN"},`)
			expected := `	"name": {
		"en": "VPN Gateway SSL-VPN Enabled",
		"zh": "VPN 网关开启 SSL-VPN"
	},`
			result := formatInlineI18nDict(input)

			Convey("It should format to multiline", func() {
				So(string(result), ShouldEqual, expected)
			})
		})

		Convey("When formatting inline dict with zh first", func() {
			input := []byte(`	"name": {"zh": "VPN 网关开启 SSL-VPN", "en": "VPN Gateway SSL-VPN Enabled"},`)
			expected := `	"name": {
		"en": "VPN Gateway SSL-VPN Enabled",
		"zh": "VPN 网关开启 SSL-VPN"
	},`
			result := formatInlineI18nDict(input)

			Convey("It should format to multiline with en first", func() {
				So(string(result), ShouldEqual, expected)
			})
		})

		Convey("When content has no inline i18n dict", func() {
			input := []byte(`	"id": "test",`)
			result := formatInlineI18nDict(input)

			Convey("It should not modify the content", func() {
				So(string(result), ShouldEqual, string(input))
			})
		})
	})
}
